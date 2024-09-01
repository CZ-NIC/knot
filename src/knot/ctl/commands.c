/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/common/stats.h"
#include "knot/conf/confio.h"
#include "knot/ctl/commands.h"
#include "knot/ctl/process.h"
#include "knot/dnssec/key-events.h"
#include "knot/events/events.h"
#include "knot/events/handlers.h"
#include "knot/journal/journal_metadata.h"
#include "knot/nameserver/query_module.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/backup.h"
#include "knot/zone/digest.h"
#include "knot/zone/timers.h"
#include "knot/zone/zonedb-load.h"
#include "knot/zone/zonefile.h"
#include "libknot/libknot.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/atomic.h"
#include "contrib/files.h"
#include "contrib/string.h"
#include "contrib/strtonum.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/ucw/lists.h"
#include "libzscanner/scanner.h"

#define MATCH_OR_FILTER(args, code) ((args)->data[KNOT_CTL_IDX_FILTER] == NULL || \
                                     strchr((args)->data[KNOT_CTL_IDX_FILTER], (code)) != NULL)

#define MATCH_AND_FILTER(args, code) ((args)->data[KNOT_CTL_IDX_FILTER] != NULL && \
                                      strchr((args)->data[KNOT_CTL_IDX_FILTER], (code)) != NULL)

typedef struct {
	ctl_args_t *args;
	int type_filter; // -1: no specific type, [0, 2^16]: specific type.
	knot_dump_style_t style;
	knot_ctl_data_t data;
	knot_dname_txt_storage_t zone;
	knot_dname_txt_storage_t owner;
	char ttl[16];
	char type[32];
	char rdata[2 * 65536];
} send_ctx_t;

static struct {
	send_ctx_t send_ctx;
	zs_scanner_t scanner;
	char txt_rr[sizeof(((send_ctx_t *)0)->owner) +
	            sizeof(((send_ctx_t *)0)->ttl) +
	            sizeof(((send_ctx_t *)0)->type) +
	            sizeof(((send_ctx_t *)0)->rdata)];
} ctl_globals[CTL_MAX_CONCURRENT + 1];

static bool allow_blocking_while_ctl_txn(zone_event_type_t event)
{
	// this can be allowed for those events that do NOT create a zone_update_t
	switch (event) {
	case ZONE_EVENT_UFREEZE:
	case ZONE_EVENT_UTHAW:
	case ZONE_EVENT_NOTIFY:
	case ZONE_EVENT_FLUSH:
		return true;
	default:
		return false;
	}
}

/*!
 * Evaluates a filter pair and checks for conflicting filters.
 *
 * \param[in]  args        Command arguments.
 * \param[out] param       The filter to be set.
 * \param[in]  dflt        Default filter value.
 * \param[in]  filter      Name of the filter.
 * \param[in]  neg_filter  Name of the negative filter.
 *
 * \return false if there is a filter conflict, true otherwise.
 */
static bool eval_opposite_filters(ctl_args_t *args, bool *param, bool dflt,
                                  int filter, int neg_filter)
{
	bool set = MATCH_AND_FILTER(args, filter);
	bool unset = MATCH_AND_FILTER(args, neg_filter);

	*param = dflt ? (set || !unset) : (set && !unset);
	return !(set && unset);
}

static bool eval_backup_filters(ctl_args_t *args, knot_backup_params_t *filters,
                                const backup_filter_list_t *item, knot_backup_params_t dflts)
{
	bool val;
	bool ret = eval_opposite_filters(args, &val, dflts & item->param,
	                                 item->filter, item->neg_filter);
	if (ret) {
		*filters |= item->param * val;
	}

	return ret;
}

static int schedule_trigger(zone_t *zone, ctl_args_t *args, zone_event_type_t event,
                            bool user)
{
	int ret = KNOT_EOK;

	if (ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_BLOCKING)) {
		if (!allow_blocking_while_ctl_txn(event) &&
		    zone->control_update != NULL) {
			return KNOT_TXN_EEXISTS;
		}
		ret = zone_events_schedule_blocking(zone, event, user);
	} else if (user) {
		zone_events_schedule_user(zone, event);
	} else {
		zone_events_schedule_now(zone, event);
	}

	return ret;
}

static void ctl_log_conf_data(knot_ctl_data_t *data)
{
	if (data == NULL) {
		return;
	}

	const char *section = (*data)[KNOT_CTL_IDX_SECTION];
	const char *item = (*data)[KNOT_CTL_IDX_ITEM];
	const char *id = (*data)[KNOT_CTL_IDX_ID];

	if (section != NULL) {
		log_ctl_debug("control, config item '%s%s%s%s%s%s'", section,
		              (id   != NULL ? "["  : ""),
		              (id   != NULL ? id   : ""),
		              (id   != NULL ? "]"  : ""),
		              (item != NULL ? "."  : ""),
		              (item != NULL ? item : ""));
	}
}

static void send_error(ctl_args_t *args, const char *msg)
{
	knot_ctl_data_t data;
	memcpy(&data, args->data, sizeof(data));

	data[KNOT_CTL_IDX_ERROR] = msg;

	int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
	if (ret != KNOT_EOK) {
		log_ctl_debug("control, failed to send error (%s)", knot_strerror(ret));
	}
}

static int get_zone(ctl_args_t *args, zone_t **zone)
{
	const char *name = args->data[KNOT_CTL_IDX_ZONE];
	assert(name != NULL);

	knot_dname_storage_t buff;
	knot_dname_t *dname = knot_dname_from_str(buff, name, sizeof(buff));
	if (dname == NULL) {
		return KNOT_EINVAL;
	}
	knot_dname_to_lower(dname);

	*zone = knot_zonedb_find(args->server->zone_db, dname);
	if (*zone == NULL) {
		return KNOT_ENOZONE;
	}

	return KNOT_EOK;
}

static int zones_apply(ctl_args_t *args, int (*fcn)(zone_t *, ctl_args_t *))
{
	int ret;

	// Process all configured zones if none is specified.
	if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
		bool failed = false;
		knot_zonedb_iter_t *it = knot_zonedb_iter_begin(args->server->zone_db);
		while (!knot_zonedb_iter_finished(it)) {
			args->suppress = false;
			ret = fcn((zone_t *)knot_zonedb_iter_val(it), args);
			if (ret != KNOT_EOK && !args->suppress) {
				failed = true;
			}
			knot_zonedb_iter_next(it);
		}
		knot_zonedb_iter_free(it);

		if (failed) {
			ret = KNOT_CTL_EZONE;
			log_ctl_error("control, error (%s)", knot_strerror(ret));
			send_error(args, knot_strerror(ret));
		}

		return KNOT_EOK;
	}

	while (true) {
		zone_t *zone;
		ret = get_zone(args, &zone);
		if (ret == KNOT_EOK) {
			ret = fcn(zone, args);
		}
		if (ret != KNOT_EOK) {
			log_ctl_zone_str_error(args->data[KNOT_CTL_IDX_ZONE],
			                       "control, error (%s)", knot_strerror(ret));
			send_error(args, knot_strerror(ret));
		}

		// Get next zone name.
		ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
		if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
			break;
		}
		strtolower((char *)args->data[KNOT_CTL_IDX_ZONE]);

		// Log the other zones the same way as the first one from process.c.
		log_ctl_zone_str_info(args->data[KNOT_CTL_IDX_ZONE],
		                      "control, received command '%s'",
		                      args->data[KNOT_CTL_IDX_CMD]);
	}

	return ret;
}

static int zone_status(zone_t *zone, ctl_args_t *args)
{
	knot_dname_txt_storage_t name;
	if (knot_dname_to_str(name, zone->name, sizeof(name)) == NULL) {
		return KNOT_EINVAL;
	}

	char flags[16] = "";
	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_ZONE] = name,
		[KNOT_CTL_IDX_FLAGS] = flags
	};

	const bool slave = zone_is_slave(conf(), zone);
	if (slave) {
		strlcat(flags, CTL_FLAG_STATUS_SLAVE, sizeof(flags));
	}
	const bool empty = (zone->contents == NULL);
	if (empty) {
		strlcat(flags, CTL_FLAG_STATUS_EMPTY, sizeof(flags));
	}
	const bool member = (zone->flags & ZONE_IS_CAT_MEMBER);
	if (member) {
		strlcat(flags, CTL_FLAG_STATUS_MEMBER, sizeof(flags));
	}

	int ret;
	char buff[128];
	knot_ctl_type_t type = KNOT_CTL_TYPE_DATA;

	if (MATCH_OR_FILTER(args, CTL_FILTER_STATUS_ROLE)) {
		data[KNOT_CTL_IDX_TYPE] = "role";

		if (slave) {
			data[KNOT_CTL_IDX_DATA] = "slave";
		} else {
			data[KNOT_CTL_IDX_DATA] = "master";
		}

		ret = knot_ctl_send(args->ctl, type, &data);
		if (ret != KNOT_EOK) {
			return ret;
		} else {
			type = KNOT_CTL_TYPE_EXTRA;
		}
	}

	if (MATCH_OR_FILTER(args, CTL_FILTER_STATUS_SERIAL)) {
		data[KNOT_CTL_IDX_TYPE] = "serial";

		rcu_read_lock();
		if (zone->contents == NULL) {
			ret = snprintf(buff, sizeof(buff), STATUS_EMPTY);
		} else {
			knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
			                                     KNOT_RRTYPE_SOA);
			ret = snprintf(buff, sizeof(buff), "%u", knot_soa_serial(soa->rdata));
		}
		rcu_read_unlock();
		if (ret < 0 || ret >= sizeof(buff)) {
			return KNOT_ESPACE;
		}

		data[KNOT_CTL_IDX_DATA] = buff;

		ret = knot_ctl_send(args->ctl, type, &data);
		if (ret != KNOT_EOK) {
			return ret;
		} else {
			type = KNOT_CTL_TYPE_EXTRA;
		}
	}

	if (MATCH_OR_FILTER(args, CTL_FILTER_STATUS_TRANSACTION)) {
		data[KNOT_CTL_IDX_TYPE] = "transaction";
		data[KNOT_CTL_IDX_DATA] = (zone->control_update != NULL) ? "open" : STATUS_EMPTY;
		ret = knot_ctl_send(args->ctl, type, &data);
		if (ret != KNOT_EOK) {
			return ret;
		} else {
			type = KNOT_CTL_TYPE_EXTRA;
		}
	}

	const bool ufrozen = zone->events.ufrozen;
	if (MATCH_OR_FILTER(args, CTL_FILTER_STATUS_FREEZE)) {
		data[KNOT_CTL_IDX_TYPE] = "freeze";
		if (ufrozen) {
			if (zone_events_get_time(zone, ZONE_EVENT_UTHAW) < time(NULL)) {
				data[KNOT_CTL_IDX_DATA] = "yes";
			} else {
				data[KNOT_CTL_IDX_DATA] = "thawing";
			}
		} else {
			if (zone_events_get_time(zone, ZONE_EVENT_UFREEZE) < time(NULL)) {
				data[KNOT_CTL_IDX_DATA] = STATUS_EMPTY;
			} else {
				data[KNOT_CTL_IDX_DATA] = "freezing";
			}
		}
		ret = knot_ctl_send(args->ctl, type, &data);
		if (ret != KNOT_EOK) {
			return ret;
		} else {
			type = KNOT_CTL_TYPE_EXTRA;
		}

		data[KNOT_CTL_IDX_TYPE] = "XFR-freeze";
		if (zone_get_flag(zone, ZONE_XFR_FROZEN, false)) {
			data[KNOT_CTL_IDX_DATA] = "yes";
		} else {
			data[KNOT_CTL_IDX_DATA] = STATUS_EMPTY;
		}
		ret = knot_ctl_send(args->ctl, type, &data);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (MATCH_OR_FILTER(args, CTL_FILTER_STATUS_CATALOG)) {
		char buf[1 + KNOT_DNAME_TXT_MAXLEN + 1 + CATALOG_GROUP_MAXLEN + 1] = "";
		data[KNOT_CTL_IDX_TYPE] = "catalog";
		data[KNOT_CTL_IDX_DATA] = buf;

		if (member) {
			const knot_dname_t *catz;
			const char *group;
			void *to_free;
			ret = catalog_get_catz(zone_catalog(zone), zone->name,
			                       &catz, &group, &to_free);
			if (ret == KNOT_EOK) {
				if (knot_dname_to_str(buf, catz, sizeof(buf)) == NULL) {
					buf[0] = '\0';
				}
				if (group[0] != '\0') {
					size_t idx = strlcat(buf, "#", sizeof(buf));
					(void)strlcat(buf + idx, group, sizeof(buf) - idx);
				}
				free(to_free);
			}
		} else {
			conf_val_t val = conf_zone_get(conf(), C_CATALOG_ROLE, zone->name);
			switch (conf_opt(&val)) {
			case CATALOG_ROLE_INTERPRET:
				data[KNOT_CTL_IDX_DATA] = "interpret";
				break;
			case CATALOG_ROLE_GENERATE:
				data[KNOT_CTL_IDX_DATA] = "generate";
				break;
			case CATALOG_ROLE_MEMBER:
				buf[0] = '@';
				val = conf_zone_get(conf(), C_CATALOG_ZONE, zone->name);
				if (knot_dname_to_str(buf + 1, conf_dname(&val), sizeof(buf) - 1) == NULL) {
					buf[1] = '\0';
				}
				val = conf_zone_get(conf(), C_CATALOG_GROUP, zone->name);
				if (val.code == KNOT_EOK) {
					size_t idx = strlcat(buf, "#", sizeof(buf));
					(void)strlcat(buf + idx, conf_str(&val), sizeof(buf) - idx);
				}
				break;
			default:
				data[KNOT_CTL_IDX_DATA] = STATUS_EMPTY;
			}
		}

		ret = knot_ctl_send(args->ctl, type, &data);
		if (ret != KNOT_EOK) {
			return ret;
		} else {
			type = KNOT_CTL_TYPE_EXTRA;
		}
	}

	if (MATCH_OR_FILTER(args, CTL_FILTER_STATUS_EVENTS)) {
		for (zone_event_type_t i = 0; i < ZONE_EVENT_COUNT; i++) {
			// Events not worth showing or used elsewhere.
			if (i == ZONE_EVENT_UFREEZE || i == ZONE_EVENT_UTHAW) {
				continue;
			}

			data[KNOT_CTL_IDX_TYPE] = zone_events_get_name(i);
			time_t ev_time = zone_events_get_time(zone, i);
			if (zone->events.running && zone->events.type == i) {
				ret = snprintf(buff, sizeof(buff), "running");
			} else if (ev_time <= 0) {
				ret = snprintf(buff, sizeof(buff), STATUS_EMPTY);
			} else if (ev_time <= time(NULL)) {
				bool frozen = ufrozen && ufreeze_applies(i);
				ret = snprintf(buff, sizeof(buff), frozen ? "frozen" : "pending");
			} else {
				knot_time_print_t format = TIME_PRINT_HUMAN_MIXED;
				if (ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS],
				                 CTL_FLAG_STATUS_UNIXTIME)) {
					format = TIME_PRINT_UNIX;
				}
				ret = knot_time_print(format, ev_time, buff, sizeof(buff));
			}
			if (ret < 0 || ret >= sizeof(buff)) {
				return KNOT_ESPACE;
			}
			data[KNOT_CTL_IDX_DATA] = buff;

			ret = knot_ctl_send(args->ctl, type, &data);
			if (ret != KNOT_EOK) {
				return ret;
			} else {
				type = KNOT_CTL_TYPE_EXTRA;
			}
		}
	}

	return KNOT_EOK;
}

static int zone_reload(zone_t *zone, _unused_ ctl_args_t *args)
{
	if (zone_expired(zone)) {
		args->suppress = true;
		return KNOT_ENOTSUP;
	}

	if (ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_FORCE)) {
		return zone_reload_modules(conf(), args->server, zone->name);
	}

	return schedule_trigger(zone, args, ZONE_EVENT_LOAD, true);
}

static int zone_refresh(zone_t *zone, _unused_ ctl_args_t *args)
{
	if (!zone_is_slave(conf(), zone)) {
		args->suppress = true;
		return KNOT_ENOTSUP;
	}

	zone->zonefile.bootstrap_cnt = 0; // restart delays
	return schedule_trigger(zone, args, ZONE_EVENT_REFRESH, true);
}

static int zone_retransfer(zone_t *zone, _unused_ ctl_args_t *args)
{
	if (!zone_is_slave(conf(), zone)) {
		args->suppress = true;
		return KNOT_ENOTSUP;
	}

	zone_set_flag(zone, ZONE_FORCE_AXFR);
	zone->zonefile.bootstrap_cnt = 0; // restart delays
	return schedule_trigger(zone, args, ZONE_EVENT_REFRESH, true);
}

static int zone_notify(zone_t *zone, _unused_ ctl_args_t *args)
{
	zone_notifailed_clear(zone);
	return schedule_trigger(zone, args, ZONE_EVENT_NOTIFY, true);
}

static int zone_flush(zone_t *zone, ctl_args_t *args)
{
	if (MATCH_AND_FILTER(args, CTL_FILTER_FLUSH_OUTDIR)) {
		rcu_read_lock();
		int ret = zone_dump_to_dir(conf(), zone, args->data[KNOT_CTL_IDX_DATA]);
		rcu_read_unlock();
		if (ret != KNOT_EOK) {
			log_zone_warning(zone->name, "failed to update zone file (%s)",
			                 knot_strerror(ret));
		}
		return ret;
	}

	zone_set_flag(zone, ZONE_USER_FLUSH);
	if (ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_FORCE)) {
		zone_set_flag(zone, ZONE_FORCE_FLUSH);
	}

	return schedule_trigger(zone, args, ZONE_EVENT_FLUSH, true);
}

static void report_insufficient_backup(ctl_args_t *args, zone_backup_ctx_t *ctx)
{
	const char *msg = "missing in backup:%s";
	char list[128];  // It must hold the longest list of components + 1.
	int remain = sizeof(list);
	char *buf = list;

	for (const backup_filter_list_t *item = backup_filters;
	     item->name != NULL; item++) {
		if (ctx->backup_params & item->param) {
			int n = snprintf(buf, remain, " %s,", item->name);
			buf += n;
			remain -= n;
		}
	}
	assert(remain > 1);

	assert(buf > list);
	*(--buf) = '\0';

	if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
		log_warning(msg, list);
	} else {
		log_zone_str_warning(args->data[KNOT_CTL_IDX_ZONE], msg, list);
	}
}

static int init_backup(ctl_args_t *args, bool restore_mode)
{
	if (!MATCH_AND_FILTER(args, CTL_FILTER_BACKUP_OUTDIR)) {
		return KNOT_ENOPARAM;
	}

	// Make sure that the backup outdir is not the same as the server DB storage.
	conf_val_t db_storage_val = conf_db_param(conf(), C_STORAGE);
	const char *db_storage = conf_str(&db_storage_val);

	const char *backup_dir = args->data[KNOT_CTL_IDX_DATA];

	if (same_path(backup_dir, db_storage)) {
		char *msg = sprintf_alloc("%s the database storage directory not allowed",
		                          restore_mode ? "restore from" : "backup to");

		if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
			log_ctl_error("%s", msg);
		} else {
			log_ctl_zone_str_error(args->data[KNOT_CTL_IDX_ZONE], "%s", msg);
		}
		free(msg);
		return KNOT_EINVAL;
	}

	// Evaluate filters (and possibly fail) before writing to the filesystem.
	knot_backup_params_t filters = 0;
	knot_backup_params_t dflts = restore_mode ? BACKUP_PARAM_DFLT_R : BACKUP_PARAM_DFLT_B;

	// Filter '+keysonly' silently changes all defaults to '+no...'.
	dflts = MATCH_AND_FILTER(args, BACKUP_PARAM_KEYSONLY) ? BACKUP_PARAM_EMPTY : dflts;

	for (const backup_filter_list_t *item = backup_filters; item->name != NULL; item++) {
		if (!eval_backup_filters(args, &filters, item, dflts)) {
			return KNOT_EXPARAM;
		}
	}

	// Priority of '+kaspdb' over '+keysonly'.
	filters &= ~((bool)(filters & BACKUP_PARAM_KASPDB) * BACKUP_PARAM_KEYSONLY);

	bool forced = ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_FORCE);

	zone_backup_ctx_t *ctx;

	// The present timer db size is not up-to-date, use the maximum one.
	conf_val_t timer_db_size = conf_db_param(conf(), C_TIMER_DB_MAX_SIZE);

	int ret = zone_backup_init(restore_mode, filters, forced,
	                           args->data[KNOT_CTL_IDX_DATA],
	                           knot_lmdb_copy_size(&args->server->kaspdb),
	                           conf_int(&timer_db_size),
	                           knot_lmdb_copy_size(&args->server->journaldb),
	                           knot_lmdb_copy_size(&args->server->catalog.db),
	                           &ctx);

	if (ret == KNOT_EBACKUPDATA) {
		report_insufficient_backup(args, ctx);
		free(ctx);
	}

	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(ctx != NULL);

	zone_backups_add(&args->server->backup_ctxs, ctx);

	return ret;
}

static zone_backup_ctx_t *latest_backup_ctx(ctl_args_t *args)
{
	// no need to mutex in this case
	return (zone_backup_ctx_t *)TAIL(args->server->backup_ctxs.ctxs);
}

static int deinit_backup(ctl_args_t *args)
{
	return zone_backup_deinit(latest_backup_ctx(args));
}

static int zone_keys_load(zone_t *zone, _unused_ ctl_args_t *args);

static int zone_backup_cmd(zone_t *zone, ctl_args_t *args)
{
	zone_backup_ctx_t *ctx = latest_backup_ctx(args);
	if (!ctx->restore_mode && ctx->failed) {
		// No need to proceed with already faulty backup.
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	pthread_mutex_lock(&zone->cu_lock);
	if (zone->backup_ctx != NULL) {
		log_zone_warning(zone->name, "backup or restore already in progress, skipping zone");
		ctx->failed = true;
		ret = KNOT_EPROGRESS;
	}

	if (ctx->restore_mode && zone->control_update != NULL && ret == KNOT_EOK) {
		log_zone_warning(zone->name, "restoring backup not possible due to open control transaction");
		ctx->failed = true;
		ret = KNOT_TXN_EEXISTS;
	}

	if (ret == KNOT_EOK) {
		zone->backup_ctx = ctx;
	}
	pthread_mutex_unlock(&zone->cu_lock);

	ctx->zone_count++;

	if (!ctx->backup_global && ret == KNOT_EOK) {
		ret = global_backup(ctx, zone_catalog(zone), zone->name);
	}

	bool finish = false;
	if ((ctx->backup_params & BACKUP_PARAM_KEYSONLY) && ret == KNOT_EOK) {
		ret = zone_backup_keysonly(ctx, conf(), zone);

		if (ctx->restore_mode && ret == KNOT_EOK) {
			ret = zone_keys_load(zone, args);
		}

		if (!(ctx->backup_params & BACKUP_PARAM_EVENT)) {
			finish = true;
		}
	}

	if (ret != KNOT_EOK || finish) {
		zone->backup_ctx = NULL;
		return ret;
	}

	pthread_mutex_lock(&ctx->readers_mutex);
	ctx->readers++;
	pthread_mutex_unlock(&ctx->readers_mutex);

	return schedule_trigger(zone, args, ZONE_EVENT_BACKUP, true);
}

static int zones_apply_backup(ctl_args_t *args, bool restore_mode)
{
	int ret_deinit;
	int ret = init_backup(args, restore_mode);

	if (ret != KNOT_EOK) {
		char *msg = sprintf_alloc("%s init failed (%s)",
		                          restore_mode ? "restore" : "backup",
		                          knot_strerror(ret));

		if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
			log_ctl_error("%s", msg);
		} else {
			log_ctl_zone_str_error(args->data[KNOT_CTL_IDX_ZONE],
			                       "%s", msg);
		}
		free (msg);

		/* Warning: zone name in the control command params discarded here. */
		args->data[KNOT_CTL_IDX_ZONE] = NULL;
		send_error(args, knot_strerror(ret));
		return KNOT_CTL_EZONE;
	}

	zone_backup_ctx_t *ctx = latest_backup_ctx(args);

	/* QUIC - server key and cert backup. */
	ret = backup_quic(ctx, args->server->quic_active || args->server->tls_active);
	if (ret != KNOT_EOK) {
		log_ctl_error("control, QUIC %s error (%s)",
		              restore_mode ? "restore" : "backup",
		              knot_strerror(ret));
		send_error(args, knot_strerror(ret));
		ret = KNOT_EOK;
		goto done;
	}

	/* Global catalog zones backup. */
	if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
		ctx->backup_global = true;
		ret = global_backup(ctx, &args->server->catalog, NULL);
		if (ret != KNOT_EOK) {
			log_ctl_error("control, error (%s)", knot_strerror(ret));
			send_error(args, knot_strerror(ret));
			ret = KNOT_EOK;
			goto done;
		}
	}

	ret = zones_apply(args, zone_backup_cmd);

done:
	ret_deinit = deinit_backup(args);
	return ret != KNOT_EOK ? ret : ret_deinit;
}

static int zone_sign(zone_t *zone, _unused_ ctl_args_t *args)
{
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (!conf_bool(&val)) {
		args->suppress = true;
		return KNOT_ENOTSUP;
	}

	zone_set_flag(zone, ZONE_FORCE_RESIGN);
	return schedule_trigger(zone, args, ZONE_EVENT_DNSSEC, true);
}

static int zone_validate(zone_t *zone, _unused_ ctl_args_t *args)
{
	return schedule_trigger(zone, args, ZONE_EVENT_VALIDATE, true);
}

static int zone_keys_load(zone_t *zone, _unused_ ctl_args_t *args)
{
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (!conf_bool(&val)) {
		args->suppress = true;
		return KNOT_ENOTSUP;
	}

	if (zone->contents == NULL) {
		log_zone_notice(zone->name, "zone is not loaded yet");
		return KNOT_EOK;
	}

	return schedule_trigger(zone, args, ZONE_EVENT_DNSSEC, true);
}

static int zone_key_roll(zone_t *zone, ctl_args_t *args)
{
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (!conf_bool(&val)) {
		args->suppress = true;
		return KNOT_ENOTSUP;
	}

	const char *key_type = args->data[KNOT_CTL_IDX_TYPE];
	if (strncasecmp(key_type, "ksk", 3) == 0) {
		zone_set_flag(zone, ZONE_FORCE_KSK_ROLL);
	} else if (strncasecmp(key_type, "zsk", 3) == 0) {
		zone_set_flag(zone, ZONE_FORCE_ZSK_ROLL);
	} else {
		return KNOT_EINVAL;
	}

	return schedule_trigger(zone, args, ZONE_EVENT_DNSSEC, true);
}

static int zone_ksk_sbm_confirm(zone_t *zone, _unused_ ctl_args_t *args)
{
	kdnssec_ctx_t ctx = { 0 };

	int ret = kdnssec_ctx_init(conf(), &ctx, zone->name, zone_kaspdb(zone), NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_dnssec_ksk_sbm_confirm(&ctx, 0);
	kdnssec_ctx_deinit(&ctx);

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (ret == KNOT_EOK && conf_bool(&val)) {
		// NOT zone_events_schedule_user() or schedule_trigger(), intentionally!
		zone_events_schedule_now(zone, ZONE_EVENT_DNSSEC);
	}

	return ret;
}

static int zone_freeze(zone_t *zone, _unused_ ctl_args_t *args)
{
	return schedule_trigger(zone, args, ZONE_EVENT_UFREEZE, false);
}

static int zone_thaw(zone_t *zone, _unused_ ctl_args_t *args)
{
	return schedule_trigger(zone, args, ZONE_EVENT_UTHAW, false);
}

static int zone_xfr_freeze(zone_t *zone, _unused_ ctl_args_t *args)
{
	zone_set_flag(zone, ZONE_XFR_FROZEN);

	log_zone_info(zone->name, "outgoing XFR frozen");

	return KNOT_EOK;
}

static int zone_xfr_thaw(zone_t *zone, _unused_ ctl_args_t *args)
{
	zone_unset_flag(zone, ZONE_XFR_FROZEN);

	log_zone_info(zone->name, "outgoing XFR unfrozen");

	return KNOT_EOK;
}

static int zone_txn_begin_l(zone_t *zone, _unused_ ctl_args_t *args)
{
	if (zone->control_update != NULL || conf()->io.txn != NULL) {
		return KNOT_TXN_EEXISTS;
	}

	struct zone_backup_ctx *backup_ctx = zone->backup_ctx;
	if (backup_ctx != NULL && backup_ctx->restore_mode) {
		log_zone_warning(zone->name, "zone restore pending, try opening control transaction later");
		return KNOT_EAGAIN;
	}

	if (zone->events.running && zone->events.type >= 0 && zone->events.blocking[zone->events.type] != NULL) {
		log_zone_warning(zone->name, "some blocking event running, try opening control transaction later");
		return KNOT_EAGAIN;
	}

	zone->control_update = malloc(sizeof(zone_update_t));
	if (zone->control_update == NULL) {
		return KNOT_ENOMEM;
	}

	zone_update_flags_t type = (zone->contents == NULL) ? UPDATE_FULL : UPDATE_INCREMENTAL;
	int ret = zone_update_init(zone->control_update, zone, type | UPDATE_STRICT);
	if (ret != KNOT_EOK) {
		free(zone->control_update);
		zone->control_update = NULL;
	}

	return ret;
}

static int zone_txn_begin(zone_t *zone, ctl_args_t *args)
{
	pthread_mutex_lock(&zone->cu_lock);
	int ret = zone_txn_begin_l(zone, args);
	pthread_mutex_unlock(&zone->cu_lock);
	return ret;
}

static int zone_txn_commit_l(zone_t *zone, _unused_ ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		args->suppress = true;
		return KNOT_TXN_ENOTEXISTS;
	}

	int ret = zone_update_semcheck(conf(), zone->control_update);
	if (ret != KNOT_EOK) {
		return ret; // Recoverable error.
	}

	// NOOP if empty changeset/contents.
	if (((zone->control_update->flags & UPDATE_INCREMENTAL) &&
	     changeset_empty(&zone->control_update->change)) ||
	    ((zone->control_update->flags & UPDATE_FULL) &&
	     zone_contents_is_empty(zone->control_update->new_cont))) {
		zone_control_clear(zone);
		return KNOT_EOK;
	}

	// Sign update.
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	bool dnssec_enable = conf_bool(&val);
	val = conf_zone_get(conf(), C_ZONEMD_GENERATE, zone->name);
	unsigned digest_alg = conf_opt(&val);
	if (dnssec_enable) {
		if (zone->control_update->flags & UPDATE_FULL) {
			zone_sign_reschedule_t resch = { 0 };
			zone_sign_roll_flags_t rflags = KEY_ROLL_ALLOW_ALL;
			ret = knot_dnssec_zone_sign(zone->control_update, conf(), 0, rflags, 0, &resch);
			event_dnssec_reschedule(conf(), zone, &resch, false);
		} else {
			ret = knot_dnssec_sign_update(zone->control_update, conf());
		}
	} else if (digest_alg != ZONE_DIGEST_NONE) {
		if (zone_update_to(zone->control_update) == NULL) {
			ret = zone_update_increment_soa(zone->control_update, conf());
		}
		if (ret == KNOT_EOK) {
			ret = zone_update_add_digest(zone->control_update, digest_alg, false);
		}
	}
	if (ret != KNOT_EOK) {
		zone_control_clear(zone);
		return ret;
	}

	ret = zone_update_commit(conf(), zone->control_update);
	if (ret != KNOT_EOK) {
		zone_control_clear(zone);
		return ret;
	}

	free(zone->control_update);
	zone->control_update = NULL;

	zone_schedule_notify(zone, 0);

	return KNOT_EOK;
}

static int zone_txn_commit(zone_t *zone, ctl_args_t *args)
{
	pthread_mutex_lock(&zone->cu_lock);
	int ret = zone_txn_commit_l(zone, args);
	pthread_mutex_unlock(&zone->cu_lock);
	return ret;
}

static int zone_txn_abort(zone_t *zone, _unused_ ctl_args_t *args)
{
	pthread_mutex_lock(&zone->cu_lock);
	if (zone->control_update == NULL) {
		args->suppress = true;
		pthread_mutex_unlock(&zone->cu_lock);
		return KNOT_TXN_ENOTEXISTS;
	}

	zone_control_clear(zone);

	pthread_mutex_unlock(&zone->cu_lock);
	return KNOT_EOK;
}

static int init_send_ctx(send_ctx_t *ctx, const knot_dname_t *zone_name,
                         ctl_args_t *args)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->args = args;

	// Set the dump style.
	ctx->style.show_ttl = true;
	ctx->style.original_ttl = true;
	ctx->style.human_timestamp = true;

	// Set the output data buffers.
	ctx->data[KNOT_CTL_IDX_ZONE]  = ctx->zone;
	ctx->data[KNOT_CTL_IDX_OWNER] = ctx->owner;
	ctx->data[KNOT_CTL_IDX_TTL]   = ctx->ttl;
	ctx->data[KNOT_CTL_IDX_TYPE]  = ctx->type;
	ctx->data[KNOT_CTL_IDX_DATA]  = ctx->rdata;

	// Set the ZONE.
	if (knot_dname_to_str(ctx->zone, zone_name, sizeof(ctx->zone)) == NULL) {
		return KNOT_EINVAL;
	}

	// Set the TYPE filter.
	if (args->data[KNOT_CTL_IDX_TYPE] != NULL) {
		uint16_t type;
		if (knot_rrtype_from_string(args->data[KNOT_CTL_IDX_TYPE], &type) != 0) {
			return KNOT_EINVAL;
		}
		ctx->type_filter = type;
	} else {
		ctx->type_filter = -1;
	}

	return KNOT_EOK;
}

static int send_rrset(knot_rrset_t *rrset, send_ctx_t *ctx)
{
	if (rrset->type != KNOT_RRTYPE_RRSIG) {
		int ret = snprintf(ctx->ttl, sizeof(ctx->ttl), "%u", rrset->ttl);
		if (ret <= 0 || ret >= sizeof(ctx->ttl)) {
			return KNOT_ESPACE;
		}
	}

	if (knot_rrtype_to_string(rrset->type, ctx->type, sizeof(ctx->type)) < 0) {
		return KNOT_ESPACE;
	}

	for (size_t i = 0; i < rrset->rrs.count; ++i) {
		if (rrset->type == KNOT_RRTYPE_RRSIG) {
			int ret = snprintf(ctx->ttl, sizeof(ctx->ttl), "%u",
			                   knot_rrsig_original_ttl(knot_rdataset_at(&rrset->rrs, i)));
			if (ret <= 0 || ret >= sizeof(ctx->ttl)) {
				return KNOT_ESPACE;
			}
		}

		int ret = knot_rrset_txt_dump_data(rrset, i, ctx->rdata,
		                                   sizeof(ctx->rdata), &ctx->style);
		if (ret < 0) {
			return ret;
		}

		ret = knot_ctl_send(ctx->args->ctl, KNOT_CTL_TYPE_DATA, &ctx->data);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int send_node(zone_node_t *node, void *ctx_void)
{
	send_ctx_t *ctx = ctx_void;
	if (knot_dname_to_str(ctx->owner, node->owner, sizeof(ctx->owner)) == NULL) {
		return KNOT_EINVAL;
	}

	for (size_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node, i);

		// Check for requested TYPE.
		if (ctx->type_filter != -1 && rrset.type != ctx->type_filter) {
			continue;
		}

		int ret = send_rrset(&rrset, ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int get_owner(uint8_t *out, size_t out_len, knot_dname_t *origin,
                     ctl_args_t *args)
{
	const char *owner = args->data[KNOT_CTL_IDX_OWNER];
	assert(owner != NULL);

	bool fqdn = false;
	size_t prefix_len = 0;

	size_t owner_len = strlen(owner);
	if (owner_len > 0 && (owner_len != 1 || owner[0] != '@')) {
		// Check if the owner is FQDN.
		if (owner[owner_len - 1] == '.') {
			fqdn = true;
		}

		if (knot_dname_from_str(out, owner, out_len) == NULL) {
			return KNOT_EINVAL;
		}
		knot_dname_to_lower(out);

		prefix_len = knot_dname_size(out);
		if (prefix_len == 0) {
			return KNOT_EINVAL;
		}

		// Ignore trailing dot.
		prefix_len--;
	}

	// Append the origin.
	if (!fqdn) {
		size_t origin_len = knot_dname_size(origin);
		if (origin_len == 0 || origin_len > out_len - prefix_len) {
			return KNOT_EINVAL;
		}
		memcpy(out + prefix_len, origin, origin_len);
	}

	return KNOT_EOK;
}

static int zone_read(zone_t *zone, ctl_args_t *args)
{
	send_ctx_t *ctx = &ctl_globals[args->thread_idx].send_ctx;
	int ret = init_send_ctx(ctx, zone->name, args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	rcu_read_lock();
	zone_contents_t *contents = zone->contents;
	if (args->data[KNOT_CTL_IDX_OWNER] != NULL) {
		knot_dname_storage_t owner;

		ret = get_owner(owner, sizeof(owner), zone->name, args);
		if (ret != KNOT_EOK) {
			rcu_read_unlock();
			return ret;
		}

		const zone_node_t *node = zone_contents_node_or_nsec3(contents, owner);
		if (node == NULL) {
			rcu_read_unlock();
			return KNOT_ENONODE;
		}

		ret = send_node((zone_node_t *)node, ctx);
	} else if (contents != NULL) {
		ret = zone_contents_apply(contents, send_node, ctx);
		if (ret == KNOT_EOK) {
			ret = zone_contents_nsec3_apply(contents, send_node, ctx);
		}
	}
	rcu_read_unlock();

	return ret;
}

static int zone_flag_txn_get(zone_t *zone, ctl_args_t *args, const char *flag)
{
	if (zone->control_update == NULL) {
		args->suppress = true;
		return KNOT_TXN_ENOTEXISTS;
	}

	send_ctx_t *ctx = &ctl_globals[args->thread_idx].send_ctx;
	int ret = init_send_ctx(ctx, zone->name, args);
	if (ret != KNOT_EOK) {
		return ret;
	}
	ctx->data[KNOT_CTL_IDX_FLAGS] = flag;

	if (args->data[KNOT_CTL_IDX_OWNER] != NULL) {
		knot_dname_storage_t owner;

		ret = get_owner(owner, sizeof(owner), zone->name, args);
		if (ret != KNOT_EOK) {
			return ret;
		}

		const zone_node_t *node = zone_contents_node_or_nsec3(zone->control_update->new_cont, owner);
		if (node == NULL) {
			return KNOT_ENONODE;

		}

		ret = send_node((zone_node_t *)node, ctx);
	} else {
		zone_tree_it_t it = { 0 };
		ret = zone_tree_it_double_begin(zone->control_update->new_cont->nodes,
						zone->control_update->new_cont->nsec3_nodes,
						&it);
		while (ret == KNOT_EOK && !zone_tree_it_finished(&it)) {
			ret = send_node(zone_tree_it_val(&it), ctx);
			zone_tree_it_next(&it);
		}
		zone_tree_it_free(&it);
	}

	return ret;
}

static int zone_txn_get(zone_t *zone, ctl_args_t *args)
{
	pthread_mutex_lock(&zone->cu_lock);
	int ret = zone_flag_txn_get(zone, args, NULL);
	pthread_mutex_unlock(&zone->cu_lock);
	return ret;
}

static int send_changeset_part(changeset_t *ch, send_ctx_t *ctx, bool from)
{
	ctx->data[KNOT_CTL_IDX_FLAGS] = from ? CTL_FLAG_DIFF_REM : CTL_FLAG_DIFF_ADD;

	// Send SOA only if explicitly changed.
	if (ch->soa_to != NULL) {
		knot_rrset_t *soa = from ? ch->soa_from : ch->soa_to;
		assert(soa);

		char *owner = knot_dname_to_str(ctx->owner, soa->owner, sizeof(ctx->owner));
		if (owner == NULL) {
			return KNOT_EINVAL;
		}

		int ret = send_rrset(soa, ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Send other records.
	changeset_iter_t it;
	int ret = from ? changeset_iter_rem(&it, ch) : changeset_iter_add(&it, ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t rrset = changeset_iter_next(&it);
	while (!knot_rrset_empty(&rrset)) {
		char *owner = knot_dname_to_str(ctx->owner, rrset.owner, sizeof(ctx->owner));
		if (owner == NULL) {
			changeset_iter_clear(&it);
			return KNOT_EINVAL;
		}

		ret = send_rrset(&rrset, ctx);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&it);
			return ret;
		}

		rrset = changeset_iter_next(&it);
	}
	changeset_iter_clear(&it);

	return KNOT_EOK;
}

static int send_changeset(changeset_t *ch, send_ctx_t *ctx)
{
	// First send 'from' changeset part.
	int ret = send_changeset_part(ch, ctx, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Second send 'to' changeset part.
	return send_changeset_part(ch, ctx, false);
}

static int zone_txn_diff_l(zone_t *zone, ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		args->suppress = true;
		return KNOT_TXN_ENOTEXISTS;
	}

	// FULL update has no changeset to print, do a 'get' instead.
	if (zone->control_update->flags & UPDATE_FULL) {
		return zone_flag_txn_get(zone, args, CTL_FLAG_DIFF_ADD);
	}

	send_ctx_t *ctx = &ctl_globals[args->thread_idx].send_ctx;
	int ret = init_send_ctx(ctx, zone->name, args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return send_changeset(&zone->control_update->change, ctx);
}

static int zone_txn_diff(zone_t *zone, ctl_args_t *args)
{
	pthread_mutex_lock(&zone->cu_lock);
	int ret = zone_txn_diff_l(zone, args);
	pthread_mutex_unlock(&zone->cu_lock);
	return ret;
}

static int get_ttl(zone_t *zone, ctl_args_t *args, uint32_t *ttl)
{
	knot_dname_storage_t owner;

	int ret = get_owner(owner, sizeof(owner), zone->name, args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	const zone_node_t *node = zone_contents_node_or_nsec3(zone->control_update->new_cont, owner);
	if (node == NULL) {
		return KNOT_ENOTTL;
	}

	uint16_t type;
	if (knot_rrtype_from_string(args->data[KNOT_CTL_IDX_TYPE], &type) != 0) {
		return KNOT_EINVAL;
	}

	knot_rrset_t rrset = node_rrset(node, type);
	if (knot_rrset_empty(&rrset)) {
		return KNOT_ENOTTL;
	}
	*ttl = rrset.ttl;

	return KNOT_EOK;
}

static int create_rrset(knot_rrset_t **rrset, zone_t *zone, ctl_args_t *args,
                        bool need_ttl)
{
	knot_dname_txt_storage_t origin_buff;
	char *origin = knot_dname_to_str(origin_buff, zone->name, sizeof(origin_buff));
	if (origin == NULL) {
		return KNOT_EINVAL;
	}

	const char *owner = args->data[KNOT_CTL_IDX_OWNER];
	const char *type  = args->data[KNOT_CTL_IDX_TYPE];
	const char *data  = args->data[KNOT_CTL_IDX_DATA];
	const char *ttl   = need_ttl ? args->data[KNOT_CTL_IDX_TTL] : NULL;

	// Prepare a buffer for a reconstructed record.
	const size_t buff_len = sizeof(ctl_globals[args->thread_idx].txt_rr);
	char *buff = ctl_globals[args->thread_idx].txt_rr;

	// Choose default TTL if none was specified.
	uint32_t default_ttl = 0;
	if (ttl == NULL && need_ttl) {
		if (get_ttl(zone, args, &default_ttl) != KNOT_EOK) {
			conf_val_t val = conf_zone_get(conf(), C_DEFAULT_TTL, zone->name);
			default_ttl = conf_int(&val);
		}
	}

	// Reconstruct the record.
	int ret = snprintf(buff, buff_len, "%s %s %s %s\n",
	                   (owner != NULL ? owner : ""),
	                   (ttl   != NULL ? ttl   : ""),
	                   (type  != NULL ? type  : ""),
	                   (data  != NULL ? data  : ""));
	if (ret <= 0 || ret >= buff_len) {
		return KNOT_ESPACE;
	}
	size_t rdata_len = ret;

	// Parse the record.
	zs_scanner_t *scanner = &ctl_globals[args->thread_idx].scanner;
	if (zs_init(scanner, origin, KNOT_CLASS_IN, default_ttl) != 0 ||
	    zs_set_input_string(scanner, buff, rdata_len) != 0 ||
	    zs_parse_record(scanner) != 0 ||
	    scanner->state != ZS_STATE_DATA) {
		ret = KNOT_EPARSEFAIL;
		goto parser_failed;
	}
	knot_dname_to_lower(scanner->r_owner);

	// Create output rrset.
	*rrset = knot_rrset_new(scanner->r_owner, scanner->r_type,
	                        scanner->r_class, scanner->r_ttl, NULL);
	if (*rrset == NULL) {
		ret = KNOT_ENOMEM;
		goto parser_failed;
	}

	ret = knot_rrset_add_rdata(*rrset, scanner->r_data, scanner->r_data_length,
	                           NULL);
parser_failed:
	zs_deinit(scanner);

	return ret;
}

static int zone_txn_set_l(zone_t *zone, ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		args->suppress = true;
		return KNOT_TXN_ENOTEXISTS;
	}

	if (args->data[KNOT_CTL_IDX_OWNER] == NULL ||
	    args->data[KNOT_CTL_IDX_TYPE]  == NULL) {
		return KNOT_EINVAL;
	}

	knot_rrset_t *rrset;
	int ret = create_rrset(&rrset, zone, args, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_update_add(zone->control_update, rrset);
	knot_rrset_free(rrset, NULL);

	return ret;
}

static int zone_txn_set(zone_t *zone, ctl_args_t *args)
{
	pthread_mutex_lock(&zone->cu_lock);
	int ret = zone_txn_set_l(zone, args);
	pthread_mutex_unlock(&zone->cu_lock);
	return ret;
}

static int zone_txn_unset_l(zone_t *zone, ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		args->suppress = true;
		return KNOT_TXN_ENOTEXISTS;
	}

	if (args->data[KNOT_CTL_IDX_OWNER] == NULL) {
		return KNOT_EINVAL;
	}

	// Remove specific record.
	if (args->data[KNOT_CTL_IDX_DATA] != NULL) {
		if (args->data[KNOT_CTL_IDX_TYPE] == NULL) {
			return KNOT_EINVAL;
		}

		knot_rrset_t *rrset;
		int ret = create_rrset(&rrset, zone, args, false);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = zone_update_remove(zone->control_update, rrset);
		knot_rrset_free(rrset, NULL);
		return ret;
	} else {
		knot_dname_storage_t owner;

		int ret = get_owner(owner, sizeof(owner), zone->name, args);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Remove whole rrset.
		if (args->data[KNOT_CTL_IDX_TYPE] != NULL) {
			uint16_t type;
			if (knot_rrtype_from_string(args->data[KNOT_CTL_IDX_TYPE],
			                            &type) != 0) {
				return KNOT_EINVAL;
			}

			return zone_update_remove_rrset(zone->control_update, owner, type);
		// Remove whole node.
		} else {
			return zone_update_remove_node(zone->control_update, owner);
		}
	}
}

static int zone_txn_unset(zone_t *zone, ctl_args_t *args)
{
	pthread_mutex_lock(&zone->cu_lock);
	int ret = zone_txn_unset_l(zone, args);
	pthread_mutex_unlock(&zone->cu_lock);
	return ret;
}

static bool zone_exists(const knot_dname_t *zone, void *data)
{
	assert(zone);
	assert(data);

	knot_zonedb_t *db = data;

	return knot_zonedb_find(db, zone) != NULL;
}

static bool zone_names_distinct(const knot_dname_t *zone, void *data)
{
	assert(zone);
	assert(data);

	knot_dname_t *zone_to_purge = data;

	return !knot_dname_is_equal(zone, zone_to_purge);
}

static int drop_journal_if_orphan(const knot_dname_t *for_zone, void *ctx)
{
	server_t *server = ctx;
	zone_journal_t j = { &server->journaldb, for_zone };
	if (!zone_exists(for_zone, server->zone_db)) {
		return journal_scrape_with_md(j, false);
	}
	return KNOT_EOK;
}

static int purge_orphan_member_cb(const knot_dname_t *member, const knot_dname_t *owner,
                                  const knot_dname_t *catz, const char *group, void *ctx)
{
	server_t *server = ctx;
	if (zone_exists(member, server->zone_db)) {
		return KNOT_EOK;
	}

	const char *err_str = NULL;

	zone_t *cat_z = knot_zonedb_find(server->zone_db, catz);
	if (cat_z == NULL) {
		err_str = "existing";
	} else if (!cat_z->is_catalog_flag) {
		err_str = "catalog";
	}

	if (err_str == NULL) {
		return KNOT_EOK;
	}

	knot_dname_txt_storage_t catz_str;
	(void)knot_dname_to_str(catz_str, catz, sizeof(catz_str));
	log_zone_info(member, "member of a non-%s zone %s, purging",
	              err_str, catz_str);

	// Single-purpose fake zone_t containing only minimal data.
	// malloc() should suffice here, but clean zone_t is more mishandling-proof.
	zone_t *orphan = calloc(1, sizeof(zone_t));
	if (orphan == NULL) {
		return KNOT_ENOMEM;
	}

	orphan->name = (knot_dname_t *)member;
	orphan->server = server;

	const purge_flag_t params =
		PURGE_ZONE_TIMERS | PURGE_ZONE_JOURNAL | PURGE_ZONE_KASPDB |
		PURGE_ZONE_BEST | PURGE_ZONE_LOG;

	int ret = selective_zone_purge(conf(), orphan, params);
	free(orphan);
	if (ret != KNOT_EOK) {
		log_zone_error(member, "purge of an orphaned zone failed (%s)",
		               knot_strerror(ret));
	}

	// this deleting inside catalog DB iteration is OK, since
	// the deletion happens in RW txn, while the iteration in persistent RO txn
	ret = catalog_del(&server->catalog, member);
	if (ret != KNOT_EOK) {
		log_zone_error(member, "remove of an orphan from catalog failed (%s)",
		               knot_strerror(ret));
	}

	return KNOT_EOK;
}

static int catalog_orphans_sweep(server_t *server)
{
	catalog_t *cat = &server->catalog;
	int ret2 = KNOT_EOK;
	int ret = catalog_begin(cat);
	if (ret == KNOT_EOK) {
		ret = catalog_apply(cat, NULL,
		                    purge_orphan_member_cb,
		                    server, false);
		if (ret != KNOT_EOK) {
			log_error("failed to purge orphan members data (%s)",
			          knot_strerror(ret));
		}
		ret2 = catalog_commit(cat);
		synchronize_rcu();
		catalog_commit_cleanup(cat);
		if (ret2 != KNOT_EOK) {
			log_error("failed to update catalog (%s)",
			          knot_strerror(ret));
		}
	} else {
		log_error("can not open catalog for purging (%s)",
		          knot_strerror(ret));
	}

	return (ret == KNOT_EOK) ? ret2 : ret;
}

static void log_if_orphans_error(knot_dname_t *zone_name, int err, char *db_type,
                                 bool *failed)
{
	if (err == KNOT_EOK || err == KNOT_ENOENT || err == KNOT_EFILE) {
		return;
	}

	*failed = true;
	const char *error = knot_strerror(err);

	char *msg = sprintf_alloc("control, failed to purge orphan from %s database (%s)",
	                          db_type, error);
	if (msg == NULL) {
		return;
	}

	if (zone_name == NULL) {
		log_error("%s", msg);
	} else {
		log_zone_error(zone_name, "%s", msg);
	}
	free(msg);
}

static int orphans_purge(ctl_args_t *args)
{
	assert(args->data[KNOT_CTL_IDX_FILTER] != NULL);
	bool only_orphan = (strlen(args->data[KNOT_CTL_IDX_FILTER]) == 1);
	int ret;
	bool failed = false;

	if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
		// Purge KASP DB.
		if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_KASPDB)) {
			ret = kasp_db_sweep(&args->server->kaspdb,
			                    zone_exists, args->server->zone_db);
			log_if_orphans_error(NULL, ret, "KASP", &failed);
		}

		// Purge zone journals of unconfigured zones.
		if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_JOURNAL)) {
			ret = journals_walk(&args->server->journaldb,
			                    drop_journal_if_orphan, args->server);
			log_if_orphans_error(NULL, ret, "journal", &failed);
		}

		// Purge timers of unconfigured zones.
		if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_TIMERS)) {
			ret = zone_timers_sweep(&args->server->timerdb,
			                        zone_exists, args->server->zone_db);
			log_if_orphans_error(NULL, ret, "timer", &failed);
		}

		// Purge and remove orphan members of non-existing/non-catalog zones.
		if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_CATALOG)) {
			ret = catalog_orphans_sweep(args->server);
			log_if_orphans_error(NULL, ret, "catalog", &failed);
		}

		if (failed) {
			send_error(args, knot_strerror(KNOT_CTL_EZONE));
		}
	} else {
		knot_dname_storage_t buff;
		while (true) {
			knot_dname_t *zone_name =
				knot_dname_from_str(buff, args->data[KNOT_CTL_IDX_ZONE],
				                    sizeof(buff));
			if (zone_name == NULL) {
				log_ctl_zone_str_error(args->data[KNOT_CTL_IDX_ZONE],
				                       "control, error (%s)",
				                       knot_strerror(KNOT_EINVAL));
				send_error(args, knot_strerror(KNOT_EINVAL));
				return KNOT_EINVAL;
			}
			knot_dname_to_lower(zone_name);

			if (!zone_exists(zone_name, args->server->zone_db)) {
				// Purge KASP DB.
				if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_KASPDB)) {
					if (knot_lmdb_open(&args->server->kaspdb) == KNOT_EOK) {
						ret = kasp_db_delete_all(&args->server->kaspdb, zone_name);
						log_if_orphans_error(zone_name, ret, "KASP", &failed);
					}
				}

				// Purge zone journal.
				if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_JOURNAL)) {
					zone_journal_t j = { &args->server->journaldb, zone_name };
					ret = journal_scrape_with_md(j, true);
					log_if_orphans_error(zone_name, ret, "journal", &failed);
				}

				// Purge zone timers.
				if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_TIMERS)) {
					ret = zone_timers_sweep(&args->server->timerdb,
					                        zone_names_distinct, zone_name);
					log_if_orphans_error(zone_name, ret, "timer", &failed);
				}

				// Purge Catalog.
				if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_CATALOG)) {
					ret = catalog_zone_purge(args->server, NULL, zone_name);
					log_if_orphans_error(zone_name, ret, "catalog", &failed);
				}

				if (failed) {
					send_error(args, knot_strerror(KNOT_ERROR));
					failed = false;
				}
			}

			// Get next zone name.
			ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
			if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
				break;
			}
			strtolower((char *)args->data[KNOT_CTL_IDX_ZONE]);

			// Log the other zones the same way as the first one from process.c.
			log_ctl_zone_str_info(args->data[KNOT_CTL_IDX_ZONE],
			                      "control, received command '%s'",
			                      args->data[KNOT_CTL_IDX_CMD]);
		}
	}

	return KNOT_EOK;
}

static int zone_purge(zone_t *zone, ctl_args_t *args)
{
	if (MATCH_OR_FILTER(args, CTL_FILTER_PURGE_EXPIRE)) {
		// Abort possible editing transaction.
		int ret = zone_txn_abort(zone, args);
		if (ret != KNOT_EOK && ret != KNOT_TXN_ENOTEXISTS) {
			log_zone_error(zone->name,
			               "failed to abort pending transaction (%s)",
			               knot_strerror(ret));
			return ret;
		}

		// Expire the zone.
		// No ret, KNOT_EOK is the only return value from event_expire().
		(void)zone_events_schedule_blocking(zone, ZONE_EVENT_EXPIRE, true);
	}

	const purge_flag_t params =
		MATCH_OR_FILTER(args, CTL_FILTER_PURGE_TIMERS)   * PURGE_ZONE_TIMERS |
		MATCH_OR_FILTER(args, CTL_FILTER_PURGE_ZONEFILE) * PURGE_ZONE_ZONEFILE |
		MATCH_OR_FILTER(args, CTL_FILTER_PURGE_JOURNAL)  * PURGE_ZONE_JOURNAL |
		MATCH_OR_FILTER(args, CTL_FILTER_PURGE_KASPDB)   * PURGE_ZONE_KASPDB |
		MATCH_OR_FILTER(args, CTL_FILTER_PURGE_CATALOG)  * PURGE_ZONE_CATALOG |
		PURGE_ZONE_NOSYNC; // Purge even zonefiles with disabled syncing.

	// Purge the requested zone data.
	return selective_zone_purge(conf(), zone, params);
}

int ctl_dump_ctr(stats_dump_params_t *params, stats_dump_ctx_t *ctx)
{
	ctl_args_t *args = ctx->ctx;

	if (ctx->item != NULL && strcasecmp(ctx->item, params->item) != 0) {
		return KNOT_EOK;
	}
	ctx->match = true;

	if (params->value == 0 &&
	    !ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_FORCE)) {
		return KNOT_EOK;
	}

	char value[32];
	int ret = snprintf(value, sizeof(value), "%"PRIu64, params->value);
	if (ret <= 0 || ret >= sizeof(value)) {
		return KNOT_ESPACE;
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_SECTION] = params->section,
		[KNOT_CTL_IDX_ITEM] = params->item,
		[KNOT_CTL_IDX_ID] = params->id,
		[KNOT_CTL_IDX_ZONE] = params->zone,
		[KNOT_CTL_IDX_DATA] = value,
	};

	knot_ctl_type_t type = (params->value_pos == 0) ?
	                       KNOT_CTL_TYPE_DATA : KNOT_CTL_TYPE_EXTRA;

	return knot_ctl_send(args->ctl, type, &data);
}

static int common_stats(ctl_args_t *args, zone_t *zone)
{
	stats_dump_ctx_t dump_ctx = {
		.server = args->server,
		.zone = zone,
		.section = args->data[KNOT_CTL_IDX_SECTION],
		.item = args->data[KNOT_CTL_IDX_ITEM],
		.ctx = args,
	};

#define STATS_CHECK(ret, send) { \
	if (ret != KNOT_EOK) { \
		if ((send)) { /* Prevents duplicit zone error logs. */ \
			send_error(args, knot_strerror(ret)); \
		} \
		return ret; \
	} \
}

	if (zone == NULL) {
		int ret = stats_server(ctl_dump_ctr, &dump_ctx);
		STATS_CHECK(ret, true);

		ret = stats_xdp(ctl_dump_ctr, &dump_ctx);
		STATS_CHECK(ret, true);

		dump_ctx.query_modules = conf()->query_modules;
		ret = stats_modules(ctl_dump_ctr, &dump_ctx);
		STATS_CHECK(ret, true);
	} else {
		int ret = stats_zone(ctl_dump_ctr, &dump_ctx);
		STATS_CHECK(ret, false);

		dump_ctx.query_modules = &zone->query_modules;
		ret = stats_modules(ctl_dump_ctr, &dump_ctx);
		STATS_CHECK(ret, false);
	}

	if (!dump_ctx.match) {
		STATS_CHECK(KNOT_EINVAL, zone == NULL);
	}
#undef STATS_CHECK

	return KNOT_EOK;
}

static int zone_stats(zone_t *zone, ctl_args_t *args)
{
	return common_stats(args, zone);
}

static int ctl_zone(ctl_args_t *args, ctl_cmd_t cmd)
{
	switch (cmd) {
	case CTL_ZONE_STATUS:
		return zones_apply(args, zone_status);
	case CTL_ZONE_RELOAD:
		return zones_apply(args, zone_reload);
	case CTL_ZONE_REFRESH:
		return zones_apply(args, zone_refresh);
	case CTL_ZONE_RETRANSFER:
		return zones_apply(args, zone_retransfer);
	case CTL_ZONE_NOTIFY:
		return zones_apply(args, zone_notify);
	case CTL_ZONE_FLUSH:
		return zones_apply(args, zone_flush);
	case CTL_ZONE_BACKUP:
		return zones_apply_backup(args, false);
	case CTL_ZONE_RESTORE:
		return zones_apply_backup(args, true);
	case CTL_ZONE_SIGN:
		return zones_apply(args, zone_sign);
	case CTL_ZONE_VALIDATE:
		return zones_apply(args, zone_validate);
	case CTL_ZONE_KEYS_LOAD:
		return zones_apply(args, zone_keys_load);
	case CTL_ZONE_KEY_ROLL:
		return zones_apply(args, zone_key_roll);
	case CTL_ZONE_KSK_SBM:
		return zones_apply(args, zone_ksk_sbm_confirm);
	case CTL_ZONE_FREEZE:
		return zones_apply(args, zone_freeze);
	case CTL_ZONE_THAW:
		return zones_apply(args, zone_thaw);
	case CTL_ZONE_XFR_FREEZE:
		return zones_apply(args, zone_xfr_freeze);
	case CTL_ZONE_XFR_THAW:
		return zones_apply(args, zone_xfr_thaw);
	case CTL_ZONE_READ:
		return zones_apply(args, zone_read);
	case CTL_ZONE_BEGIN:
		return zones_apply(args, zone_txn_begin);
	case CTL_ZONE_COMMIT:
		return zones_apply(args, zone_txn_commit);
	case CTL_ZONE_ABORT:
		return zones_apply(args, zone_txn_abort);
	case CTL_ZONE_DIFF:
		return zones_apply(args, zone_txn_diff);
	case CTL_ZONE_GET:
		return zones_apply(args, zone_txn_get);
	case CTL_ZONE_SET:
		return zones_apply(args, zone_txn_set);
	case CTL_ZONE_UNSET:
		return zones_apply(args, zone_txn_unset);
	case CTL_ZONE_PURGE:
		if (MATCH_AND_FILTER(args, CTL_FILTER_PURGE_ORPHAN)) {
			return orphans_purge(args);
		} else {
			return zones_apply(args, zone_purge);
		}
	case CTL_ZONE_STATS:
		return zones_apply(args, zone_stats);
	default:
		assert(0);
		return KNOT_EINVAL;
	}
}

static void check_zone_txn(zone_t *zone, const knot_dname_t **exists)
{
	if (zone->control_update != NULL) {
		*exists = zone->name;
	}
}

static int check_no_zone_txn(server_t *server, const char *action)
{
	const knot_dname_t *zone_txn_exists = NULL;
	knot_zonedb_foreach(server->zone_db, check_zone_txn, &zone_txn_exists);
	if (zone_txn_exists != NULL) {
		knot_dname_txt_storage_t zone_str;
		knot_dname_to_str(zone_str, zone_txn_exists, sizeof(zone_str));
		log_warning("%s rejected due to existing transaction for zone %s",
		            action, zone_str);
		return KNOT_TXN_EEXISTS;
	}
	return KNOT_EOK;
}

static int server_status(ctl_args_t *args)
{
	const char *type = args->data[KNOT_CTL_IDX_TYPE];

	if (type == NULL || strlen(type) == 0) {
		return KNOT_EOK;
	}

	char buff[4096] = "";

	int ret;
	if (strcasecmp(type, "version") == 0) {
		ret = snprintf(buff, sizeof(buff), "%s", PACKAGE_VERSION);
	} else if (strcasecmp(type, "workers") == 0) {
		int running_bkg_wrk, wrk_queue;
		worker_pool_status(args->server->workers, false, &running_bkg_wrk, &wrk_queue);
		ret = snprintf(buff, sizeof(buff), "UDP workers: %zu, TCP workers: %zu, "
		               "XDP workers: %zu, background workers: %zu (running: %d, pending: %d)",
		               conf()->cache.srv_udp_threads, conf()->cache.srv_tcp_threads,
		               conf()->cache.srv_xdp_threads, conf()->cache.srv_bg_threads,
		               running_bkg_wrk, wrk_queue);
	} else if (strcasecmp(type, "configure") == 0) {
		ret = snprintf(buff, sizeof(buff), "%s", configure_summary);
	} else if (strcasecmp(type, "cert-key") == 0) {
		uint8_t pin[128];
		size_t pin_len = server_cert_pin(args->server, pin, sizeof(pin));
		if (pin_len > 0) {
			ret = snprintf(buff, sizeof(buff), "%.*s", (int)pin_len, pin);
		} else {
			ret = snprintf(buff, sizeof(buff), STATUS_EMPTY);
		}
	} else {
		return KNOT_EINVAL;
	}
	if (ret <= 0 || ret >= sizeof(buff)) {
		return KNOT_ESPACE;
	}

	args->data[KNOT_CTL_IDX_DATA] = buff;

	return knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &args->data);
}

static int ctl_server(ctl_args_t *args, ctl_cmd_t cmd)
{
	int ret = KNOT_EOK;

	switch (cmd) {
	case CTL_STATUS:
		ret = server_status(args);
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
		}
		break;
	case CTL_STOP:
		ret = KNOT_CTL_ESTOP;
		break;
	case CTL_RELOAD:
		ret = check_no_zone_txn(args->server, "server reload");
		if (ret == KNOT_EOK) {
			ret = server_reload(args->server, RELOAD_FULL);
		}
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
		}
		break;
	default:
		assert(0);
		ret = KNOT_EINVAL;
	}

	return ret;
}

static int ctl_stats(ctl_args_t *args, _unused_ ctl_cmd_t cmd)
{
	return common_stats(args, NULL);
}

static int send_block_data(conf_io_t *io, knot_ctl_data_t *data)
{
	knot_ctl_t *ctl = (knot_ctl_t *)io->misc;

	const yp_item_t *item = (io->key1 != NULL) ? io->key1 : io->key0;
	assert(item != NULL);

	char buff[YP_MAX_TXT_DATA_LEN + 1] = "\0";

	(*data)[KNOT_CTL_IDX_DATA] = buff;

	// Format explicit binary data value.
	if (io->data.bin != NULL) {
		size_t buff_len = sizeof(buff);
		int ret = yp_item_to_txt(item, io->data.bin, io->data.bin_len, buff,
		                         &buff_len, YP_SNOQUOTE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		return knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, data);
	// Format all multivalued item data if no specified index.
	} else if ((item->flags & YP_FMULTI) && io->data.index == 0) {
		size_t values = conf_val_count(io->data.val);
		for (size_t i = 0; i < values; i++) {
			conf_val(io->data.val);
			size_t buff_len = sizeof(buff);
			int ret = yp_item_to_txt(item, io->data.val->data,
			                         io->data.val->len, buff,&buff_len,
			                         YP_SNOQUOTE);
			if (ret != KNOT_EOK) {
				return ret;
			}

			knot_ctl_type_t type = (i == 0) ? KNOT_CTL_TYPE_DATA :
			                                  KNOT_CTL_TYPE_EXTRA;
			ret = knot_ctl_send(ctl, type, data);
			if (ret != KNOT_EOK) {
				return ret;
			}

			conf_val_next(io->data.val);
		}
		return KNOT_EOK;
	// Format singlevalued item data or a specified one from multivalued.
	} else {
		conf_val(io->data.val);
		size_t buff_len = sizeof(buff);
		int ret = yp_item_to_txt(item, io->data.val->data, io->data.val->len,
		                         buff, &buff_len, YP_SNOQUOTE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		return knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, data);
	}
}

static int send_block(conf_io_t *io)
{
	knot_ctl_t *ctl = (knot_ctl_t *)io->misc;

	// Get possible error message.
	const char *err = io->error.str;
	if (err == NULL && io->error.code != KNOT_EOK) {
		err = knot_strerror(io->error.code);
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_ERROR] = err,
	};

	if (io->key0 != NULL) {
		data[KNOT_CTL_IDX_SECTION] = io->key0->name + 1;
	}
	if (io->key1 != NULL) {
		data[KNOT_CTL_IDX_ITEM] = io->key1->name + 1;
	}

	// Get the item prefix.
	switch (io->type) {
	case NEW: data[KNOT_CTL_IDX_FLAGS] = CTL_FLAG_DIFF_ADD; break;
	case OLD: data[KNOT_CTL_IDX_FLAGS] = CTL_FLAG_DIFF_REM; break;
	default: break;
	}

	knot_dname_txt_storage_t id;

	// Get the textual item id.
	if (io->id_len > 0 && io->key0 != NULL) {
		size_t id_len = sizeof(id);
		int ret = yp_item_to_txt(io->key0->var.g.id, io->id, io->id_len,
		                         id, &id_len, YP_SNOQUOTE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		if (io->id_as_data) {
			data[KNOT_CTL_IDX_DATA] = id;
		} else {
			data[KNOT_CTL_IDX_ID] = id;
		}
	}

	if (io->data.val == NULL && io->data.bin == NULL) {
		return knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &data);
	} else {
		return send_block_data(io, &data);
	}
}

static int ctl_conf_txn(ctl_args_t *args, ctl_cmd_t cmd)
{
	conf_io_t io = {
		.fcn = send_block,
		.misc = args->ctl
	};

	int ret = KNOT_EOK;

	switch (cmd) {
	case CTL_CONF_BEGIN:
		ret = check_no_zone_txn(args->server, "config, transaction");
		if (ret == KNOT_EOK) {
			ret = conf_io_begin(false);
		}
		break;
	case CTL_CONF_ABORT:
		conf_io_abort(false);
		ret = KNOT_EOK;
		break;
	case CTL_CONF_COMMIT:
		// First check the database.
		ret = conf_io_check(&io);
		if (ret != KNOT_EOK) {
			// A semantic error is already sent by the check function.
			if (io.error.code != KNOT_EOK) {
				return KNOT_EOK;
			}
			// No transaction abort!
			break;
		}

		ret = conf_io_commit(false);
		if (ret != KNOT_EOK) {
			conf_io_abort(false);
			break;
		}

		ret = server_reload(args->server, RELOAD_COMMIT);
		break;
	default:
		assert(0);
		ret = KNOT_EINVAL;
	}

	if (ret != KNOT_EOK) {
		send_error(args, knot_strerror(ret));
	}

	return ret;
}

static void list_zone(zone_t *zone, knot_ctl_t *ctl)
{
	knot_dname_txt_storage_t buff;
	knot_dname_to_str(buff, zone->name, sizeof(buff));

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_SECTION] = "zone",
		[KNOT_CTL_IDX_ID] = buff
	};

	(void)knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &data);
}

static int list_zones(knot_zonedb_t *zonedb, knot_ctl_t *ctl)
{
	assert(zonedb != NULL && ctl != NULL);

	knot_zonedb_foreach(zonedb, list_zone, ctl);

	return KNOT_EOK;
}

static int ctl_conf_list(ctl_args_t *args, ctl_cmd_t cmd)
{
	conf_io_t io = {
		.fcn = send_block,
		.misc = args->ctl
	};

	int ret = KNOT_EOK;

	while (true) {
		const char *key0  = args->data[KNOT_CTL_IDX_SECTION];
		const char *key1  = args->data[KNOT_CTL_IDX_ITEM];
		const char *id    = args->data[KNOT_CTL_IDX_ID];
		const char *flags = args->data[KNOT_CTL_IDX_FLAGS];

		bool schema = ctl_has_flag(flags, CTL_FLAG_LIST_SCHEMA);
		bool current = !ctl_has_flag(flags, CTL_FLAG_LIST_TXN);
		bool zones = ctl_has_flag(flags, CTL_FLAG_LIST_ZONES);

		if (zones) {
			ret = list_zones(args->server->zone_db, args->ctl);
		} else {
			ret = conf_io_list(key0, key1, id, schema, current, &io);
		}
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
			break;
		}

		// Get next data unit.
		ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
		if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
			break;
		}
	}

	return ret;
}

static int ctl_conf_read(ctl_args_t *args, ctl_cmd_t cmd)
{
	conf_io_t io = {
		.fcn = send_block,
		.misc = args->ctl
	};

	int ret = KNOT_EOK;

	while (true) {
		const char *key0 = args->data[KNOT_CTL_IDX_SECTION];
		const char *key1 = args->data[KNOT_CTL_IDX_ITEM];
		const char *id   = args->data[KNOT_CTL_IDX_ID];

		ctl_log_conf_data(&args->data);

		switch (cmd) {
		case CTL_CONF_READ:
			ret = conf_io_get(key0, key1, id, true, &io);
			break;
		case CTL_CONF_DIFF:
			ret = conf_io_diff(key0, key1, id, &io);
			break;
		case CTL_CONF_GET:
			ret = conf_io_get(key0, key1, id, false, &io);
			break;
		default:
			assert(0);
			ret = KNOT_EINVAL;
		}
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
			break;
		}

		// Get next data unit.
		ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
		if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
			break;
		}
	}

	return ret;
}

static int ctl_conf_modify(ctl_args_t *args, ctl_cmd_t cmd)
{
	// Start child transaction.
	int ret = conf_io_begin(true);
	if (ret != KNOT_EOK) {
		send_error(args, knot_strerror(ret));
		return ret;
	}

	while (true) {
		const char *key0 = args->data[KNOT_CTL_IDX_SECTION];
		const char *key1 = args->data[KNOT_CTL_IDX_ITEM];
		const char *id   = args->data[KNOT_CTL_IDX_ID];
		const char *data = args->data[KNOT_CTL_IDX_DATA];

		ctl_log_conf_data(&args->data);

		switch (cmd) {
		case CTL_CONF_SET:
			ret = conf_io_set(key0, key1, id, data);
			break;
		case CTL_CONF_UNSET:
			ret = conf_io_unset(key0, key1, id, data);
			break;
		default:
			assert(0);
			ret = KNOT_EINVAL;
		}
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
			break;
		}

		// Get next data unit.
		ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
		if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
			break;
		}
	}

	// Finish child transaction.
	if (ret == KNOT_EOK) {
		ret = conf_io_commit(true);
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
		}
	} else {
		conf_io_abort(true);
	}

	return ret;
}

typedef enum {
	CTL_LOCK_NONE   = 0x00,
	CTL_LOCK_SRV_R  = 0x01, // Can run in parallel with other R commands.
	CTL_LOCK_SRV_W  = 0x02, // Cannot run in parallel with other commands.
} ctl_lock_flag_t;

typedef struct {
	const char *name;
	int (*fcn)(ctl_args_t *, ctl_cmd_t);
	ctl_lock_flag_t locks;
} desc_t;

static const desc_t cmd_table[] = {
	[CTL_NONE]            = { "" },

	[CTL_STATUS]          = { "status",             ctl_server,       CTL_LOCK_SRV_R },
	[CTL_STOP]            = { "stop",               ctl_server,       CTL_LOCK_SRV_R },
	[CTL_RELOAD]          = { "reload",             ctl_server,       CTL_LOCK_SRV_W },
	[CTL_STATS]           = { "stats",              ctl_stats,        CTL_LOCK_SRV_R },

	[CTL_ZONE_STATUS]     = { "zone-status",        ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_RELOAD]     = { "zone-reload",        ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_REFRESH]    = { "zone-refresh",       ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_RETRANSFER] = { "zone-retransfer",    ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_NOTIFY]     = { "zone-notify",        ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_FLUSH]      = { "zone-flush",         ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_BACKUP]     = { "zone-backup",        ctl_zone,         CTL_LOCK_SRV_W }, // Backup and restore must be exclusive as the global backup ctx is accessed.
	[CTL_ZONE_RESTORE]    = { "zone-restore",       ctl_zone,         CTL_LOCK_SRV_W },
	[CTL_ZONE_SIGN]       = { "zone-sign",          ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_VALIDATE]   = { "zone-validate",      ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_KEYS_LOAD]  = { "zone-keys-load",     ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_KEY_ROLL]   = { "zone-key-rollover",  ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_KSK_SBM]    = { "zone-ksk-submitted", ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_FREEZE]     = { "zone-freeze",        ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_THAW]       = { "zone-thaw",          ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_XFR_FREEZE] = { "zone-xfr-freeze",    ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_XFR_THAW]   = { "zone-xfr-thaw",      ctl_zone,         CTL_LOCK_SRV_R },

	[CTL_ZONE_READ]       = { "zone-read",          ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_BEGIN]      = { "zone-begin",         ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_COMMIT]     = { "zone-commit",        ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_ABORT]      = { "zone-abort",         ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_DIFF]       = { "zone-diff",          ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_GET]        = { "zone-get",           ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_SET]        = { "zone-set",           ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_UNSET]      = { "zone-unset",         ctl_zone,         CTL_LOCK_SRV_R },
	[CTL_ZONE_PURGE]      = { "zone-purge",         ctl_zone,         CTL_LOCK_SRV_W },
	[CTL_ZONE_STATS]      = { "zone-stats",	        ctl_zone,         CTL_LOCK_SRV_R },

	[CTL_CONF_LIST]       = { "conf-list",          ctl_conf_list,    CTL_LOCK_SRV_R }, // Can either read live conf or conf txn. The latter would deserve CTL_LOCK_SRV_W, but when conf txn exists, all cmds are done by single thread anyway.
	[CTL_CONF_READ]       = { "conf-read",          ctl_conf_read,    CTL_LOCK_SRV_R },
	[CTL_CONF_BEGIN]      = { "conf-begin",         ctl_conf_txn,     CTL_LOCK_SRV_W }, // It's locked only during conf-begin, not for the whole duration of the transaction.
	[CTL_CONF_COMMIT]     = { "conf-commit",        ctl_conf_txn,     CTL_LOCK_SRV_W },
	[CTL_CONF_ABORT]      = { "conf-abort",         ctl_conf_txn,     CTL_LOCK_SRV_W },
	[CTL_CONF_DIFF]       = { "conf-diff",          ctl_conf_read,    CTL_LOCK_SRV_W },
	[CTL_CONF_GET]        = { "conf-get",           ctl_conf_read,    CTL_LOCK_SRV_W },
	[CTL_CONF_SET]        = { "conf-set",           ctl_conf_modify,  CTL_LOCK_SRV_W },
	[CTL_CONF_UNSET]      = { "conf-unset",         ctl_conf_modify,  CTL_LOCK_SRV_W },
};

#define MAX_CTL_CODE (sizeof(cmd_table) / sizeof(desc_t) - 1)

const char *ctl_cmd_to_str(ctl_cmd_t cmd)
{
	if (cmd <= CTL_NONE || cmd > MAX_CTL_CODE) {
		return NULL;
	}

	return cmd_table[cmd].name;
}

ctl_cmd_t ctl_str_to_cmd(const char *cmd_str)
{
	if (cmd_str == NULL) {
		return CTL_NONE;
	}

	for (ctl_cmd_t cmd = CTL_NONE + 1; cmd <= MAX_CTL_CODE; cmd++) {
		if (strcmp(cmd_str, cmd_table[cmd].name) == 0) {
			return cmd;
		}
	}

	return CTL_NONE;
}

static int ctl_lock(server_t *server, ctl_lock_flag_t flags, uint64_t timeout_ms)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (ret != 0) {
		return KNOT_ERROR;
	}
	ts.tv_sec += timeout_ms / 1000;
	ts.tv_nsec += (timeout_ms % 1000) * 1000000LU;

	if ((flags & CTL_LOCK_SRV_W)) {
		assert(!(flags & CTL_LOCK_SRV_R));
#if !defined(__APPLE__)
		ret = pthread_rwlock_timedwrlock(&server->ctl_lock, &ts);
#else
		ret = pthread_rwlock_wrlock(&server->ctl_lock);
#endif
	}
	if ((flags & CTL_LOCK_SRV_R)) {
#if !defined(__APPLE__)
		ret = pthread_rwlock_timedrdlock(&server->ctl_lock, &ts);
#else
		ret = pthread_rwlock_rdlock(&server->ctl_lock);
#endif
	}
	return (ret != 0 ? KNOT_EBUSY : KNOT_EOK);
}

static void ctl_unlock(server_t *server)
{
	pthread_rwlock_unlock(&server->ctl_lock);
}

int ctl_exec(ctl_cmd_t cmd, ctl_args_t *args)
{
	if (args == NULL) {
		return KNOT_EINVAL;
	}

	int ret = ctl_lock(args->server, cmd_table[cmd].locks, conf()->cache.ctl_timeout);
	if (ret == KNOT_EOK) {
		ret = cmd_table[cmd].fcn(args, cmd);
		ctl_unlock(args->server);
	}

	return ret;
}

bool ctl_has_flag(const char *flags, const char *flag)
{
	if (flags == NULL || flag == NULL) {
		return false;
	}

	return strstr(flags, flag) != NULL;
}
