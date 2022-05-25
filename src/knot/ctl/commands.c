/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/common/stats.h"
#include "knot/conf/confio.h"
#include "knot/ctl/commands.h"
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
} ctl_globals;

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

static int schedule_trigger(zone_t *zone, ctl_args_t *args, zone_event_type_t event,
                            bool user)
{
	int ret = KNOT_EOK;

	if (ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_BLOCKING)) {
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

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_ZONE] = name
	};

	int ret;
	char buff[128];
	knot_ctl_type_t type = KNOT_CTL_TYPE_DATA;

	if (MATCH_OR_FILTER(args, CTL_FILTER_STATUS_ROLE)) {
		data[KNOT_CTL_IDX_TYPE] = "role";

		if (zone_is_slave(conf(), zone)) {
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

		if (zone->contents != NULL) {
			knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
			                                     KNOT_RRTYPE_SOA);
			ret = snprintf(buff, sizeof(buff), "%u", knot_soa_serial(soa->rdata));
		} else {
			ret = snprintf(buff, sizeof(buff), "none");
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

	if (MATCH_OR_FILTER(args, CTL_FILTER_STATUS_TRANSACTION)) {
		data[KNOT_CTL_IDX_TYPE] = "transaction";
		data[KNOT_CTL_IDX_DATA] = (zone->control_update != NULL) ? "open" : "none";
		ret = knot_ctl_send(args->ctl, type, &data);
		if (ret != KNOT_EOK) {
			return ret;
		} else {
			type = KNOT_CTL_TYPE_EXTRA;
		}
	}

	bool ufrozen = zone->events.ufrozen;
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
				data[KNOT_CTL_IDX_DATA] = "no";
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

		data[KNOT_CTL_IDX_TYPE] = "XFR freeze";
		if (zone_get_flag(zone, ZONE_XFR_FROZEN, false)) {
			data[KNOT_CTL_IDX_DATA] = "yes";
		} else {
			data[KNOT_CTL_IDX_DATA] = "no";
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

		if (zone->flags & ZONE_IS_CAT_MEMBER) {
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
				data[KNOT_CTL_IDX_DATA] = "none";
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
				ret = snprintf(buff, sizeof(buff), "not scheduled");
			} else if (ev_time <= time(NULL)) {
				bool frozen = ufrozen && ufreeze_applies(i);
				ret = snprintf(buff, sizeof(buff), frozen ? "frozen" : "pending");
			} else {
				ret = knot_time_print(TIME_PRINT_HUMAN_MIXED,
				                      ev_time, buff, sizeof(buff));
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

	return schedule_trigger(zone, args, ZONE_EVENT_REFRESH, true);
}

static int zone_retransfer(zone_t *zone, _unused_ ctl_args_t *args)
{
	if (!zone_is_slave(conf(), zone)) {
		args->suppress = true;
		return KNOT_ENOTSUP;
	}

	zone_set_flag(zone, ZONE_FORCE_AXFR);
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

	if (ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_FORCE)) {
		zone_set_flag(zone, ZONE_FORCE_FLUSH);
	}

	return schedule_trigger(zone, args, ZONE_EVENT_FLUSH, true);
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
	bool filter_zonefile, filter_journal, filter_timers, filter_kaspdb, filter_catalog;

	// The default filter values are set just in this paragraph.
	if (!(eval_opposite_filters(args, &filter_zonefile, true,
	                            CTL_FILTER_BACKUP_ZONEFILE, CTL_FILTER_BACKUP_NOZONEFILE) &&
	    eval_opposite_filters(args, &filter_journal, false,
	                          CTL_FILTER_BACKUP_JOURNAL, CTL_FILTER_BACKUP_NOJOURNAL) &&
	    eval_opposite_filters(args, &filter_timers, true,
	                          CTL_FILTER_BACKUP_TIMERS, CTL_FILTER_BACKUP_NOTIMERS) &&
	    eval_opposite_filters(args, &filter_kaspdb, true,
	                          CTL_FILTER_BACKUP_KASPDB, CTL_FILTER_BACKUP_NOKASPDB) &&
	    eval_opposite_filters(args, &filter_catalog, true,
	                          CTL_FILTER_BACKUP_CATALOG, CTL_FILTER_BACKUP_NOCATALOG))) {
		return KNOT_EXPARAM;
	}

	bool forced = ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_FORCE);

	zone_backup_ctx_t *ctx;

	// The present timer db size is not up-to-date, use the maximum one.
	conf_val_t timer_db_size = conf_db_param(conf(), C_TIMER_DB_MAX_SIZE);

	int ret = zone_backup_init(restore_mode, forced,
	                           args->data[KNOT_CTL_IDX_DATA],
	                           knot_lmdb_copy_size(&args->server->kaspdb),
	                           conf_int(&timer_db_size),
	                           knot_lmdb_copy_size(&args->server->journaldb),
	                           knot_lmdb_copy_size(&args->server->catalog.db),
	                           &ctx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(ctx != NULL);
	ctx->backup_zonefile = filter_zonefile;
	ctx->backup_journal = filter_journal;
	ctx->backup_timers = filter_timers;
	ctx->backup_kaspdb = filter_kaspdb;
	ctx->backup_catalog = filter_catalog;

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

static int zone_backup_cmd(zone_t *zone, ctl_args_t *args)
{
	zone_backup_ctx_t *ctx = latest_backup_ctx(args);
	if (!ctx->restore_mode && ctx->failed) {
		// No need to proceed with already faulty backup.
		return KNOT_EOK;
	}

	if (zone->backup_ctx != NULL) {
		log_zone_warning(zone->name, "backup or restore already in progress, skipping zone");
		ctx->failed = true;
		return KNOT_EPROGRESS;
	}

	zone->backup_ctx = ctx;
	pthread_mutex_lock(&ctx->readers_mutex);
	ctx->readers++;
	pthread_mutex_unlock(&ctx->readers_mutex);
	ctx->zone_count++;

	int ret = schedule_trigger(zone, args, ZONE_EVENT_BACKUP, true);

	if (ret == KNOT_EOK && !ctx->backup_global && (ctx->restore_mode || !ctx->failed)) {
		ret = global_backup(ctx, zone_catalog(zone), zone->name);
	}

	return ret;
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

	/* Global catalog zones backup. */
	if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
		zone_backup_ctx_t *ctx = latest_backup_ctx(args);
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

static int zone_keys_load(zone_t *zone, _unused_ ctl_args_t *args)
{
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (!conf_bool(&val)) {
		args->suppress = true;
		return KNOT_ENOTSUP;
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
		// NOT zone_events_schedule_user(), intentionally!
		ret = schedule_trigger(zone, args, ZONE_EVENT_DNSSEC, false);
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

static int zone_txn_begin(zone_t *zone, _unused_ ctl_args_t *args)
{
	if (zone->control_update != NULL) {
		return KNOT_TXN_EEXISTS;
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

static int zone_txn_commit(zone_t *zone, _unused_ ctl_args_t *args)
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

static int zone_txn_abort(zone_t *zone, _unused_ ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		args->suppress = true;
		return KNOT_TXN_ENOTEXISTS;
	}

	zone_control_clear(zone);

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
	send_ctx_t *ctx = &ctl_globals.send_ctx;
	int ret = init_send_ctx(ctx, zone->name, args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (args->data[KNOT_CTL_IDX_OWNER] != NULL) {
		knot_dname_storage_t owner;

		ret = get_owner(owner, sizeof(owner), zone->name, args);
		if (ret != KNOT_EOK) {
			return ret;
		}

		const zone_node_t *node = zone_contents_node_or_nsec3(zone->contents, owner);
		if (node == NULL) {
			return KNOT_ENONODE;
		}

		ret = send_node((zone_node_t *)node, ctx);
	} else if (zone->contents != NULL) {
		ret = zone_contents_apply(zone->contents, send_node, ctx);
		if (ret == KNOT_EOK) {
			ret = zone_contents_nsec3_apply(zone->contents, send_node, ctx);
		}
	}

	return ret;
}

static int zone_flag_txn_get(zone_t *zone, ctl_args_t *args, const char *flag)
{
	if (zone->control_update == NULL) {
		args->suppress = true;
		return KNOT_TXN_ENOTEXISTS;
	}

	send_ctx_t *ctx = &ctl_globals.send_ctx;
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
	return zone_flag_txn_get(zone, args, NULL);
}

static int send_changeset_part(changeset_t *ch, send_ctx_t *ctx, bool from)
{
	ctx->data[KNOT_CTL_IDX_FLAGS] = from ? CTL_FLAG_REM : CTL_FLAG_ADD;

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

static int zone_txn_diff(zone_t *zone, ctl_args_t *args)
{
	if (zone->control_update == NULL) {
		args->suppress = true;
		return KNOT_TXN_ENOTEXISTS;
	}

	// FULL update has no changeset to print, do a 'get' instead.
	if (zone->control_update->flags & UPDATE_FULL) {
		return zone_flag_txn_get(zone, args, CTL_FLAG_ADD);
	}

	send_ctx_t *ctx = &ctl_globals.send_ctx;
	int ret = init_send_ctx(ctx, zone->name, args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return send_changeset(&zone->control_update->change, ctx);
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
		return KNOT_EINVAL;
	}

	uint16_t type;
	if (knot_rrtype_from_string(args->data[KNOT_CTL_IDX_TYPE], &type) != 0) {
		return KNOT_EINVAL;
	}

	*ttl = node_rrset(node, type).ttl;

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
	const size_t buff_len = sizeof(ctl_globals.txt_rr);
	char *buff = ctl_globals.txt_rr;

	uint32_t default_ttl = 0;
	if (ttl == NULL) {
		int ret = get_ttl(zone, args, &default_ttl);
		if (need_ttl && ret != KNOT_EOK) {
			return ret;
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
	zs_scanner_t *scanner = &ctl_globals.scanner;
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

static int zone_txn_set(zone_t *zone, ctl_args_t *args)
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

static int zone_txn_unset(zone_t *zone, ctl_args_t *args)
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

static void log_if_orphans_error(knot_dname_t *zone_name, int err, char *db_type)
{
	if (err == KNOT_EOK || err == KNOT_ENOENT || err == KNOT_EFILE) {
		return;
	}

	char *msg = sprintf_alloc("failed to purge orphan from %s database (%s)",
	                          db_type, knot_strerror(err));
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

	if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
		// Purge KASP DB.
		if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_KASPDB)) {
			ret = kasp_db_sweep(&args->server->kaspdb,
			                    zone_exists, args->server->zone_db);
			log_if_orphans_error(NULL, ret, "KASP");
		}

		// Purge zone journals of unconfigured zones.
		if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_JOURNAL)) {
			ret = journals_walk(&args->server->journaldb,
			                    drop_journal_if_orphan, args->server);
			log_if_orphans_error(NULL, ret, "journal");
		}

		// Purge timers of unconfigured zones.
		if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_TIMERS)) {
			ret = zone_timers_sweep(&args->server->timerdb,
			                        zone_exists, args->server->zone_db);
			log_if_orphans_error(NULL, ret, "timer");
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
						log_if_orphans_error(zone_name, ret, "KASP");
					}
				}

				// Purge zone journal.
				if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_JOURNAL)) {
					zone_journal_t j = { &args->server->journaldb, zone_name };
					ret = journal_scrape_with_md(j, true);
					log_if_orphans_error(zone_name, ret, "journal");
				}

				// Purge zone timers.
				if (only_orphan || MATCH_AND_FILTER(args, CTL_FILTER_PURGE_TIMERS)) {
					ret = zone_timers_sweep(&args->server->timerdb,
					                        zone_names_distinct, zone_name);
					log_if_orphans_error(zone_name, ret, "timer");
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

#define RETURN_IF_FAILED(str, exception) \
{ \
	if (ret != KNOT_EOK && ret != (exception)) { \
		log_zone_error(zone->name, \
		               "failed to %s (%s)", (str), knot_strerror(ret)); \
		return ret; \
	} \
}

static int zone_purge(zone_t *zone, ctl_args_t *args)
{
	int ret = KNOT_EOK;

	// Abort possible editing transaction.
	if (MATCH_OR_FILTER(args, CTL_FILTER_PURGE_EXPIRE)) {
		ret = zone_txn_abort(zone, args);
		RETURN_IF_FAILED("abort pending transaction", KNOT_TXN_ENOTEXISTS);
	}

	// Purge the zone timers.
	if (MATCH_OR_FILTER(args, CTL_FILTER_PURGE_TIMERS)) {
		memset(&zone->timers, 0, sizeof(zone->timers));
		ret = zone_timers_sweep(&args->server->timerdb,
		                        zone_names_distinct, zone->name);
		RETURN_IF_FAILED("purge timers", KNOT_ENOENT);
	}

	// Expire the zone.
	if (MATCH_OR_FILTER(args, CTL_FILTER_PURGE_EXPIRE)) {
		// KNOT_EOK is the only return value from event_expire().
		(void)schedule_trigger(zone, args, ZONE_EVENT_EXPIRE, true);
	}

	// Purge the zone file.
	if (MATCH_OR_FILTER(args, CTL_FILTER_PURGE_ZONEFILE)) {
		char *zonefile = conf_zonefile(conf(), zone->name);
		ret = (unlink(zonefile) == -1 ? knot_map_errno() : KNOT_EOK);
		free(zonefile);
		RETURN_IF_FAILED("purge zone file", KNOT_ENOENT);
	}

	// Purge the zone journal.
	if (MATCH_OR_FILTER(args, CTL_FILTER_PURGE_JOURNAL)) {
		ret = journal_scrape_with_md(zone_journal(zone), true);
		RETURN_IF_FAILED("purge journal", KNOT_ENOENT);
	}

	// Purge KASP DB.
	if (MATCH_OR_FILTER(args, CTL_FILTER_PURGE_KASPDB)) {
		ret = knot_lmdb_open(zone_kaspdb(zone));
		if (ret == KNOT_EOK) {
			ret = kasp_db_delete_all(zone_kaspdb(zone), zone->name);
		}
		RETURN_IF_FAILED("purge KASP DB", KNOT_ENOENT);
	}

	return KNOT_EOK;
}

static int send_stats_ctr(mod_ctr_t *ctr, uint64_t **stats_vals, unsigned threads,
                          ctl_args_t *args, knot_ctl_data_t *data)
{
	char index[128];
	char value[32];

	if (ctr->count == 1) {
		uint64_t counter = stats_get_counter(stats_vals, ctr->offset, threads);
		int ret = snprintf(value, sizeof(value), "%"PRIu64, counter);
		if (ret <= 0 || ret >= sizeof(value)) {
			return KNOT_ESPACE;
		}

		(*data)[KNOT_CTL_IDX_ID] = NULL;
		(*data)[KNOT_CTL_IDX_DATA] = value;

		ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, data);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		bool force = ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS],
		                          CTL_FLAG_FORCE);

		for (uint32_t i = 0; i < ctr->count; i++) {
			uint64_t counter = stats_get_counter(stats_vals, ctr->offset + i, threads);

			// Skip empty counters.
			if (counter == 0 && !force) {
				continue;
			}

			int ret;
			if (ctr->idx_to_str) {
				char *str = ctr->idx_to_str(i, ctr->count);
				if (str == NULL) {
					continue;
				}
				ret = snprintf(index, sizeof(index), "%s", str);
				free(str);
			} else {
				ret = snprintf(index, sizeof(index), "%u", i);
			}
			if (ret <= 0 || ret >= sizeof(index)) {
				return KNOT_ESPACE;
			}

			ret = snprintf(value, sizeof(value), "%"PRIu64, counter);
			if (ret <= 0 || ret >= sizeof(value)) {
				return KNOT_ESPACE;
			}

			(*data)[KNOT_CTL_IDX_ID] = index;
			(*data)[KNOT_CTL_IDX_DATA] = value;

			knot_ctl_type_t type = (i == 0) ? KNOT_CTL_TYPE_DATA :
			                                  KNOT_CTL_TYPE_EXTRA;
			ret = knot_ctl_send(args->ctl, type, data);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static int modules_stats(list_t *query_modules, ctl_args_t *args, knot_dname_t *zone)
{
	if (query_modules == NULL) {
		return KNOT_EOK;
	}

	const char *section = args->data[KNOT_CTL_IDX_SECTION];
	const char *item = args->data[KNOT_CTL_IDX_ITEM];

	knot_dname_txt_storage_t name = "";
	knot_ctl_data_t data = { 0 };

	bool section_found = (section == NULL) ? true : false;
	bool item_found = (item == NULL) ? true : false;

	knotd_mod_t *mod;
	WALK_LIST(mod, *query_modules) {
		// Skip modules without statistics.
		if (mod->stats_count == 0) {
			continue;
		}

		// Check for specific module.
		if (section != NULL) {
			if (section_found) {
				break;
			} else if (strcasecmp(mod->id->name + 1, section) == 0) {
				section_found = true;
			} else {
				continue;
			}
		}

		data[KNOT_CTL_IDX_SECTION] = mod->id->name + 1;

		unsigned threads = knotd_mod_threads(mod);

		for (int i = 0; i < mod->stats_count; i++) {
			mod_ctr_t *ctr = mod->stats_info + i;

			// Skip empty counter.
			if (ctr->name == NULL) {
				continue;
			}

			// Check for specific counter.
			if (item != NULL) {
				if (item_found) {
					break;
				} else if (strcasecmp(ctr->name, item) == 0) {
					item_found = true;
				} else {
					continue;
				}
			}

			// Prepare zone name if not already prepared.
			if (zone != NULL && name[0] == '\0') {
				if (knot_dname_to_str(name, zone, sizeof(name)) == NULL) {
					return KNOT_EINVAL;
				}
				data[KNOT_CTL_IDX_ZONE] = name;
			}

			data[KNOT_CTL_IDX_ITEM] = ctr->name;

			// Send the counters.
			int ret = send_stats_ctr(ctr, mod->stats_vals, threads, args, &data);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return (section_found && item_found) ? KNOT_EOK : KNOT_ENOENT;
}

static int zone_stats(zone_t *zone, ctl_args_t *args)
{
	return modules_stats(&zone->query_modules, args, zone->name);
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

static int server_status(ctl_args_t *args)
{
	const char *type = args->data[KNOT_CTL_IDX_TYPE];

	if (type == NULL || strlen(type) == 0) {
		return KNOT_EOK;
	}

	char buff[2048] = "";

	int ret;
	if (strcasecmp(type, "version") == 0) {
		ret = snprintf(buff, sizeof(buff), "Version: %s", PACKAGE_VERSION);
	} else if (strcasecmp(type, "workers") == 0) {
		int running_bkg_wrk, wrk_queue;
		worker_pool_status(args->server->workers, false, &running_bkg_wrk, &wrk_queue);
		ret = snprintf(buff, sizeof(buff), "UDP workers: %zu, TCP workers: %zu, "
		               "XDP workers: %zu, background workers: %zu (running: %d, pending: %d)",
		               conf()->cache.srv_udp_threads, conf()->cache.srv_tcp_threads,
		               conf()->cache.srv_xdp_threads, conf()->cache.srv_bg_threads,
		               running_bkg_wrk, wrk_queue);
	} else if (strcasecmp(type, "configure") == 0) {
		ret = snprintf(buff, sizeof(buff), "%s", CONFIGURE_SUMMARY);
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
		ret = server_reload(args->server);
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

static int ctl_stats(ctl_args_t *args, ctl_cmd_t cmd)
{
	const char *section = args->data[KNOT_CTL_IDX_SECTION];
	const char *item = args->data[KNOT_CTL_IDX_ITEM];

	bool found = (section == NULL) ? true : false;

	// Process server metrics.
	if (section == NULL || strcasecmp(section, "server") == 0) {
		char value[32];
		knot_ctl_data_t data = {
			[KNOT_CTL_IDX_SECTION] = "server",
			[KNOT_CTL_IDX_DATA] = value
		};

		for (const stats_item_t *i = server_stats; i->name != NULL; i++) {
			if (item != NULL) {
				if (found) {
					break;
				} else if (strcmp(i->name, item) == 0) {
					found = true;
				} else {
					continue;
				}
			} else {
				found = true;
			}

			data[KNOT_CTL_IDX_ITEM] = i->name;
			int ret = snprintf(value, sizeof(value), "%"PRIu64,
			                   i->val(args->server));
			if (ret <= 0 || ret >= sizeof(value)) {
				ret = KNOT_ESPACE;
				send_error(args, knot_strerror(ret));
				return ret;
			}

			ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
			if (ret != KNOT_EOK) {
				send_error(args, knot_strerror(ret));
				return ret;
			}
		}
	}

	// Process modules metrics.
	if (section == NULL || strncasecmp(section, "mod-", strlen("mod-")) == 0) {
		int ret = modules_stats(conf()->query_modules, args, NULL);
		if (ret != KNOT_EOK) {
			send_error(args, knot_strerror(ret));
			return ret;
		}

		found = true;
	}

	if (!found) {
		send_error(args, knot_strerror(KNOT_EINVAL));
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
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
	case NEW: data[KNOT_CTL_IDX_FLAGS] = CTL_FLAG_ADD; break;
	case OLD: data[KNOT_CTL_IDX_FLAGS] = CTL_FLAG_REM; break;
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
		ret = conf_io_begin(false);
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

		ret = server_reload(args->server);
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

typedef struct {
	const char *name;
	int (*fcn)(ctl_args_t *, ctl_cmd_t);
} desc_t;

static const desc_t cmd_table[] = {
	[CTL_NONE]            = { "" },

	[CTL_STATUS]          = { "status",          ctl_server },
	[CTL_STOP]            = { "stop",            ctl_server },
	[CTL_RELOAD]          = { "reload",          ctl_server },
	[CTL_STATS]           = { "stats",           ctl_stats },

	[CTL_ZONE_STATUS]     = { "zone-status",        ctl_zone },
	[CTL_ZONE_RELOAD]     = { "zone-reload",        ctl_zone },
	[CTL_ZONE_REFRESH]    = { "zone-refresh",       ctl_zone },
	[CTL_ZONE_RETRANSFER] = { "zone-retransfer",    ctl_zone },
	[CTL_ZONE_NOTIFY]     = { "zone-notify",        ctl_zone },
	[CTL_ZONE_FLUSH]      = { "zone-flush",         ctl_zone },
	[CTL_ZONE_BACKUP]     = { "zone-backup",        ctl_zone },
	[CTL_ZONE_RESTORE]    = { "zone-restore",       ctl_zone },
	[CTL_ZONE_SIGN]       = { "zone-sign",          ctl_zone },
	[CTL_ZONE_KEYS_LOAD]  = { "zone-keys-load",     ctl_zone },
	[CTL_ZONE_KEY_ROLL]   = { "zone-key-rollover",  ctl_zone },
	[CTL_ZONE_KSK_SBM]    = { "zone-ksk-submitted", ctl_zone },
	[CTL_ZONE_FREEZE]     = { "zone-freeze",        ctl_zone },
	[CTL_ZONE_THAW]       = { "zone-thaw",          ctl_zone },
	[CTL_ZONE_XFR_FREEZE] = { "zone-xfr-freeze",    ctl_zone },
	[CTL_ZONE_XFR_THAW]   = { "zone-xfr-thaw",      ctl_zone },

	[CTL_ZONE_READ]       = { "zone-read",       ctl_zone },
	[CTL_ZONE_BEGIN]      = { "zone-begin",      ctl_zone },
	[CTL_ZONE_COMMIT]     = { "zone-commit",     ctl_zone },
	[CTL_ZONE_ABORT]      = { "zone-abort",      ctl_zone },
	[CTL_ZONE_DIFF]       = { "zone-diff",       ctl_zone },
	[CTL_ZONE_GET]        = { "zone-get",        ctl_zone },
	[CTL_ZONE_SET]        = { "zone-set",        ctl_zone },
	[CTL_ZONE_UNSET]      = { "zone-unset",      ctl_zone },
	[CTL_ZONE_PURGE]      = { "zone-purge",      ctl_zone },
	[CTL_ZONE_STATS]      = { "zone-stats",	     ctl_zone },

	[CTL_CONF_LIST]       = { "conf-list",       ctl_conf_list },
	[CTL_CONF_READ]       = { "conf-read",       ctl_conf_read },
	[CTL_CONF_BEGIN]      = { "conf-begin",      ctl_conf_txn },
	[CTL_CONF_COMMIT]     = { "conf-commit",     ctl_conf_txn },
	[CTL_CONF_ABORT]      = { "conf-abort",      ctl_conf_txn },
	[CTL_CONF_DIFF]       = { "conf-diff",       ctl_conf_read },
	[CTL_CONF_GET]        = { "conf-get",        ctl_conf_read },
	[CTL_CONF_SET]        = { "conf-set",        ctl_conf_modify },
	[CTL_CONF_UNSET]      = { "conf-unset",      ctl_conf_modify },
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

int ctl_exec(ctl_cmd_t cmd, ctl_args_t *args)
{
	if (args == NULL) {
		return KNOT_EINVAL;
	}

	return cmd_table[cmd].fcn(args, cmd);
}

bool ctl_has_flag(const char *flags, const char *flag)
{
	if (flags == NULL || flag == NULL) {
		return false;
	}

	return strstr(flags, flag) != NULL;
}
