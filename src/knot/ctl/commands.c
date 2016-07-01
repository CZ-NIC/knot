/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/conf/confio.h"
#include "knot/ctl/commands.h"
#include "libknot/libknot.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/macros.h"
#include "contrib/string.h"

void ctl_log_data(knot_ctl_data_t *data)
{
	if (data == NULL) {
		return;
	}

	const char *zone = (*data)[KNOT_CTL_IDX_ZONE];
	const char *section = (*data)[KNOT_CTL_IDX_SECTION];
	const char *item = (*data)[KNOT_CTL_IDX_ITEM];
	const char *id = (*data)[KNOT_CTL_IDX_ID];

	if (zone != NULL) {
		log_debug("control, zone '%s'", zone);
	} else if (section != NULL) {
		log_debug("control, item '%s%s%s%s%s%s'", section,
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
		log_debug("control, failed to send error (%s)", knot_strerror(ret));
	}
}

static int get_zone(ctl_args_t *args, zone_t **zone)
{
	const char *name = args->data[KNOT_CTL_IDX_ZONE];
	assert(name != NULL);

	uint8_t buff[KNOT_DNAME_MAXLEN];

	knot_dname_t *dname = knot_dname_from_str(buff, name, sizeof(buff));
	if (dname == NULL) {
		return KNOT_EINVAL;
	}

	int ret = knot_dname_to_lower(dname);
	if (ret != KNOT_EOK) {
		return ret;
	}

	*zone = knot_zonedb_find(args->server->zone_db, dname);
	if (*zone == NULL) {
		return KNOT_ENOZONE;
	}

	return KNOT_EOK;
}

static int zones_apply(ctl_args_t *args, int (*fcn)(zone_t *, ctl_args_t *))
{
	// Process all configured zones if none is specified.
	if (args->data[KNOT_CTL_IDX_ZONE] == NULL) {
		rcu_read_lock();
		knot_zonedb_foreach(args->server->zone_db, fcn, args);
		rcu_read_unlock();
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;

	rcu_read_lock();

	while (true) {
		zone_t *zone;
		int ret = get_zone(args, &zone);
		if (ret == KNOT_EOK) {
			ret = fcn(zone, args);
		}
		if (ret != KNOT_EOK) {
			log_zone_str_debug(args->data[KNOT_CTL_IDX_ZONE],
			                   "control, (%s)", knot_strerror(ret));
			send_error(args, knot_strerror(ret));
		}

		// Get next zone name.
		ret = knot_ctl_receive(args->ctl, &args->type, &args->data);
		if (ret != KNOT_EOK || args->type != KNOT_CTL_TYPE_DATA) {
			break;
		}
		ctl_log_data(&args->data);
	}

	rcu_read_unlock();

	return ret;
}

static int zone_status(zone_t *zone, ctl_args_t *args)
{
	// Zone name.
	char name[KNOT_DNAME_TXT_MAXLEN + 1];
	if (knot_dname_to_str(name, zone->name, sizeof(name)) == NULL) {
		return KNOT_EINVAL;
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_ZONE] = name
	};

	// Zone type.
	data[KNOT_CTL_IDX_TYPE] = "type";

	if (zone_is_slave(conf(), zone)) {
		data[KNOT_CTL_IDX_DATA] = "slave";
	} else {
		data[KNOT_CTL_IDX_DATA] = "master";
	}

	int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Zone serial.
	data[KNOT_CTL_IDX_TYPE] = "serial";

	char buff[128];
	if (zone->contents != NULL) {
		knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
		                                     KNOT_RRTYPE_SOA);
		ret = snprintf(buff, sizeof(buff), "%u", knot_soa_serial(soa));
	} else {
		ret = snprintf(buff, sizeof(buff), "none");
	}
	if (ret < 0 || ret >= sizeof(buff)) {
		return KNOT_ESPACE;
	}

	data[KNOT_CTL_IDX_DATA] = buff;

	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_EXTRA, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Next event.
	data[KNOT_CTL_IDX_TYPE] = "next-event";

	zone_event_type_t next_type = ZONE_EVENT_INVALID;
	time_t next_time = zone_events_get_next(zone, &next_type);
	if (next_type != ZONE_EVENT_INVALID) {
		const char *next_name = zone_events_get_name(next_type);

		next_time = next_time - time(NULL);
		if (next_time < 0) {
			ret = snprintf(buff, sizeof(buff), "%s pending",
			               next_name);
		} else {
			ret = snprintf(buff, sizeof(buff), "%s in %lldh%lldm%llds",
			               next_name,
			               (long long)(next_time / 3600),
			               (long long)(next_time % 3600) / 60,
			               (long long)(next_time % 60));
		}
		if (ret < 0 || ret >= sizeof(buff)) {
			return KNOT_ESPACE;
		}

		data[KNOT_CTL_IDX_DATA] = buff;
	} else {
		data[KNOT_CTL_IDX_DATA] = "idle";
	}

	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_EXTRA, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// DNSSEC re-signing time.
	data[KNOT_CTL_IDX_TYPE] = "auto-dnssec";

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		struct tm time_gm = { 0 };
		time_t refresh_at = zone_events_get_time(zone, ZONE_EVENT_DNSSEC);
		gmtime_r(&refresh_at, &time_gm);

		size_t written = strftime(buff, sizeof(buff), KNOT_LOG_TIME_FORMAT,
		                          &time_gm);
		if (written == 0) {
			return KNOT_ESPACE;
		}

		data[KNOT_CTL_IDX_DATA] = buff;
	} else {
		data[KNOT_CTL_IDX_DATA] = "disabled";
	}

	return knot_ctl_send(args->ctl, KNOT_CTL_TYPE_EXTRA, &data);
}

static int zone_reload(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (zone->flags & ZONE_EXPIRED) {
		return KNOT_ENOTSUP;
	}

	zone_events_schedule(zone, ZONE_EVENT_LOAD, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_refresh(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (!zone_is_slave(conf(), zone)) {
		return KNOT_ENOTSUP;
	}

	zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_retransfer(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (!zone_is_slave(conf(), zone)) {
		return KNOT_ENOTSUP;
	}

	zone->flags |= ZONE_FORCE_AXFR;
	zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_flush(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	if (ctl_has_flag(args->data[KNOT_CTL_IDX_FLAGS], CTL_FLAG_FORCE)) {
		zone->flags |= ZONE_FORCE_FLUSH;
	}

	zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_sign(zone_t *zone, ctl_args_t *args)
{
	UNUSED(args);

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (!conf_bool(&val)) {
		return KNOT_ENOTSUP;
	}

	zone->flags |= ZONE_FORCE_RESIGN;
	zone_events_schedule(zone, ZONE_EVENT_DNSSEC, ZONE_EVENT_NOW);

	return KNOT_EOK;
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
	case CTL_ZONE_FLUSH:
		return zones_apply(args, zone_flush);
	case CTL_ZONE_SIGN:
		return zones_apply(args, zone_sign);
	default:
		assert(0);
		return KNOT_EINVAL;
	}
}

static int ctl_server(ctl_args_t *args, ctl_cmd_t cmd)
{
	int ret = KNOT_EOK;

	switch (cmd) {
	case CTL_STATUS:
		ret = KNOT_EOK;
		break;
	case CTL_STOP:
		ret = KNOT_CTL_ESTOP;
		break;
	case CTL_RELOAD:
		ret = server_reload(args->server, conf()->filename, true);
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

	char id[KNOT_DNAME_TXT_MAXLEN + 1] = "\0";

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
	}

	const yp_item_t *item = (io->key1 != NULL) ? io->key1 : io->key0;
	assert(item != NULL);

	char buff[YP_MAX_TXT_DATA_LEN + 1] = "\0";

	data[KNOT_CTL_IDX_DATA] = buff;

	// Format explicit binary data value.
	if (io->data.bin != NULL) {
		size_t buff_len = sizeof(buff);
		int ret = yp_item_to_txt(item, io->data.bin, io->data.bin_len, buff,
		                         &buff_len, YP_SNOQUOTE);
		if (ret != KNOT_EOK) {
			return ret;
		}
		return knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &data);
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
			ret = knot_ctl_send(ctl, type, &data);
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
		return knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &data);
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
			// No transaction abort!
			break;
		}

		ret = conf_io_commit(false);
		if (ret != KNOT_EOK) {
			conf_io_abort(false);
			break;
		}

		ret = server_reload(args->server, NULL, false);
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

		switch (cmd) {
		case CTL_CONF_LIST:
			ret = conf_io_list(key0, &io);
			break;
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
		ctl_log_data(&args->data);
	}

	return ret;
}

static int ctl_conf_modify(ctl_args_t *args, ctl_cmd_t cmd)
{
	conf_io_t io = {
		.fcn = send_block,
		.misc = args->ctl
	};

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

		switch (cmd) {
		case CTL_CONF_SET:
			ret = conf_io_set(key0, key1, id, data, &io);
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
		ctl_log_data(&args->data);
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

	[CTL_ZONE_STATUS]     = { "zone-status",     ctl_zone },
	[CTL_ZONE_RELOAD]     = { "zone-reload",     ctl_zone },
	[CTL_ZONE_REFRESH]    = { "zone-refresh",    ctl_zone },
	[CTL_ZONE_RETRANSFER] = { "zone-retransfer", ctl_zone },
	[CTL_ZONE_FLUSH]      = { "zone-flush",      ctl_zone },
	[CTL_ZONE_SIGN]       = { "zone-sign",       ctl_zone },

	[CTL_CONF_LIST]       = { "conf-list",       ctl_conf_read },
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
