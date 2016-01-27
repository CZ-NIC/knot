/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/conf/confio.h"
#include "knot/ctl/commands.h"
#include "knot/ctl/remote.h"
#include "libknot/libknot.h"
#include "contrib/macros.h"
#include "contrib/string.h"

/*! \brief Callback prototype for per-zone operations. */
typedef int (remote_zonef_t)(zone_t *, remote_cmdargs_t *);

/*! \brief Append data to the output buffer. */
static int cmdargs_append(remote_cmdargs_t *args, const char *data, size_t size)
{
	assert(args);
	assert(size <= CMDARGS_ALLOC_BLOCK);

	if (args->response_size + size >= args->response_max) {
		size_t new_max = args->response_max + CMDARGS_ALLOC_BLOCK;
		char *new_response = realloc(args->response, new_max);
		if (!new_response) {
			return KNOT_ENOMEM;
		}

		args->response = new_response;
		args->response_max = new_max;
	}

	memcpy(args->response + args->response_size, data, size);
	args->response_size += size;
	args->response[args->response_size] = '\0';

	return KNOT_EOK;
}

static void zone_apply(server_t *s, remote_cmdargs_t *a, remote_zonef_t *cb,
                       const knot_dname_t *dname)
{
	int ret = KNOT_ENOZONE;

	zone_t *zone = knot_zonedb_find(s->zone_db, dname);
	if (zone != NULL) {
		ret = cb(zone, a);
	}

	if (ret != KNOT_EOK) {
		char name[KNOT_DNAME_TXT_MAXLEN] = "";
		knot_dname_to_str(name, dname, sizeof(name));

		char *msg = sprintf_alloc("%signoring [%s] %s",
		                          (a->response_size > 0) ? "\n" : "",
		                          name, knot_strerror(ret));
		cmdargs_append(a, msg, strlen(msg));
		free(msg);
	}
}

/*! \brief Apply callback to all zones specified by RDATA. */
static int zones_apply(server_t *s, remote_cmdargs_t *a, remote_zonef_t *cb)
{
	assert(s);
	assert(a);
	assert(cb);

	rcu_read_lock();

	/* Process all configured zones if none is specified. */
	if (a->argc == 0) {
		knot_zonedb_foreach(s->zone_db, cb, a);
	} else {
		/* Process all specified zones. */
		for (unsigned i = 0; i < a->argc; i++) {
			const knot_rrset_t *rr = &a->arg[i];
			if (rr->type != KNOT_RRTYPE_NS) {
				continue;
			}

			for (unsigned j = 0; j < rr->rrs.rr_count; j++) {
				zone_apply(s, a, cb, knot_ns_name(&rr->rrs, j));
			}
		}
	}

	rcu_read_unlock();

	return KNOT_EOK;
}

static char *dnssec_info(const zone_t *zone, char *buf, size_t buf_size)
{
	assert(zone);
	assert(buf);

	time_t refresh_at = zone_events_get_time(zone, ZONE_EVENT_DNSSEC);
	struct tm time_gm = { 0 };

	gmtime_r(&refresh_at, &time_gm);
	size_t written = strftime(buf, buf_size, KNOT_LOG_TIME_FORMAT, &time_gm);
	if (written == 0) {
		return NULL;
	}

	return buf;
}

static int zone_status(zone_t *zone, remote_cmdargs_t *a)
{
	/* Fetch latest serial. */
	uint32_t serial = 0;
	if (zone->contents) {
		const knot_rdataset_t *soa_rrs = node_rdataset(zone->contents->apex,
		                                               KNOT_RRTYPE_SOA);
		assert(soa_rrs != NULL);
		serial = knot_soa_serial(soa_rrs);
	}

	/* Fetch next zone event. */
	char when[128] = { '\0' };
	zone_event_type_t next_type = ZONE_EVENT_INVALID;
	const char *next_name = "";
	time_t next_time = zone_events_get_next(zone, &next_type);
	if (next_type != ZONE_EVENT_INVALID) {
		next_name = zone_events_get_name(next_type);
		next_time = next_time - time(NULL);
		if (next_time < 0) {
			memcpy(when, "pending", strlen("pending"));
		} else if (snprintf(when, sizeof(when),
		                    "in %lldh%lldm%llds",
		                    (long long)(next_time / 3600),
		                    (long long)(next_time % 3600) / 60,
		                    (long long)(next_time % 60)) < 0) {
			return KNOT_ESPACE;
		}
	} else {
		memcpy(when, "idle", strlen("idle"));
	}

	/* Prepare zone info. */
	char buf[512] = { '\0' };
	char dnssec_buf[128] = { '\0' };
	char *zone_name = knot_dname_to_str_alloc(zone->name);

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	bool dnssec_enable = conf_bool(&val);
	bool is_slave = zone_is_slave(conf(), zone);

	int n = snprintf(buf, sizeof(buf),
	                 "%s%s\ttype=%s | serial=%u | %s %s | %s %s",
	                 (a->response_size > 0) ? "\n" : "",
	                 zone_name,
	                 is_slave ? "slave" : "master",
	                 serial,
	                 next_name,
	                 when,
	                 dnssec_enable ? "automatic DNSSEC, resigning at:" : "DNSSEC signing disabled",
	                 dnssec_enable ? dnssec_info(zone, dnssec_buf, sizeof(dnssec_buf)) : "");
	free(zone_name);
	if (n < 0 || n >= sizeof(buf)) {
		return KNOT_ESPACE;
	}

	return cmdargs_append(a, buf, n);
}

static int zone_reload(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	if (zone->flags & ZONE_EXPIRED) {
		return KNOT_ENOTSUP;
	}

	zone_events_schedule(zone, ZONE_EVENT_LOAD, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_refresh(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	if (!zone_is_slave(conf(), zone)) {
		return KNOT_ENOTSUP;
	}

	zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_retransfer(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	if (!zone_is_slave(conf(), zone)) {
		return KNOT_ENOTSUP;
	}

	zone->flags |= ZONE_FORCE_AXFR;
	zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_flush(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	zone->flags |= ZONE_FORCE_FLUSH;
	zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int zone_sign(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (!conf_bool(&val)) {
		return KNOT_ENOTSUP;
	}

	zone->flags |= ZONE_FORCE_RESIGN;
	zone_events_schedule(zone, ZONE_EVENT_DNSSEC, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

static int ctl_status(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);

	const char *msg = "Running";
	cmdargs_append(a, msg, strlen(msg));

	return KNOT_EOK;
}

static int ctl_stop(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);
	UNUSED(a);

	return KNOT_CTL_ESTOP;
}

static int ctl_reload(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);
	UNUSED(a);

	return server_reload(s, conf()->filename);
}

static int ctl_zone_status(server_t *s, remote_cmdargs_t *a)
{
	return zones_apply(s, a, zone_status);
}

static int ctl_zone_reload(server_t *s, remote_cmdargs_t *a)
{
	return zones_apply(s, a, zone_reload);
}

static int ctl_zone_refresh(server_t *s, remote_cmdargs_t *a)
{
	return zones_apply(s, a, zone_refresh);
}

static int ctl_zone_retransfer(server_t *s, remote_cmdargs_t *a)
{
	return zones_apply(s, a, zone_retransfer);
}

static int ctl_zone_flush(server_t *s, remote_cmdargs_t *a)
{
	return zones_apply(s, a, zone_flush);
}

static int ctl_zone_sign(server_t *s, remote_cmdargs_t *a)
{
	return zones_apply(s, a, zone_sign);
}

static int format_item(conf_io_t *io)
{
	remote_cmdargs_t *a = (remote_cmdargs_t *)io->misc;

	// Get possible error message.
	const char *err = io->error.str;
	if (err == NULL && io->error.code != KNOT_EOK) {
		err = knot_strerror(io->error.code);
	}

	// Get the item key and data strings.
	char *key = conf_io_txt_key(io);
	if (key == NULL) {
		return KNOT_ERROR;
	}
	char *data = conf_io_txt_data(io);

	// Format the item.
	char *item = sprintf_alloc(
		"%s%s%s%s%s%s%s",
		(a->response_size > 0 ? "\n" : ""),
		(err != NULL ? "Error (" : ""),
		(err != NULL ? err : ""),
		(err != NULL ? "): " : ""),
		key,
		(data != NULL ? " = " : ""),
		(data != NULL ? data : ""));
	free(key);
	free(data);
	if (item == NULL) {
		return KNOT_ENOMEM;
	}

	// Append the item.
	int ret = cmdargs_append(a, item, strlen(item));
	free(item);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

static int ctl_conf_begin(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);
	UNUSED(a);

	return conf_io_begin(false);
}

static int ctl_conf_commit(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(a);

	conf_io_t io = {
		.fcn = format_item,
		.misc = a
	};

	// First check the database.
	int ret = conf_io_check(&io);
	if (ret != KNOT_EOK) {
		(void)conf_io_abort(false);
		return ret;
	}

	ret = conf_io_commit(false);
	if (ret != KNOT_EOK) {
		(void)conf_io_abort(false);
		return ret;
	}

	return server_reload(s, NULL);
}

static int ctl_conf_abort(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);
	UNUSED(a);

	return conf_io_abort(false);
}

static int parse_conf_key(char *key, char **key0, char **id, char **key1)
{
	// Check for the empty argument.
	if (key == NULL) {
		*key0 = NULL;
		*key1 = NULL;
		*id = NULL;
		return KNOT_EOK;
	}

	// Get key0.
	char *_key0 = key;

	// Check for id.
	char *_id = strchr(key, '[');
	if (_id != NULL) {
		// Separate key0 and id.
		*_id++ = '\0';

		// Check for id end.
		char *id_end = _id;
		while ((id_end = strchr(id_end, ']')) != NULL) {
			// Check for escaped character.
			if (*(id_end - 1) != '\\') {
				break;
			}
			id_end++;
		}

		// Check for unclosed id.
		if (id_end == NULL) {
			return KNOT_EINVAL;
		}

		// Separate id and key1.
		*id_end = '\0';

		key = id_end + 1;

		// Key1 or nothing must follow.
		if (*key != '.' && *key != '\0') {
			return KNOT_EINVAL;
		}
	}

	// Check for key1.
	char *_key1 = strchr(key, '.');
	if (_key1 != NULL) {
		// Separate key0/id and key1.
		*_key1++ = '\0';

		if (*_key1 == '\0') {
			return KNOT_EINVAL;
		}
	}

	*key0 = _key0;
	*key1 = _key1;
	*id = _id;

	return KNOT_EOK;
}

static int ctl_conf_list(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);

	if (a->argc > 1) {
		return KNOT_EINVAL;
	}

	char *key = (a->argc == 1) ?
	            (char *)remote_get_txt(&a->arg[0], 0, NULL) : NULL;

	// Split key path.
	char *key0, *key1, *id;
	int ret = parse_conf_key(key, &key0, &id, &key1);
	if (ret != KNOT_EOK) {
		free(key);
		return ret;
	}

	if (key1 != NULL || id != NULL) {
		free(key);
		return KNOT_EINVAL;
	}

	conf_io_t io = {
		.fcn = format_item,
		.misc = a
	};

	// Get items.
	ret = conf_io_list(key0, &io);

	free(key);

	return ret;
}

static int ctl_conf_diff(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);

	if (a->argc > 1) {
		return KNOT_EINVAL;
	}

	char *key = (a->argc == 1) ?
	            (char *)remote_get_txt(&a->arg[0], 0, NULL) : NULL;

	// Split key path.
	char *key0, *key1, *id;
	int ret = parse_conf_key(key, &key0, &id, &key1);
	if (ret != KNOT_EOK) {
		free(key);
		return ret;
	}

	conf_io_t io = {
		.fcn = format_item,
		.misc = a
	};

	// Get the difference.
	ret = conf_io_diff(key0, key1, id, &io);

	free(key);

	return ret;
}

static int conf_read(server_t *s, remote_cmdargs_t *a, bool get_current)
{
	UNUSED(s);

	if (a->argc > 1) {
		return KNOT_EINVAL;
	}

	char *key = (a->argc == 1) ?
	            (char *)remote_get_txt(&a->arg[0], 0, NULL) : NULL;

	// Split key path.
	char *key0, *key1, *id;
	int ret = parse_conf_key(key, &key0, &id, &key1);
	if (ret != KNOT_EOK) {
		free(key);
		return ret;
	}

	conf_io_t io = {
		.fcn = format_item,
		.misc = a
	};

	// Get item(s) value.
	ret = conf_io_get(key0, key1, id, get_current, &io);

	free(key);

	return ret;
}

static int ctl_conf_read(server_t *s, remote_cmdargs_t *a)
{
	return conf_read(s, a, true);
}

static int ctl_conf_get(server_t *s, remote_cmdargs_t *a)
{
	return conf_read(s, a, false);
}

static int ctl_conf_set(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);

	if (a->argc < 1 || a->argc > 255) {
		return KNOT_EINVAL;
	}

	char *key = (char *)remote_get_txt(&a->arg[0], 0, NULL);

	// Split key path.
	char *key0, *key1, *id;
	int ret = parse_conf_key(key, &key0, &id, &key1);
	if (ret != KNOT_EOK) {
		free(key);
		return ret;
	}

	conf_io_t io = {
		.fcn = format_item,
		.misc = a
	};

	// Start child transaction.
	ret = conf_io_begin(true);
	if (ret != KNOT_EOK) {
		free(key);
		return ret;
	}

	// Add item with no data.
	if (a->argc == 1) {
		ret = conf_io_set(key0, key1, id, NULL, &io);
	// Add item with specified data.
	} else {
		for (int i = 1; i < a->argc; i++) {
			char *data = (char *)remote_get_txt(&a->arg[i], 0, NULL);
			ret = conf_io_set(key0, key1, id, data, &io);
			free(data);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	free(key);

	// Finish child transaction.
	if (ret == KNOT_EOK) {
		return conf_io_commit(true);
	} else {
		(void)conf_io_abort(true);
		return ret;
	}
}

static int ctl_conf_unset(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);

	if (a->argc > 255) {
		return KNOT_EINVAL;
	}

	char *key = (a->argc >= 1) ?
	            (char *)remote_get_txt(&a->arg[0], 0, NULL) : NULL;

	// Split key path.
	char *key0, *key1, *id;
	int ret = parse_conf_key(key, &key0, &id, &key1);
	if (ret != KNOT_EOK) {
		free(key);
		return ret;
	}

	// Start child transaction.
	ret = conf_io_begin(true);
	if (ret != KNOT_EOK) {
		free(key);
		return ret;
	}

	// Delete item with no data.
	if (a->argc <= 1) {
		ret = conf_io_unset(key0, key1, id, NULL);
	// Delete specified data.
	} else {
		for (int i = 1; i < a->argc; i++) {
			char *data = (char *)remote_get_txt(&a->arg[i], 0, NULL);
			ret = conf_io_unset(key0, key1, id, data);
			free(data);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	free(key);

	// Finish child transaction.
	if (ret == KNOT_EOK) {
		return conf_io_commit(true);
	} else {
		(void)conf_io_abort(true);
		return ret;
	}
}

/*! \brief Table of remote commands. */
const remote_cmd_t remote_cmd_tbl[] = {
	{ KNOT_CTL_STATUS,          ctl_status },
	{ KNOT_CTL_STOP,            ctl_stop },
	{ KNOT_CTL_RELOAD,          ctl_reload },

	{ KNOT_CTL_ZONE_STATUS,     ctl_zone_status },
	{ KNOT_CTL_ZONE_RELOAD,     ctl_zone_reload },
	{ KNOT_CTL_ZONE_REFRESH,    ctl_zone_refresh },
	{ KNOT_CTL_ZONE_RETRANSFER, ctl_zone_retransfer },
	{ KNOT_CTL_ZONE_FLUSH,      ctl_zone_flush },
	{ KNOT_CTL_ZONE_SIGN,       ctl_zone_sign },

	{ KNOT_CTL_CONF_LIST,       ctl_conf_list },
	{ KNOT_CTL_CONF_READ,       ctl_conf_read },
	{ KNOT_CTL_CONF_BEGIN,      ctl_conf_begin },
	{ KNOT_CTL_CONF_COMMIT,     ctl_conf_commit },
	{ KNOT_CTL_CONF_ABORT,      ctl_conf_abort },
	{ KNOT_CTL_CONF_DIFF,       ctl_conf_diff },
	{ KNOT_CTL_CONF_GET,        ctl_conf_get },
	{ KNOT_CTL_CONF_SET,        ctl_conf_set },
	{ KNOT_CTL_CONF_UNSET,      ctl_conf_unset },
	{ NULL }
};
