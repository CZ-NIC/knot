/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/random.h"
#include "knot/common/fdset.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/conf/confdb.h"
#include "knot/conf/confio.h"
#include "knot/ctl/remote.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/server/tcp-handler.h"
#include "knot/zone/timers.h"
#include "libknot/libknot.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/macros.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/wire.h"

#define KNOT_CTL_REALM "knot."
#define KNOT_CTL_REALM_EXT ("." KNOT_CTL_REALM)
#define CMDARGS_ALLOC_BLOCK KNOT_WIRE_MAX_PKTSIZE
#define CMDARGS_BUFLEN_LOG 256

/*! \brief Remote command structure. */
typedef struct remote_cmdargs {
	const knot_rrset_t *arg;
	unsigned argc;
	knot_rcode_t rc;
	char *response;
	size_t response_size;
	size_t response_max;
} remote_cmdargs_t;

/*! \brief Initialize cmdargs_t structure. */
static int cmdargs_init(remote_cmdargs_t *args)
{
	assert(args);

	char *response = malloc(CMDARGS_ALLOC_BLOCK);
	if (!response) {
		return KNOT_ENOMEM;
	}

	memset(args, 0, sizeof(*args));
	args->response = response;
	args->response_max = CMDARGS_ALLOC_BLOCK;

	return KNOT_EOK;
}

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

/*! \brief Deinitialize cmdargs_t structure. */
static void cmdargs_deinit(remote_cmdargs_t *args)
{
	assert(args);

	free(args->response);
	memset(args, 0, sizeof(*args));
}

/*! \brief Callback prototype for remote commands. */
typedef int (*remote_cmdf_t)(server_t *, remote_cmdargs_t *);

/*! \brief Callback prototype for per-zone operations. */
typedef int (remote_zonef_t)(zone_t *, remote_cmdargs_t *);

/*! \brief Remote command table item. */
typedef struct remote_cmd {
	const char *name;
	remote_cmdf_t f;
} remote_cmd_t;

/* Forward decls. */
static int remote_c_stop(server_t *s, remote_cmdargs_t *a);
static int remote_c_reload(server_t *s, remote_cmdargs_t *a);
static int remote_c_refresh(server_t *s, remote_cmdargs_t *a);
static int remote_c_retransfer(server_t *s, remote_cmdargs_t *a);
static int remote_c_status(server_t *s, remote_cmdargs_t *a);
static int remote_c_zonestatus(server_t *s, remote_cmdargs_t *a);
static int remote_c_flush(server_t *s, remote_cmdargs_t *a);
static int remote_c_signzone(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_begin(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_commit(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_abort(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_desc(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_diff(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_read(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_get(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_set(server_t *s, remote_cmdargs_t *a);
static int remote_c_conf_unset(server_t *s, remote_cmdargs_t *a);

/*! \brief Table of remote commands. */
struct remote_cmd remote_cmd_tbl[] = {
	{ "stop",        &remote_c_stop },
	{ "reload",      &remote_c_reload },
	{ "refresh",     &remote_c_refresh },
	{ "retransfer",  &remote_c_retransfer },
	{ "status",      &remote_c_status },
	{ "zonestatus",  &remote_c_zonestatus },
	{ "flush",       &remote_c_flush },
	{ "signzone",    &remote_c_signzone },
	{ "conf-begin",  &remote_c_conf_begin },
	{ "conf-commit", &remote_c_conf_commit },
	{ "conf-abort",  &remote_c_conf_abort },
	{ "conf-desc",   &remote_c_conf_desc },
	{ "conf-diff",   &remote_c_conf_diff },
	{ "conf-read",   &remote_c_conf_read },
	{ "conf-get",    &remote_c_conf_get },
	{ "conf-set",    &remote_c_conf_set },
	{ "conf-unset",  &remote_c_conf_unset },
	{ NULL }
};

/* Private APIs. */

/*! \brief Apply callback to all zones specified by RDATA of NS RRs. */
static int remote_rdata_apply(server_t *s, remote_cmdargs_t *a, remote_zonef_t *cb)
{
	if (!s || !a || !cb) {
		return KNOT_EINVAL;
	}

	zone_t *zone = NULL;
	int ret = KNOT_EOK;

	for (unsigned i = 0; i < a->argc; ++i) {
		/* Process all zones in data section. */
		const knot_rrset_t *rr = &a->arg[i];
		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}

		uint16_t rr_count = rr->rrs.rr_count;
		for (uint16_t i = 0; i < rr_count; i++) {
			const knot_dname_t *dn = knot_ns_name(&rr->rrs, i);
			zone = knot_zonedb_find(s->zone_db, dn);
			if (zone == NULL) {
				char zname[KNOT_DNAME_MAXLEN];
				knot_dname_to_str(zname, dn, KNOT_DNAME_MAXLEN);
				log_warning("remote control, zone %s not found.",
				            zname);
			} else if (cb(zone, a) != KNOT_EOK) {
				a->rc = KNOT_RCODE_SERVFAIL;
			}
		}
	}

	return ret;
}

/*! \brief Zone refresh callback. */
static int remote_zone_refresh(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	rcu_read_lock();
	bool is_slave = zone_is_slave(zone);
	rcu_read_unlock();

	if (!is_slave) {
		return KNOT_EINVAL;
	}

	zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*! \brief Zone reload callback. */
static int remote_zone_reload(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	if (zone->flags & ZONE_EXPIRED) {
		log_zone_warning(zone->name, "cannot reload expired zone");
		return KNOT_EOK;
	}

	zone_events_schedule(zone, ZONE_EVENT_LOAD, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*! \brief Zone refresh callback. */
static int remote_zone_retransfer(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	rcu_read_lock();
	bool is_slave = zone_is_slave(zone);
	rcu_read_unlock();

	if (!is_slave) {
		return KNOT_EINVAL;
	}

	zone->flags |= ZONE_FORCE_AXFR;
	zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*! \brief Zone flush callback. */
static int remote_zone_flush(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	zone->flags |= ZONE_FORCE_FLUSH;
	zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*! \brief Sign zone callback. */
static int remote_zone_sign(zone_t *zone, remote_cmdargs_t *a)
{
	UNUSED(a);

	rcu_read_lock();
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	bool dnssec_enable = conf_bool(&val);
	rcu_read_unlock();

	if (!dnssec_enable) {
		return KNOT_EINVAL;
	}

	zone->flags |= ZONE_FORCE_RESIGN;
	zone_events_schedule(zone, ZONE_EVENT_DNSSEC, ZONE_EVENT_NOW);
	return KNOT_EOK;
}

/*!
 * \brief Remote command 'stop' handler.
 *
 * QNAME: stop
 * DATA: NULL
 */
static int remote_c_stop(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(a);
	UNUSED(s);
	return KNOT_CTL_STOP;
}

/*!
 * \brief Remote command 'reload' handler.
 *
 * QNAME: reload
 * DATA: NONE for all zones
 *       NS RRs with zones in RDATA
 */
static int remote_c_reload(server_t *s, remote_cmdargs_t *a)
{
	int ret = KNOT_EOK;

	if (a->argc == 0) {
		/* Reload all. */
		ret = server_reload(s, conf()->filename);
	} else {
		rcu_read_lock();
		/* Reload specific zones. */
		ret = remote_rdata_apply(s, a, &remote_zone_reload);
		rcu_read_unlock();
	}

	return (ret != KNOT_EOK) ? ret : KNOT_CTL_ACCEPTED;
}

/*!
 * \brief Remote command 'status' handler.
 *
 * QNAME: status
 * DATA: NONE
 */
static int remote_c_status(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);
	UNUSED(a);
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

static int remote_zonestatus(zone_t *zone, remote_cmdargs_t *a)
{
	if (zone == NULL || a == NULL) {
		return KNOT_EINVAL;
	}

	/* Fetch latest serial. */
	const knot_rdataset_t *soa_rrs = NULL;
	uint32_t serial = 0;
	if (zone->contents) {
		soa_rrs = node_rdataset(zone->contents->apex,
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
	bool is_slave = zone_is_slave(zone);

	int n = snprintf(buf, sizeof(buf),
	                 "%s\ttype=%s | serial=%u | %s %s | %s %s\n",
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

/*!
 * \brief Remote command 'zonestatus' handler.
 *
 * QNAME: zonestatus
 * DATA: NONE for all zones
 *       NS RRs with zones in RDATA
 */
static int remote_c_zonestatus(server_t *s, remote_cmdargs_t *a)
{
	rcu_read_lock();
	if (a->argc == 0) {
		knot_zonedb_foreach(s->zone_db, remote_zonestatus, a);
	} else {
		remote_rdata_apply(s, a, remote_zonestatus);
	}
	rcu_read_unlock();

	return KNOT_EOK;
}

/*!
 * \brief Remote command 'refresh' handler.
 *
 * QNAME: refresh
 * DATA: NONE for all zones
 *       NS RRs with zones in RDATA
 */
static int remote_c_refresh(server_t *s, remote_cmdargs_t *a)
{
	rcu_read_lock();
	if (a->argc == 0) {
		/* Refresh all. */
		knot_zonedb_foreach(s->zone_db, remote_zone_refresh, NULL);
	} else {
		/* Refresh specific zones. */
		remote_rdata_apply(s, a, remote_zone_refresh);
	}
	rcu_read_unlock();

	return KNOT_CTL_ACCEPTED;
}

/*!
 * \brief Remote command 'retransfer' handler.
 *
 * QNAME: retransfer
 * DATA: NS RRs with zones in RDATA
 */
static int remote_c_retransfer(server_t *s, remote_cmdargs_t *a)
{
	if (a->argc == 0) {
		/* Retransfer all. */
		return KNOT_CTL_ARG_REQ;
	} else {
		rcu_read_lock();
		/* Retransfer specific zones. */
		remote_rdata_apply(s, a, remote_zone_retransfer);
		rcu_read_unlock();
	}

	return KNOT_CTL_ACCEPTED;

}

/*!
 * \brief Remote command 'flush' handler.
 *
 * QNAME: flush
 * DATA: NONE for all zones
 *       NS RRs with zones in RDATA
 */
static int remote_c_flush(server_t *s, remote_cmdargs_t *a)
{
	rcu_read_lock();
	if (a->argc == 0) {
		/* Flush all. */
		knot_zonedb_foreach(s->zone_db, remote_zone_flush, NULL);
	} else {
		/* Flush specific zones. */
		remote_rdata_apply(s, a, remote_zone_flush);
	}
	rcu_read_unlock();

	return KNOT_CTL_ACCEPTED;
}

/*!
 * \brief Remote command 'signzone' handler.
 */
static int remote_c_signzone(server_t *s, remote_cmdargs_t *a)
{
	if (a->argc == 0) {
		/* Resign all. */
		return KNOT_CTL_ARG_REQ;
	} else {
		rcu_read_lock();
		/* Resign specific zones. */
		remote_rdata_apply(s, a, remote_zone_sign);
		rcu_read_unlock();
	}

	return KNOT_CTL_ACCEPTED;
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

/*!
 * \brief Remote command 'conf-begin' handler.
 */
static int remote_c_conf_begin(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);
	UNUSED(a);

	return conf_io_begin(false);
}

/*!
 * \brief Remote command 'conf-commit' handler.
 */
static int remote_c_conf_commit(server_t *s, remote_cmdargs_t *a)
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

/*!
 * \brief Remote command 'conf-abort' handler.
 */
static int remote_c_conf_abort(server_t *s, remote_cmdargs_t *a)
{
	UNUSED(s);
	UNUSED(a);

	return conf_io_abort(false);
}

/*!
 * \brief Parse config key path key0[id].key1.
 */
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

/*!
 * \brief Remote command 'conf-desc' handler.
 */
static int remote_c_conf_desc(server_t *s, remote_cmdargs_t *a)
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
	ret = conf_io_desc(key0, &io);

	free(key);

	return ret;
}

/*!
 * \brief Remote command 'conf-diff' handler.
 */
static int remote_c_conf_diff(server_t *s, remote_cmdargs_t *a)
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

/*!
 * \brief Remote command 'conf-read' handler.
 */
static int remote_c_conf_read(server_t *s, remote_cmdargs_t *a)
{
	return conf_read(s, a, true);
}

/*!
 * \brief Remote command 'conf-get' handler.
 */
static int remote_c_conf_get(server_t *s, remote_cmdargs_t *a)
{
	return conf_read(s, a, false);
}

/*!
 * \brief Remote command 'conf-set' handler.
 */
static int remote_c_conf_set(server_t *s, remote_cmdargs_t *a)
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

/*!
 * \brief Remote command 'conf-unset' handler.
 */
static int remote_c_conf_unset(server_t *s, remote_cmdargs_t *a)
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

int remote_bind(const char *path)
{
	if (path == NULL) {
		return KNOT_EINVAL;
	}

	log_info("remote control, binding to '%s'", path);

	/* Prepare socket address. */
	struct sockaddr_storage addr;
	int ret = sockaddr_set(&addr, AF_UNIX, path, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Create new socket. */
	int sock = net_bound_socket(SOCK_STREAM, &addr, 0);
	if (sock < 0) {
		log_error("remote control, failed to bind to '%s' (%s)",
		          path, knot_strerror(sock));
		return sock;
	}

	/* Start listening. */
	if (listen(sock, TCP_BACKLOG_SIZE) != 0) {
		log_error("remote control, failed to listen on '%s'", path);
		close(sock);
		return knot_map_errno();
	}

	return sock;
}

void remote_unbind(int sock)
{
	if (sock < 0) {
		return;
	}

	/* Remove the control socket file.  */
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if (getsockname(sock, (struct sockaddr *)&addr, &addr_len) == 0) {
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		if (sockaddr_tostr(addr_str, sizeof(addr_str), &addr) > 0) {
			(void)unlink(addr_str);
		}
	}

	/* Close the socket.  */
	(void)close(sock);
}

int remote_poll(int sock, const sigset_t *sigmask)
{
	/* Wait for events. */
	fd_set rfds;
	FD_ZERO(&rfds);
	if (sock > -1) {
		FD_SET(sock, &rfds);
	} else {
		sock = -1; /* Make sure n == r + 1 == 0 */
	}

	return pselect(sock + 1, &rfds, NULL, NULL, NULL, sigmask);
}

int remote_recv(int sock, uint8_t *buf, size_t *buflen)
{
	int c = tcp_accept(sock);
	if (c < 0) {
		return c;
	}

	/* Receive data. */
	int n = net_dns_tcp_recv(c, buf, *buflen, NULL);
	*buflen = n;
	if (n <= 0) {
		close(c);
		return KNOT_ECONNREFUSED;
	}

	return c;
}

int remote_parse(knot_pkt_t *pkt)
{
	return knot_pkt_parse(pkt, 0);
}

static int remote_send_chunk(int c, knot_pkt_t *query, const char *d, uint16_t len,
                             int index)
{
	knot_pkt_t *resp = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, &query->mm);
	if (!resp) {
		return KNOT_ENOMEM;
	}

	/* Initialize response. */
	int ret = knot_pkt_init_response(resp, query);
	if (ret != KNOT_EOK) {
		goto failed;
	}

	/* Write to NS section. */
	ret = knot_pkt_begin(resp, KNOT_AUTHORITY);
	assert(ret == KNOT_EOK);

	/* Create TXT RR with result. */
	knot_rrset_t rr;
	ret = remote_build_rr(&rr, "result.", KNOT_RRTYPE_TXT);
	if (ret != KNOT_EOK) {
		goto failed;
	}

	ret = remote_create_txt(&rr, d, len, index);
	assert(ret == KNOT_EOK);

	ret = knot_pkt_put(resp, 0, &rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		goto failed;
	}

	rcu_read_lock();
	conf_val_t *val = &conf()->cache.srv_tcp_reply_timeout;
	struct timeval timeout = { conf_int(val), 0 };
	rcu_read_unlock();

	ret = net_dns_tcp_send(c, resp->wire, resp->size, &timeout);

failed:

	/* Free packet. */
	knot_pkt_free(&resp);

	return ret;
}

static void log_command(const char *cmd, const remote_cmdargs_t *args)
{
	char params[CMDARGS_BUFLEN_LOG] = { 0 };
	size_t rest = CMDARGS_BUFLEN_LOG;
	size_t pos = 0;

	for (unsigned i = 0; i < args->argc; i++) {
		const knot_rrset_t *rr = &args->arg[i];
		if (rr->type != KNOT_RRTYPE_NS) {
			continue;
		}

		uint16_t rr_count = rr->rrs.rr_count;
		for (uint16_t j = 0; j < rr_count; j++) {
			const knot_dname_t *dn = knot_ns_name(&rr->rrs, j);
			char *name = knot_dname_to_str_alloc(dn);

			int ret = snprintf(params + pos, rest, " %s", name);
			free(name);

			if (ret <= 0 || ret >= rest) {
				break;
			}
			pos += ret;
			rest -= ret;
		}
	}

	log_info("remote control, received command '%s%s'", cmd, params);
}

int remote_answer(int sock, server_t *s, knot_pkt_t *pkt)
{
	if (sock < 0 || s == NULL || pkt == NULL) {
		return KNOT_EINVAL;
	}

	/* Prerequisites:
	 * QCLASS: CH
	 * QNAME: <CMD>.KNOT_CTL_REALM.
	 */
	const knot_dname_t *qname = knot_pkt_qname(pkt);
	if (knot_pkt_qclass(pkt) != KNOT_CLASS_CH) {
		return KNOT_EMALF;
	}

	knot_dname_t *realm = knot_dname_from_str_alloc(KNOT_CTL_REALM);
	if (!knot_dname_is_sub(qname, realm) != 0) {
		knot_dname_free(&realm, NULL);
		return KNOT_EMALF;
	}
	knot_dname_free(&realm, NULL);

	/* Command:
	 * QNAME: leftmost label of QNAME
	 */
	size_t cmd_len = *qname;
	char *cmd = strndup((char*)qname + 1, cmd_len);

	/* Data:
	 * NS: TSIG
	 * AR: data
	 */
	remote_cmdargs_t args = { 0 };
	int ret = cmdargs_init(&args);
	if (ret != KNOT_EOK) {
		free(cmd);
		return ret;
	}

	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	args.arg = knot_pkt_rr(authority, 0);
	args.argc = authority->count;
	args.rc = KNOT_RCODE_NOERROR;

	log_command(cmd, &args);

	remote_cmd_t *c = remote_cmd_tbl;
	while (c->name != NULL) {
		if (strcmp(cmd, c->name) == 0) {
			ret = c->f(s, &args);
			break;
		}
		++c;
	}

	/* Prepare response. */
	if (args.response_size == 0) {
		args.response_size = strlen(knot_strerror(ret));
		strlcpy(args.response, knot_strerror(ret), args.response_max);
	}

	int index = 0;
	unsigned p = 0;
	size_t chunk = 16384;
	for (; p + chunk < args.response_size; p += chunk) {
		remote_send_chunk(sock, pkt, args.response + p, chunk, index);
		index++;
	}

	unsigned r = args.response_size - p;
	if (r > 0) {
		remote_send_chunk(sock, pkt, args.response + p, r, index);
	}

	cmdargs_deinit(&args);
	free(cmd);
	return ret;
}

int remote_process(server_t *server, int sock, uint8_t *buf, size_t buflen)
{
	knot_pkt_t *pkt =  knot_pkt_new(buf, buflen, NULL);
	if (pkt == NULL) {
		return KNOT_ENOMEM;
	}

	/* Accept incoming connection and read packet. */
	int client = remote_recv(sock, pkt->wire, &buflen);
	if (client < 0) {
		knot_pkt_free(&pkt);
		return client;
	} else {
		pkt->size = buflen;
	}

	/* Parse packet and answer if OK. */
	int ret = remote_parse(pkt);
	if (ret == KNOT_EOK) {
		ret = remote_answer(client, server, pkt);
	}

	knot_pkt_free(&pkt);
	close(client);
	return ret;
}

knot_pkt_t* remote_query(const char *query)
{
	if (!query) {
		return NULL;
	}

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		return NULL;
	}

	knot_wire_set_id(pkt->wire, dnssec_random_uint16_t());

	/* Question section. */
	char *qname = strcdup(query, KNOT_CTL_REALM_EXT);
	knot_dname_t *dname = knot_dname_from_str_alloc(qname);
	free(qname);
	if (!dname) {
		knot_pkt_free(&pkt);
		return NULL;
	}

	/* Cannot return != KNOT_EOK, but still. */
	if (knot_pkt_put_question(pkt, dname, KNOT_CLASS_CH, KNOT_RRTYPE_ANY) != KNOT_EOK) {
		knot_pkt_free(&pkt);
		knot_dname_free(&dname, NULL);
		return NULL;
	}

	knot_dname_free(&dname, NULL);
	return pkt;
}

int remote_build_rr(knot_rrset_t *rr, const char *owner, uint16_t type)
{
	if (!rr || !owner) {
		return KNOT_EINVAL;
	}

	/* Assert K is FQDN. */
	knot_dname_t *name = knot_dname_from_str_alloc(owner);
	if (name == NULL) {
		return KNOT_ENOMEM;
	}

	/* Init RRSet. */
	knot_rrset_init(rr, name, type, KNOT_CLASS_CH);

	return KNOT_EOK;
}

int remote_create_txt(knot_rrset_t *rr, const char *str, size_t str_len,
                      uint16_t index)
{
	if (!rr || !str) {
		return KNOT_EINVAL;
	}

	/* Maximal chunk size. */
	const size_t K = 255;
	/* Number of chunks (ceiling operation). */
	const size_t chunks = (str_len + K - 1)/ K;
	/* Total raw chunk length. */
	const size_t raw_len = sizeof(uint8_t) + sizeof(index) + str_len + chunks;

	uint8_t raw[raw_len];
	memset(raw, 0, raw_len);

	uint8_t *out = raw;
	const char *in = str;

	/* Write index chunk. */
	*out++ = sizeof(index);
	wire_write_u16(out, index);
	out += sizeof(index);

	if (chunks > 0) {
		/* Write leading full chunks. */
		for (size_t i = 0; i < chunks - 1; i++) {
			/* Maximal chunk length. */
			*out++ = (uint8_t)K;
			/* Data chunk. */
			memcpy(out, in, K);
			out += K;
			in += K;
		}

		/* Write last chunk. */
		const size_t rest = str + str_len - in;
		assert(rest <= K);
		/* Last chunk length. */
		*out++ = (uint8_t)rest;
		/* Last data chunk. */
		memcpy(out, in, rest);
	}

	return knot_rrset_add_rdata(rr, raw, raw_len, 0, NULL);
}

int remote_create_ns(knot_rrset_t *rr, const char *name)
{
	if (!rr || !name) {
		return KNOT_EINVAL;
	}

	/* Create dname. */
	knot_dname_t *dn = knot_dname_from_str_alloc(name);
	if (!dn) {
		return KNOT_ERROR;
	}

	/* Build RDATA. */
	int dn_size = knot_dname_size(dn);
	int result = knot_rrset_add_rdata(rr, dn, dn_size, 0, NULL);
	knot_dname_free(&dn, NULL);

	return result;
}

int remote_print_txt(const knot_rrset_t *rr, uint16_t pos)
{
	if (!rr) {
		return KNOT_EINVAL;
	}

	size_t count = knot_txt_count(&rr->rrs, pos);
	for (size_t i = 0; i < count; i++) {
		const uint8_t *rdata = knot_txt_data(&rr->rrs, pos, i);
		printf("%.*s", (int)rdata[0], rdata + 1);
	}

	return KNOT_EOK;
}

uint8_t *remote_get_txt(const knot_rrset_t *rr, uint16_t pos, size_t *out_len)
{
	if (!rr) {
		return NULL;
	}

	// The buffer will be slightly bigger (including string lengths).
	size_t buf_len = knot_rdata_rdlen(knot_rdataset_at(&rr->rrs, pos));
	uint8_t *buf = malloc(buf_len);
	if (buf == NULL) {
		return NULL;
	}

	size_t len = 0;

	size_t count = knot_txt_count(&rr->rrs, pos);
	for (size_t i = 1; i < count; i++) {
		const uint8_t *rdata = knot_txt_data(&rr->rrs, pos, i);
		memcpy(buf + len, rdata + 1, rdata[0]);
		len += rdata[0];
	}

	// There is always at least one free byte.
	buf[len] = '\0';

	if (out_len != NULL) {
		*out_len = len;
	}

	return buf;
}
