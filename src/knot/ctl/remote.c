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

#include <config.h>
#include <sys/stat.h>
#include "knot/ctl/remote.h"
#include "common/log.h"
#include "common/fdset.h"
#include "knot/knot.h"
#include "knot/conf/conf.h"
#include "knot/server/socket.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/zones.h"
#include "libknot/util/wire.h"
#include "libknot/packet/query.h"
#include "common/descriptor.h"
#include "libknot/packet/response.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/tsig-op.h"
#include "libknot/rdata.h"
#include "libknot/dnssec/random.h"
#include "libknot/dnssec/zone-sign.h"
#include "libknot/dnssec/zone-nsec.h"

#define KNOT_CTL_REALM "knot."
#define KNOT_CTL_REALM_EXT ("." KNOT_CTL_REALM)
#define CMDARGS_BUFLEN (1024*1024) /* 1M */
#define KNOT_CTL_SOCKET_UMASK 0007

/*! \brief Remote command structure. */
typedef struct remote_cmdargs_t {
	const knot_rrset_t **arg;
	unsigned argc;
	knot_rcode_t rc;
	char resp[CMDARGS_BUFLEN];
	size_t rlen;
} remote_cmdargs_t;

/*! \brief Callback prototype for remote commands. */
typedef int (*remote_cmdf_t)(server_t*, remote_cmdargs_t*);

/*! \brief Callback prototype for per-zone operations. */
typedef int (remote_zonef_t)(server_t*, const knot_zone_t *);

/*! \brief Remote command table item. */
typedef struct remote_cmd_t {
	const char *name;
	remote_cmdf_t f;
} remote_cmd_t;

/* Forward decls. */
static int remote_c_stop(server_t *s, remote_cmdargs_t* a);
static int remote_c_reload(server_t *s, remote_cmdargs_t* a);
static int remote_c_refresh(server_t *s, remote_cmdargs_t* a);
static int remote_c_status(server_t *s, remote_cmdargs_t* a);
static int remote_c_zonestatus(server_t *s, remote_cmdargs_t* a);
static int remote_c_flush(server_t *s, remote_cmdargs_t* a);
static int remote_c_signzone(server_t *s, remote_cmdargs_t* a);

/*! \brief Table of remote commands. */
struct remote_cmd_t remote_cmd_tbl[] = {
	{ "stop",      &remote_c_stop },
	{ "reload",    &remote_c_reload },
	{ "refresh",   &remote_c_refresh },
	{ "status",    &remote_c_status },
	{ "zonestatus",&remote_c_zonestatus },
	{ "flush",     &remote_c_flush },
	{ "signzone",  &remote_c_signzone },
	{ NULL,        NULL }
};

/* Private APIs. */

/*! \brief Apply callback to all zones specified by RDATA of CNAME RRs. */
static int remote_rdata_apply(server_t *s, remote_cmdargs_t* a, remote_zonef_t *cb)
{
	if (!s || !a || !cb) {
		return KNOT_EINVAL;
	}

	knot_nameserver_t *ns = s->nameserver;
	knot_zone_t *zone = NULL;
	int ret = KNOT_EOK;

	/* Refresh specific zones. */
	for (unsigned i = 0; i < a->argc; ++i) {
		/* Process all zones in data section. */
		const knot_rrset_t *rr = a->arg[i];
		if (knot_rrset_type(rr) != KNOT_RRTYPE_NS) {
			continue;
		}

		for (uint16_t i = 0; i < knot_rrset_rdata_rr_count(rr); i++) {
			/* Refresh zones. */
			const knot_dname_t *dn =
				knot_rdata_ns_name(rr, i);
			rcu_read_lock();
			zone = knot_zonedb_find_zone(ns->zone_db, dn);
			if (cb(s, zone) != KNOT_EOK) {
				a->rc = KNOT_RCODE_SERVFAIL;
			}
			rcu_read_unlock();
		}
	}

	return ret;
}

/*! \brief Zone refresh callback. */
static int remote_zone_refresh(server_t *s, const knot_zone_t *z)
{
	if (!s || !z) {
		return KNOT_EINVAL;
	}

	knot_nameserver_t *ns =  s->nameserver;
	evsched_t *sch = ((server_t *)knot_ns_get_data(ns))->sched;
	zonedata_t *zd = (zonedata_t *)knot_zone_data(z);
	if (!sch || !zd) {
		return KNOT_EINVAL;
	}

	/* Expire REFRESH timer. */
	if (zd->xfr_in.timer) {
		evsched_cancel(sch, zd->xfr_in.timer);
		evsched_schedule(sch, zd->xfr_in.timer,
		                 knot_random_uint32_t() % 1000);
	}

	return KNOT_EOK;
}

/*! \brief Zone flush callback. */
static int remote_zone_flush(server_t *s, const knot_zone_t *z)
{
	if (!s || !z) {
		return KNOT_EINVAL;
	}

	knot_nameserver_t *ns =  s->nameserver;
	evsched_t *sch = ((server_t *)knot_ns_get_data(ns))->sched;
	zonedata_t *zd = (zonedata_t *)knot_zone_data(z);
	if (!sch || !zd) {
		return KNOT_EINVAL;
	}

	/* Expire IXFR sync timer. */
	if (zd->ixfr_dbsync) {
		evsched_cancel(sch, zd->ixfr_dbsync);
		evsched_schedule(sch, zd->ixfr_dbsync,
		                 knot_random_uint32_t() % 1000);
	}

	return KNOT_EOK;
}

/*! \brief Sign zone callback. */
static int remote_zone_sign(server_t *server, const knot_zone_t *zone)
{
	if (!server || !zone) {
		return KNOT_EINVAL;
	}

	char *zone_name = knot_dname_to_str(zone->name);
	log_server_info("Requested zone resign for '%s'.\n", zone_name);
	free(zone_name);

	uint32_t expires_at = 0;
	zones_cancel_dnssec((knot_zone_t *)zone);
	rcu_read_lock();
	zones_dnssec_sign((knot_zone_t *)zone, true, &expires_at);
	rcu_read_unlock();
	zones_schedule_dnssec((knot_zone_t *)zone, expires_at);

	return KNOT_EOK;
}

/*!
 * \brief Remote command 'stop' handler.
 *
 * QNAME: stop
 * DATA: NULL
 */
static int remote_c_stop(server_t *s, remote_cmdargs_t* a)
{
	UNUSED(a);
	UNUSED(s);
	return KNOT_CTL_STOP;
}

/*!
 * \brief Remote command 'reload' handler.
 *
 * QNAME: reload
 * DATA: NULL
 */
static int remote_c_reload(server_t *s, remote_cmdargs_t* a)
{
	UNUSED(a);
	return server_reload(s, conf()->filename);
}

/*!
 * \brief Remote command 'status' handler.
 *
 * QNAME: status
 * DATA: NONE
 */
static int remote_c_status(server_t *s, remote_cmdargs_t* a)
{
	UNUSED(s);
	UNUSED(a);
	/*! \todo #2035 Add some TXT RRs with stats. */
	dbg_server("remote: %s\n", __func__);
	return KNOT_EOK;
}

static char *dnssec_info(const zonedata_t *zd, char *buf, size_t buf_size)
{
	assert(zd && zd->dnssec_timer);
	assert(buf);

	time_t diff_time = zd->dnssec_timer->tv.tv_sec;
	struct tm *t = localtime(&diff_time);

	size_t written = strftime(buf, buf_size, "%c", t);
	if (written == 0) {
		return NULL;
	}

	return buf;
}

/*!
 * \brief Remote command 'zonestatus' handler.
 *
 * QNAME: zonestatus
 * DATA: NONE
 */
static int remote_c_zonestatus(server_t *s, remote_cmdargs_t* a)
{
	dbg_server("remote: %s\n", __func__);
	char *dst = a->resp;
	size_t rb = sizeof(a->resp) - 1;

	int ret = KNOT_EOK;
	rcu_read_lock();
	knot_nameserver_t *ns =  s->nameserver;
	const knot_zone_t **zones = knot_zonedb_zones(ns->zone_db);
	for (unsigned i = 0; i < knot_zonedb_zone_count(ns->zone_db); ++i) {
		zonedata_t *zd = (zonedata_t *)zones[i]->data;

		/* Fetch latest serial. */
		const knot_rrset_t *soa_rrs = 0;
		uint32_t serial = 0;
		knot_zone_contents_t *contents = knot_zone_get_contents(zones[i]);
		if (contents) {
			soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
			                          KNOT_RRTYPE_SOA);
			assert(soa_rrs != NULL);
			serial = knot_rdata_soa_serial(soa_rrs);
		}

		/* Evalute zone type. */
		const char *state = NULL;
		if (serial == 0)  {
			state = "bootstrap";
		} else if (zd->xfr_in.has_master) {
			state = "xfer";
		}

		/* Evaluate zone state. */
		char *when = NULL;
		if (zd->xfr_in.state == XFR_PENDING) {
			when = strdup("pending");
		} else if (zd->xfr_in.timer && zd->xfr_in.timer->tv.tv_sec != 0) {
			struct timeval now, dif;
			gettimeofday(&now, 0);
			timersub(&zd->xfr_in.timer->tv, &now, &dif);
			when = malloc(64);
			if (when == NULL) {
				ret = KNOT_ENOMEM;
				break;
			}
			/*! Workaround until proper zone fetching API and locking
			 *  is implemented (ref #31)
			 */
			if (dif.tv_sec < 0) {
				memcpy(when, "busy", 5);
			} else if (snprintf(when, 64, "in %uh%um%us",
			                    (unsigned int)dif.tv_sec / 3600,
			                    (unsigned int)(dif.tv_sec % 3600) / 60,
			                    (unsigned int)dif.tv_sec % 60) < 0) {
				free(when);
				ret = KNOT_ESPACE;
				break;
			}
		} else {
			when = strdup("idle");
		}

		/* Workaround, some platforms ignore 'size' with snprintf() */
		char buf[512] = { '\0' };
		char dnssec_buf[128] = { '\0' };
		int n = snprintf(buf, sizeof(buf),
		                 "%s\ttype=%s | serial=%u | %s %s | %s %s\n",
		                 zd->conf->name,
		                 zd->xfr_in.has_master ? "slave" : "master",
		                 serial,
		                 state ? state : "",
		                 when ? when : "",
		                 zd->conf->dnssec_enable ? "automatic DNSSEC, resigning at:" : "",
		                 zd->conf->dnssec_enable ? dnssec_info(zd, dnssec_buf, sizeof(dnssec_buf)) : "");
		free(when);
		if (n < 0 || (size_t)n > rb) {
			*dst = '\0';
			ret = KNOT_ESPACE;
			break;
		}

		assert(n <= sizeof(buf));

		memcpy(dst, buf, n);
		rb -= n;
		dst += n;


	}
	rcu_read_unlock();

	a->rlen = sizeof(a->resp) - 1 - rb;
	return ret;
}

/*!
 * \brief Remote command 'refresh' handler.
 *
 * QNAME: refresh
 * DATA: NONE for all zones
 *       CNAME RRs with zones in RDATA
 */
static int remote_c_refresh(server_t *s, remote_cmdargs_t* a)
{
	/* Refresh all. */
	dbg_server("remote: %s\n", __func__);
	if (a->argc == 0) {
		dbg_server_verb("remote: refreshing all zones\n");
		return server_refresh(s);
	}

	/* Refresh specific zones. */
	return remote_rdata_apply(s, a, &remote_zone_refresh);
}

/*!
 * \brief Remote command 'flush' handler.
 *
 * QNAME: flush
 * DATA: NONE for all zones
 *       CNAME RRs with zones in RDATA
 */
static int remote_c_flush(server_t *s, remote_cmdargs_t* a)
{
	/* Flush all. */
	dbg_server("remote: %s\n", __func__);
	if (a->argc == 0) {
		int ret = 0;
		dbg_server_verb("remote: flushing all zones\n");
		rcu_read_lock();
		knot_nameserver_t *ns =  s->nameserver;
		const knot_zone_t **zones = knot_zonedb_zones(ns->zone_db);
		for (unsigned i = 0; i < knot_zonedb_zone_count(ns->zone_db); ++i) {
			ret = remote_zone_flush(s, zones[i]);
		}
		rcu_read_unlock();
		return ret;
	}

	/* Flush specific zones. */
	return remote_rdata_apply(s, a, &remote_zone_flush);
}

/*!
 * \brief Remote command 'signzone' handler.
 *
 */
static int remote_c_signzone(server_t *server, remote_cmdargs_t* arguments)
{
	dbg_server("remote: %s\n", __func__);

	if (arguments->argc == 0) {
		log_server_error("signzone for all zone was requested\n");
		// TODO
		return KNOT_ENOTSUP;
	}

	return remote_rdata_apply(server, arguments, remote_zone_sign);
}

/*!
 * \brief Prepare and send error response.
 * \param c Client fd.
 * \param buf Query buffer.
 * \param buflen Query size.
 * \return number of bytes sent
 */
static int remote_senderr(int c, uint8_t *qbuf, size_t buflen)
{
	knot_wire_set_qr(qbuf);
	knot_wire_set_rcode(qbuf, KNOT_RCODE_REFUSED);
	return tcp_send(c, qbuf, buflen);
}

/* Public APIs. */

int remote_bind(conf_iface_t *desc)
{
	if (!desc) {
		return -1;
	}

	/* Create new socket. */
	int s = socket_create(desc->family, SOCK_STREAM, 0);
	if (s < 0) {
		log_server_error("Couldn't create socket for remote "
				 "control interface - %s", knot_strerror(s));
		return KNOT_ERROR;
	}

	/* Bind to interface and start listening. */
	mode_t old_umask = umask(KNOT_CTL_SOCKET_UMASK);
	int r = socket_bind(s, desc->family, desc->address, desc->port);
	umask(old_umask);
	if (r == KNOT_EOK) {
		r = socket_listen(s, TCP_BACKLOG_SIZE);
	}
	if (r != KNOT_EOK) {
		log_server_error("Could not bind to remote control interface.\n");
		socket_close(s);
		return r;
	}

	return s;
}

int remote_unbind(int r)
{
	if (r < 0) {
		return KNOT_EINVAL;
	}

	return socket_close(r);
}

int remote_poll(int r)
{
	/* Wait for events. */
	fd_set rfds;
	FD_ZERO(&rfds);
	if (r > -1) {
		FD_SET(r, &rfds);
	} else {
		r = -1; /* Make sure n == r + 1 == 0 */
	}

	return fdset_pselect(r + 1, &rfds, NULL, NULL, NULL, NULL);
}

int remote_recv(int r, sockaddr_t *a, uint8_t* buf, size_t *buflen)
{
	int c = tcp_accept(r);
	if (c < 0) {
		dbg_server("remote: couldn't accept incoming connection\n");
		return c;
	}

	/* Receive data. */
	int n = tcp_recv(c, buf, *buflen, a);
	*buflen = n;
	if (n <= 0) {
		dbg_server("remote: failed to receive data\n");
		socket_close(c);
		return KNOT_ECONNREFUSED;
	}

	return c;
}

int remote_parse(knot_packet_t* pkt, const uint8_t* buf, size_t buflen)
{
	knot_packet_type_t qtype = KNOT_QUERY_NORMAL;
	int ret = knot_ns_parse_packet(buf, buflen, pkt, &qtype);
	if (ret != KNOT_EOK) {
		dbg_server("remote: failed to parse packet\n");
		return KNOT_EINVAL;
	}
	ret = knot_packet_parse_rest(pkt, 0);
	if (ret != KNOT_EOK) {
		dbg_server("remote: failed to parse packet data\n");
		return KNOT_EINVAL;
	}

	return ret;
}

static int remote_send_chunk(int c, knot_packet_t *pkt, const char* d,
                             uint16_t dlen, uint8_t* rwire, size_t rlen)
{
	int ret = KNOT_ERROR;
	knot_packet_t *resp = knot_packet_new_mm(&pkt->mm);
	if (!resp) {
		return ret;
	}
	uint8_t *wire = NULL;
	size_t len = 0;
	ret = knot_packet_set_max_size(resp, SOCKET_MTU_SZ);
	if (ret != KNOT_EOK)  {
		knot_packet_free(&resp);
		return ret;
	}
	ret = knot_response_init_from_query(resp, pkt);
	if (ret != KNOT_EOK)  {
		knot_packet_free(&resp);
		return ret;
	}
	ret = knot_packet_to_wire(resp, &wire, &len);
	if (ret != KNOT_EOK)  {
                knot_packet_free(&resp);
                return ret;
        }
	if (len > 0) {
		memcpy(rwire, wire, len);
		rlen -= len;
	}
	knot_packet_free(&resp);
	if (len == 0) {
		return KNOT_ERROR;
	}

	/* Evaluate output. */
	uint16_t rr_count = 0;
	knot_rrset_t *rr = remote_build_rr("result.", KNOT_RRTYPE_TXT);
	remote_create_txt(rr, d, dlen);


	size_t rrlen = rlen;
	ret = knot_rrset_to_wire(rr, rwire + len, &rrlen, rlen, &rr_count, NULL);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&rr, 1);
		return ret;
	}
	knot_wire_set_nscount(rwire, rr_count);
	len += rrlen;
	knot_rrset_deep_free(&rr, 1);

	if (len > 0) {
		return tcp_send(c, rwire, len);
	}

	return len;
}

int remote_answer(int fd, server_t *s, knot_packet_t *pkt, uint8_t* rwire, size_t rlen)
{
	if (fd < 0 || !s || !pkt || !rwire) {
		return KNOT_EINVAL;
	}

	/* Prerequisites:
	 * QCLASS: CH
	 * QNAME: <CMD>.KNOT_CTL_REALM.
	 */
	const knot_dname_t *qname = knot_packet_qname(pkt);
	if (knot_packet_qclass(pkt) != KNOT_CLASS_CH) {
		dbg_server("remote: qclass != CH\n");
		return KNOT_EMALF;
	}

	knot_dname_t *realm = knot_dname_from_str(KNOT_CTL_REALM);
	if (!knot_dname_is_sub(qname, realm) != 0) {
		dbg_server("remote: qname != *%s\n", KNOT_CTL_REALM_EXT);
		knot_dname_free(&realm);
		return KNOT_EMALF;
	}
	knot_dname_free(&realm);

	/* Command:
	 * QNAME: leftmost label of QNAME
	 */
	size_t cmd_len = *qname;
	char *cmd = strndup((char*)qname + 1, cmd_len);

	/* Data:
	 * NS: TSIG
	 * AR: data
	 */
	int ret = KNOT_EOK;
	remote_cmdargs_t* args = malloc(sizeof(remote_cmdargs_t));
	if (!args) {
		free(cmd);
		return KNOT_ENOMEM;
	}
	memset(args, 0, sizeof(remote_cmdargs_t));
	args->arg = pkt->authority;
	args->argc = knot_packet_authority_rrset_count(pkt);
	args->rc = KNOT_RCODE_NOERROR;

	remote_cmd_t *c = remote_cmd_tbl;
	while(c->name != NULL) {
		if (strcmp(cmd, c->name) == 0) {
			ret = c->f(s, args);
			break;
		}
		++c;
	}

	/* Prepare response. */
	if (ret != KNOT_EOK || args->rlen == 0) {
		args->rlen = strlen(knot_strerror(ret));
		strncpy(args->resp, knot_strerror(ret), args->rlen);
	}

	unsigned p = 0;
	size_t chunk = 16384;
	for (; p + chunk < args->rlen; p += chunk) {
		remote_send_chunk(fd, pkt, args->resp + p, chunk, rwire, rlen);
	}

	unsigned r = args->rlen - p;
	if (r > 0) {
		remote_send_chunk(fd, pkt, args->resp + p, r, rwire, rlen);
	}

	free(args);
	free(cmd);
	return ret;
}

int remote_process(server_t *s, conf_iface_t *ctl_if, int r,
                   uint8_t* buf, size_t buflen)
{
	knot_packet_t *pkt =  knot_packet_new();
	if (!pkt) {
		dbg_server("remote: not enough space to allocate query\n");
		return KNOT_ENOMEM;
	}

	/* Initialize remote party address. */
	sockaddr_t a;
	sockaddr_prep(&a);

	/* Accept incoming connection and read packet. */
	size_t wire_len = buflen;
	int c = remote_recv(r, &a, buf, &wire_len);
	if (c < 0) {
		dbg_server("remote: couldn't receive query = %d\n", c);
		knot_packet_free(&pkt);
		return c;
	}

	/* Parse packet and answer if OK. */
	int ret = remote_parse(pkt, buf, wire_len);
	if (ret == KNOT_EOK && ctl_if->family != AF_UNIX) {

		/* Check ACL list. */
		char straddr[SOCKADDR_STRLEN];
		sockaddr_tostr(&a, straddr, sizeof(straddr));
		int rport = sockaddr_portnum(&a);
		knot_tsig_key_t *k = NULL;
		acl_match_t *m = NULL;
		knot_rcode_t ts_rc = 0;
		uint16_t ts_trc = 0;
		uint64_t ts_tmsigned = 0;
		const knot_rrset_t *tsig_rr = knot_packet_tsig(pkt);
		if ((m = acl_find(conf()->ctl.acl, &a)) == NULL) {
			knot_packet_free(&pkt);
			log_server_warning("Denied remote control for '%s@%d' "
			                   "(doesn't match ACL).\n",
			                   straddr, rport);
			remote_senderr(c, buf, wire_len);
			socket_close(c);
			return KNOT_EACCES;
		} else if (m->val) {
			k = ((conf_iface_t *)m->val)->key;
		}

		/* Check TSIG. */
		if (k) {
			if (!tsig_rr) {
				log_server_warning("Denied remote control for '%s@%d' "
				                   "(key required).\n",
				                   straddr, rport);
				knot_packet_free(&pkt);
				remote_senderr(c, buf, wire_len);
				socket_close(c);
				return KNOT_EACCES;
			}
			ret = zones_verify_tsig_query(pkt, k, &ts_rc,
			                              &ts_trc, &ts_tmsigned);
			if (ret != KNOT_EOK) {
				log_server_warning("Denied remote control for '%s@%d' "
				                   "(key verification failed).\n",
				                   straddr, rport);
				knot_packet_free(&pkt);
				remote_senderr(c, buf, wire_len);
				socket_close(c);
				return KNOT_EACCES;
			}
		}
	}

	/* Answer packet. */
	if (ret == KNOT_EOK)
		ret = remote_answer(c, s, pkt, buf, buflen);

	knot_packet_free(&pkt);
	socket_close(c);
	return ret;
}

knot_packet_t* remote_query(const char *query, const knot_tsig_key_t *key)
{
	if (!query) {
		return NULL;
	}

	knot_packet_t *qr = knot_packet_new();
	if (!qr) {
		return NULL;
	}

	knot_packet_set_max_size(qr, 512);
	knot_query_init(qr);
	knot_packet_set_random_id(qr);

	/* Reserve space for TSIG. */
	if (key) {
		knot_packet_set_tsig_size(qr, tsig_wire_maxsize(key));
	}

	/* Question section. */
	char *qname = strcdup(query, KNOT_CTL_REALM_EXT);
	knot_dname_t *dname = knot_dname_from_str(qname);
	if (!dname) {
		knot_packet_free(&qr);
		free(qname);
		return NULL;
	}

	/* Cannot return != KNOT_EOK, but still. */
	if (knot_query_set_question(qr, dname, KNOT_CLASS_CH, KNOT_RRTYPE_ANY) != KNOT_EOK) {
		knot_packet_free(&qr);
		knot_dname_free(&dname);
		free(qname);
		return NULL;
	}

	knot_dname_free(&dname);
	free(qname);

	return qr;
}

int remote_query_append(knot_packet_t *qry, knot_rrset_t *data)
{
	if (!qry || !data) {
		return KNOT_EINVAL;
	}

	uint8_t *sp = qry->wireformat + qry->size;
	uint16_t rrs = 0;
	size_t bsize = 0;
	int ret = knot_rrset_to_wire(data, sp, &bsize, qry->max_size, &rrs, 0);
	if (ret == KNOT_EOK) {
		knot_wire_add_nscount(qry->wireformat, rrs);
	}

	/* Finalize packet size. */
	qry->size += bsize;
	return KNOT_EOK;
}


int remote_query_sign(uint8_t *wire, size_t *size, size_t maxlen,
                      const knot_tsig_key_t *key)
{
	if (!wire || !size || !key) {
		return KNOT_EINVAL;
	}

	size_t dlen = knot_tsig_digest_length(key->algorithm);
	uint8_t *digest = malloc(dlen);
	if (!digest) {
		return KNOT_ENOMEM;
	}

	int ret = knot_tsig_sign(wire, size, maxlen, NULL, 0, digest, &dlen,
	                         key, 0, 0);
	free(digest);

	return ret;
}

knot_rrset_t* remote_build_rr(const char *k, uint16_t t)
{
	if (!k) {
		return NULL;
	}

	/* Assert K is FQDN. */
	knot_dname_t *key = knot_dname_from_str(k);
	if (key == NULL) {
		return NULL;
	}

	/* Create RRSet. */
	knot_rrset_t *rr = knot_rrset_new(key, t, KNOT_CLASS_CH, 0);
	if (rr == NULL)
		knot_dname_free(&key);

	return rr;
}

int remote_create_txt(knot_rrset_t *rr, const char *v, size_t v_len)
{
	if (!rr || !v) {
		return KNOT_EINVAL;
	}

	/* Number of chunks. */
	const size_t K = 255;
	unsigned chunks = v_len / K + 1;
	uint8_t *raw = knot_rrset_create_rdata(rr, v_len + chunks);

	/* Write TXT item. */
	unsigned p = 0;
	if (v_len > K) {
		for (; p + K < v_len; p += K) {
			*(raw++) = (uint8_t)K;
			memcpy(raw, v+p, K);
			raw += K;
		}
	}
	unsigned r = v_len - p;
	if (r > 0) {
		*(raw++) = (uint8_t)r;
		memcpy(raw, v+p, r);
	}

	return KNOT_EOK;
}

int remote_create_ns(knot_rrset_t *rr, const char *d)
{
	if (!rr || !d) {
		return KNOT_EINVAL;
	}

	/* Create dname. */
	knot_dname_t *dn = knot_dname_from_str(d);
	if (!dn) {
		return KNOT_ERROR;
	}

	/* Build RDATA. */
	int dn_size = knot_dname_size(dn);
	int result = knot_rrset_add_rdata(rr, dn, dn_size);
	knot_dname_free(&dn);

	return result;
}

int remote_print_txt(const knot_rrset_t *rr, uint16_t i)
{
	if (!rr || knot_rrset_rdata_rr_count(rr) < 1) {
		return -1;
	}

	/* Packet parser should have already checked the packet validity. */
	char buf[256];
	uint16_t parsed = 0;
	uint16_t rlen = rrset_rdata_item_size(rr, i);
	uint8_t *p = knot_rrset_get_rdata(rr, i);
	while (parsed < rlen) {
		memcpy(buf, (const char*)(p+1), *p);
		buf[*p] = '\0';
		printf("%s", buf);
		parsed += *p + 1;
		p += *p + 1;
	}
	return KNOT_EOK;
}
