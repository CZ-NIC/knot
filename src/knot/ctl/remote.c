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

#include "remote.h"
#include "common/log.h"
#include "common/fdset.h"
#include "common/prng.h"
#include "knot/common.h"
#include "knot/conf/conf.h"
#include "knot/server/socket.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/zones.h"
#include "libknot/util/wire.h"
#include "libknot/packet/query.h"
#include "libknot/packet/response.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/tsig-op.h"

#define KNOT_CTL_REALM "knot."
#define KNOT_CTL_REALM_EXT ("." KNOT_CTL_REALM)
#define KNOT_CTL_REALM_LEN 5

/*! \brief Remote command structure. */
typedef struct remote_cmdargs_t {
	const knot_rrset_t **arg;
	unsigned argc;
	knot_rcode_t rc;
} remote_cmdargs_t;

/*! \brief Callback prototype for remote commands. */
typedef int (*remote_cmdf_t)(server_t*, remote_cmdargs_t*);

/*! \brief Callback prototype for per-zone operations. */
typedef int (remote_zonef_t)(server_t*, knot_zone_t *);

/*! \brief Remote command table item. */
typedef struct remote_cmd_t {
	const char *name;
	remote_cmdf_t f;
} remote_cmd_t;

/* Forward decls. */
static int remote_c_reload(server_t *s, remote_cmdargs_t* a);
static int remote_c_refresh(server_t *s, remote_cmdargs_t* a);
static int remote_c_status(server_t *s, remote_cmdargs_t* a);
static int remote_c_flush(server_t *s, remote_cmdargs_t* a);

/*! \brief Table of remote commands. */
struct remote_cmd_t remote_cmd_tbl[] = {
	{ "reload",    &remote_c_reload },
	{ "refresh",   &remote_c_refresh },
	{ "status",    &remote_c_status },
	{ "flush",     &remote_c_flush },
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
		rcu_read_lock();
		
		/* Process all zones in data section. */
		const knot_rrset_t *rr = a->arg[i];
		if (knot_rrset_type(rr) != KNOT_RRTYPE_CNAME) {
			continue;
		}
		
		const knot_rdata_t *rd = knot_rrset_rdata(rr);
		while (rd != NULL) {
			/* Skip empty nodes. */
			if (knot_rdata_item_count(rd) < 1) {
				rd = knot_rrset_rdata_next(rr, rd);
				continue;
			}
			/* Refresh zones. */
			const knot_dname_t *dn = knot_rdata_item(rd, 0)->dname;
			zone = knot_zonedb_find_zone(ns->zone_db, dn);
			if (cb(s, zone) != KNOT_EOK) {
				a->rc = KNOT_RCODE_SERVFAIL;
			}
			rd = knot_rrset_rdata_next(rr, rd);
		}
		rcu_read_unlock();
	}
	
	return ret;
}

/*! \brief Zone refresh callback. */
static int remote_zone_refresh(server_t *s, knot_zone_t *z)
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
		                 tls_rand() * 1000);
	}
	
	return KNOT_EOK;
}

/*! \brief Zone flush callback. */
static int remote_zone_flush(server_t *s, knot_zone_t *z)
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
		                 tls_rand() * 1000);
	}
	
	return KNOT_EOK;
}

/*! \brief Helper to build RDATA from RDATA item. */
knot_rdata_t* remote_build_rdata(knot_rdata_item_t *i)
{
	/* Create RDATA. */
	knot_rdata_t *rd = knot_rdata_new();
	if (!rd) {
		return NULL;
	}
	
	/* Set RDATA items. */
	int ret = knot_rdata_set_items(rd, i, 1);
	if (ret != KNOT_EOK) {
		knot_rdata_free(&rd);
		return NULL;
	}
	
	return rd;
}

/*!
 * \brief Remote command 'reload' handler.
 *
 * QNAME: reload
 * DATA: NULL
 */
static int remote_c_reload(server_t *s, remote_cmdargs_t* a)
{
	return server_reload(s, conf()->filename);
}

/*!
 * \brief Remote command 'status' handler.
 *
 * QNAME: refresh
 * DATA: NONE
 */
static int remote_c_status(server_t *s, remote_cmdargs_t* a)
{
	/*! \todo #2035 Add some TXT RRs with stats. */
	dbg_server("remote: %s\n", __func__);
	return KNOT_EOK;
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
		dbg_server_verb("remote: flushing all zones\n");
		return KNOT_ENOTSUP;
	}
	
	/* Flush specific zones. */
	return remote_rdata_apply(s, a, &remote_zone_flush);
}

/* Public APIs. */

int remote_bind(conf_iface_t *desc)
{
	if (!desc) {
		return -1;
	}
	
	/* Create new socket. */
	int s = socket_create(desc->family, SOCK_STREAM);
	if (s < 0) {
		log_server_error("Couldn't create socket for remote "
				 "control interface - %s",
				 knot_strerror(s));
		return KNOT_ERROR;
	}
	
	/* Bind to interface and start listening. */
	int r = socket_bind(s, desc->family, desc->address, desc->port);
	if (r == KNOT_EOK) {
		r = socket_listen(s, TCP_BACKLOG_SIZE);
	}
	if (r != KNOT_EOK) {
		socket_close(s);
		log_server_error("Could not bind to "
				 "remote control interface %s port %d.\n",
				 desc->address, desc->port);
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
	if (r < 0) {
		return -1;
	}
	
	/* Wait for events. */
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(r, &rfds);
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
	ret = knot_packet_parse_rest(pkt);
	if (ret != KNOT_EOK) {
		dbg_server("remote: failed to parse packet data\n");
		return KNOT_EINVAL;
	}
	
	return ret;
}

int remote_answer(server_t *s, knot_packet_t *pkt, uint8_t* rwire, size_t *rlen)
{
	if (!s || !pkt || !rwire) {
		*rlen = 0;
		return KNOT_EINVAL;
	}
	
	/* Prerequisites:
	 * QCLASS: CH
	 * QNAME: <CMD>.KNOT_CTL_REALM.
	 */
	const knot_dname_t *qname = knot_packet_qname(pkt);
	if (knot_packet_qclass(pkt) != KNOT_CLASS_CH) {
		dbg_server("remote: qclass != CH\n");
		*rlen = 0;
		return KNOT_EMALF;
	}
	
	knot_dname_t *realm = knot_dname_new_from_str(KNOT_CTL_REALM,
	                                              KNOT_CTL_REALM_LEN, NULL);
	if (!knot_dname_is_subdomain(qname, realm) != 0) {
		dbg_server("remote: qname != *%s\n", KNOT_CTL_REALM_EXT);
		knot_dname_free(&realm);
		*rlen = 0;
		return KNOT_EMALF;
	}
	knot_dname_free(&realm);
	
	/* Command:
	 * QNAME: leftmost label of QNAME
	 */
	size_t cmd_len = knot_dname_label_size(qname, 0);
	char *cmd = strndup((char*)qname->name + 1, cmd_len);

	/* Data:
	 * NS: TSIG
	 * AR: data
	 */
	int ret = KNOT_EOK;
	remote_cmd_t *c = remote_cmd_tbl;
	remote_cmdargs_t args;
	args.arg = pkt->authority;
	args.argc = knot_packet_authority_rrset_count(pkt);
	args.rc = KNOT_RCODE_NOERROR;
	while(c->name != NULL) {
		if (strcmp(cmd, c->name) == 0) {
			ret = c->f(s, &args);
			break;
		}
		++c;
	}
	
	/* Prepare response. */
	size_t remaining = *rlen;
	knot_packet_t *resp = knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	if (!resp) {
		free(cmd);
		return ret;
	}
	uint8_t *wire = NULL;
	size_t len = 0;
	ret = knot_packet_set_max_size(resp, SOCKET_MTU_SZ);
	if (ret != KNOT_EOK)  {
		free(cmd);
		knot_packet_free(&resp);
		return ret;
	}
	ret = knot_response_init_from_query(resp, pkt, 1);
	if (ret != KNOT_EOK)  {
		free(cmd);
		knot_packet_free(&resp);
		return ret;
	}
	ret = knot_packet_to_wire(resp, &wire, &len);
	if (ret != KNOT_EOK)  {
                free(cmd);
                knot_packet_free(&resp);
                return ret;
        }
	if (len > 0) {
		memcpy(rwire, wire, len);
		*rlen = len;
	}
	knot_packet_free(&resp);
	
	/* Evaluate output. */
	int rr_count = 0;
	knot_rrset_t *rr = remote_build_rr("result.", KNOT_RRTYPE_TXT);
	knot_rdata_t *rd = remote_create_txt(knot_strerror(ret));
	knot_rrset_add_rdata(rr, rd);
		
	remaining -= *rlen;
	knot_rrset_to_wire(rr, rwire + *rlen, &remaining, &rr_count);
	knot_wire_set_nscount(rwire, 1);
	*rlen += remaining;
	knot_rrset_deep_free(&rr, 1, 1, 1);
	
	free(cmd);
	return ret;
}

int remote_process(server_t *s, int r, uint8_t* buf, size_t buflen)
{
	knot_packet_t *pkt =  knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (!pkt) {
		dbg_server("remote: not enough space to allocate query\n");
		return KNOT_ENOMEM;
	}
	
	/* Initialize remote party address. */
	rcu_read_lock();
	sockaddr_t a;
	conf_iface_t *ctl_if = conf()->ctl.iface;
	if (ctl_if) {
		sockaddr_init(&a, ctl_if->family);
	}
	rcu_read_unlock();
	
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
	if (ret == KNOT_EOK) {
		
		/* Check ACL list. */
		rcu_read_lock();
		knot_key_t *k = NULL;
		acl_key_t *m = NULL;
		knot_rcode_t ts_rc = 0;
		uint16_t ts_trc = 0;
		uint64_t ts_tmsigned = 0;
		const knot_rrset_t *tsig_rr = knot_packet_tsig(pkt);
		if (acl_match(conf()->ctl.acl, &a, &m) == ACL_DENY) {
			knot_packet_free(&pkt);
			socket_close(c);
			rcu_read_unlock();
			return KNOT_EACCES;
		}
		if (m && m->val) {
			k = ((conf_iface_t *)m->val)->key;
		}
		rcu_read_unlock();
		
		/* Check TSIG. */
		if (k) {
			if (!tsig_rr) {
				knot_packet_free(&pkt);
				socket_close(c);
				return KNOT_EACCES;
			}
			ret = zones_verify_tsig_query(pkt, k, &ts_rc,
			                              &ts_trc, &ts_tmsigned);
			if (ret != KNOT_EOK) {
				dbg_server("remote: failed to verify TSIG, "
				           "RC: %u TSIG_RC: %u\n",
				           ts_rc, ts_trc);
				knot_packet_free(&pkt);
				socket_close(c);
				return KNOT_EACCES;
			}
		}
		
		/* Answer packet. */
		wire_len = buflen;
		remote_answer(s, pkt, buf, &wire_len);
		if (wire_len > 0) {
			tcp_send(c, buf, wire_len);
		}
	}
	
	knot_packet_free(&pkt);
	socket_close(c);
	return ret;
}

knot_packet_t* remote_query(const char *query, const knot_key_t *key)
{
	if (!query) {
		return NULL;
	}
	
	knot_packet_t *qr = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
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
	knot_question_t q;
	char *qname = strcdup(query, KNOT_CTL_REALM_EXT);
	q.qname = knot_dname_new_from_str(qname, strlen(qname), 0);
	if (!q.qname) {
		knot_packet_free(&qr);
		free(qname);
		return NULL;
	}
	q.qtype = KNOT_RRTYPE_ANY;
	q.qclass = KNOT_CLASS_CH;

	/* Cannot return != KNOT_EOK, but still. */
	if (knot_query_set_question(qr, &q) != KNOT_EOK) {
		knot_packet_free(&qr);
        	free(qname);
        	return NULL;
	}

	knot_dname_release(q.qname);
	free(qname);
	
	return qr;
}

int remote_query_append(knot_packet_t *qry, knot_rrset_t *data)
{
	if (!qry || !data) {
		return KNOT_EINVAL;
	}
	
	uint8_t *sp = qry->wireformat + qry->size;
	uint8_t *np   = qry->wireformat + qry->max_size;
	uint8_t *p = sp;
	const knot_rdata_t *rd = knot_rrset_rdata(data);
	while (rd != NULL) {
		int ret = knot_query_rr_to_wire(data, rd, &p, np);
		if (ret == KNOT_EOK) {
			qry->header.nscount += 1;
		}
		rd = knot_rrset_rdata_next(data, rd);
	}

	/* Finalize packet size. */
	qry->size += (p - sp);
	return KNOT_EOK;
}


int remote_query_sign(uint8_t *wire, size_t *size, size_t maxlen,
                      const knot_key_t *key)
{
	if (!wire || !size || !key) {
		return KNOT_EINVAL;
	}
	
	size_t dlen = tsig_alg_digest_length(key->algorithm);
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
	knot_dname_t *key = remote_dname_fqdn(k);
	if (!key) {
		return NULL;
	}
	
	/* Create RRSet. */
	knot_rrset_t *rr = knot_rrset_new(key, t, KNOT_CLASS_CH, 0);
	knot_dname_release(key);
	return rr;
}

knot_rdata_t* remote_create_txt(const char *v)
{
	if (!v) {
		return NULL;
	}

	/* Create raw_data item. */
	size_t v_len = strlen(v);
	knot_rdata_item_t i;
	i.raw_data = malloc(v_len + 3);
	if (!i.raw_data) {
		return NULL;
	}
	*i.raw_data = v_len + 1;
	
	/* Write TXT item. */
	uint8_t *raw_item = (uint8_t*)(i.raw_data + 1);
	*(raw_item++) = v_len;
	memcpy(raw_item, v, v_len);
	
	knot_rdata_t *rd = remote_build_rdata(&i);
	if (!rd) {
		free(i.raw_data);
	}
	
	return rd;
}

knot_rdata_t* remote_create_cname(const char *d)
{
	if (!d) {
		return NULL;
	}

	/* Create dname item. */
	knot_rdata_item_t i;
	knot_dname_t *dn = remote_dname_fqdn(d);
	i.dname = dn;
	
	/* Build RDATA. */
	knot_rdata_t *rd = remote_build_rdata(&i);
	if (!rd) {
		knot_dname_release(dn);
	}
	
	return rd;
}

char* remote_parse_txt(const knot_rdata_t *rd)
{
	if (!rd || knot_rdata_count(rd) < 1) {
		return NULL;
	}
	
	const knot_rdata_item_t *ri = knot_rdata_item(rd, 0);
	if (!ri) {
		return NULL;
	}
	
	/* Packet parser should have already checked the packet validity. */
	uint8_t item_len = ri->raw_data[1] & 0x00ff;
	return strndup(((const char*)ri->raw_data) + 3, item_len);
}

knot_dname_t* remote_dname_fqdn(const char *k)
{
	/*! \todo #2035 knot_dname_new_from_str() should ensure final '.' */
	knot_dname_t *key = NULL;
	size_t key_len = strlen(k);
	if (k[key_len - 1] != '.') {
		char *fqdn = strcdup(k, ".");
		key = knot_dname_new_from_str(fqdn, key_len + 1, NULL);
		free(fqdn);
	} else {
		key = knot_dname_new_from_str(k, key_len, NULL);
	}
	return key;
}

