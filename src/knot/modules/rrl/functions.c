/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <time.h>

#include "knot/modules/rrl/functions.h"
#include "contrib/musl/inet_ntop.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"

/* Limits (class, ipv6 remote, FIXME dname) */
#define RRL_CLSBLK_MAXLEN 16
/* CIDR block prefix lengths for v4/v6 */
#define RRL_V4_PREFIX_LEN 3 /* /24 */
#define RRL_V6_PREFIX_LEN 7 /* /56 */
/* Defaults */
#define RRL_PSIZE_LARGE 1024

/* Classification */
enum {
	CLS_NULL     = 0 << 0, /* Empty bucket. */
	CLS_NORMAL   = 1 << 0, /* Normal response. */
	CLS_ERROR    = 1 << 1, /* Error response. */
	CLS_NXDOMAIN = 1 << 2, /* NXDOMAIN (special case of error). */
	CLS_EMPTY    = 1 << 3, /* Empty response. */
	CLS_LARGE    = 1 << 4, /* Response size over threshold (1024k). */
	CLS_WILDCARD = 1 << 5, /* Wildcard query. */
	CLS_ANY      = 1 << 6, /* ANY query (spec. class). */
	CLS_DNSSEC   = 1 << 7  /* DNSSEC related RR query (spec. class) */
};

/* Classification string. */
struct cls_name {
	int code;
	const char *name;
};

static const struct cls_name rrl_cls_names[] = {
	{ CLS_NORMAL,   "POSITIVE" },
	{ CLS_ERROR,    "ERROR" },
	{ CLS_NXDOMAIN, "NXDOMAIN"},
	{ CLS_EMPTY,    "EMPTY"},
	{ CLS_LARGE,    "LARGE"},
	{ CLS_WILDCARD, "WILDCARD"},
	{ CLS_ANY,      "ANY"},
	{ CLS_DNSSEC,   "DNSSEC"},
	{ CLS_NULL,     "NULL"},
	{ CLS_NULL,     NULL}
};

static inline const char *rrl_clsstr(int code)
{
	for (const struct cls_name *c = rrl_cls_names; c->name; c++) {
		if (c->code == code) {
			return c->name;
		}
	}

	return "unknown class";
}

/* Bucket flags. */
enum {
	RRL_BF_NULL   = 0 << 0, /* No flags. */
	RRL_BF_SSTART = 1 << 0, /* Bucket in slow-start after collision. */
	RRL_BF_ELIMIT = 1 << 1  /* Bucket is rate-limited. */
};

static uint8_t rrl_clsid(rrl_req_t *p)
{
	/* Check error code */
	int ret = CLS_NULL;
	switch (knot_wire_get_rcode(p->wire)) {
	case KNOT_RCODE_NOERROR: ret = CLS_NORMAL; break;
	case KNOT_RCODE_NXDOMAIN: return CLS_NXDOMAIN; break;
	default: return CLS_ERROR; break;
	}

	/* Check if answered from a qname */
	if (ret == CLS_NORMAL && p->flags & RRL_REQ_WILDCARD) {
		return CLS_WILDCARD;
	}

	/* Check query type for spec. classes. */
	if (p->query) {
		switch(knot_pkt_qtype(p->query)) {
		case KNOT_RRTYPE_ANY:      /* ANY spec. class */
			return CLS_ANY;
			break;
		case KNOT_RRTYPE_DNSKEY:
		case KNOT_RRTYPE_RRSIG:
		case KNOT_RRTYPE_DS:      /* DNSSEC-related RR class. */
			return CLS_DNSSEC;
			break;
		default:
			break;
		}
	}

	/* Check packet size for threshold. */
	if (p->len >= RRL_PSIZE_LARGE) {
		return CLS_LARGE;
	}

	/* Check ancount */
	if (knot_wire_get_ancount(p->wire) == 0) {
		return CLS_EMPTY;
	}

	return ret;
}

static int rrl_classify(uint8_t *dst, size_t maxlen, const struct sockaddr_storage *remote,
                        rrl_req_t *req, const knot_dname_t *name)
{
	/* Class */
	uint8_t cls = rrl_clsid(req);
	*dst = cls;
	int blklen = sizeof(cls);

	/* Address (in network byteorder, adjust masks). */
	uint64_t netblk = 0;
	if (remote->ss_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)remote;
		memcpy(&netblk, &ipv6->sin6_addr, RRL_V6_PREFIX_LEN);
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)remote;
		memcpy(&netblk, &ipv4->sin_addr, RRL_V4_PREFIX_LEN);
	}
	memcpy(dst + blklen, &netblk, sizeof(netblk));
	blklen += sizeof(netblk);

	/* Name not considered anymore. */

	return blklen;
}

static void subnet_tostr(char *dst, size_t maxlen, const struct sockaddr_storage *ss)
{
	const void *addr;
	const char *suffix;

	if (ss->ss_family == AF_INET6) {
		addr = &((struct sockaddr_in6 *)ss)->sin6_addr;
		suffix = "/56";
	} else {
		addr = &((struct sockaddr_in *)ss)->sin_addr;
		suffix = "/24";
	}

	if (knot_inet_ntop(ss->ss_family, addr, dst, maxlen) != NULL) {
		strlcat(dst, suffix, maxlen);
	} else {
		dst[0] = '\0';
	}
}

static void rrl_log_state(knotd_mod_t *mod, const struct sockaddr_storage *ss,
                          uint16_t flags, uint8_t cls, const knot_dname_t *qname) // TODO remove or adapt, not used
{
	if (mod == NULL || ss == NULL) {
		return;
	}

	char addr_str[SOCKADDR_STRLEN];
	subnet_tostr(addr_str, sizeof(addr_str), ss);

	const char *what = "leaves";
	if (flags & RRL_BF_ELIMIT) {
		what = "enters";
	}

	knot_dname_txt_storage_t buf;
	char *qname_str = knot_dname_to_str(buf, qname, sizeof(buf));
	if (qname_str == NULL) {
		qname_str = "?";
	}

	knotd_mod_log(mod, LOG_NOTICE, "address/subnet %s, class %s, qname %s, %s limiting",
	              addr_str, rrl_clsstr(cls), qname_str, what);
}

rrl_table_t *rrl_create(size_t size, uint32_t rate)
{
	if (size == 0) {
		return NULL;
	}

	rrl_table_t *tbl = KRU.create(20);  // TODO set loads_bits
	if (!tbl) {
		return NULL;
	}

	return tbl;
}

int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *remote,
              rrl_req_t *req, const knot_dname_t *zone, knotd_mod_t *mod)
{
	if (!rrl || !req || !remote) {
		return KNOT_EINVAL;
	}

	struct kru_query query = {0};
	query.price = 1<<9;  // TODO set price
	assert(sizeof(query.key) >= RRL_CLSBLK_MAXLEN);
	size_t buf_len = rrl_classify(query.key, RRL_CLSBLK_MAXLEN, remote, req, zone);
	if (buf_len < 0) {
		return KNOT_ERROR;
	}

	struct timespec now_ts = {0};
	clock_gettime(CLOCK_MONOTONIC_COARSE, &now_ts);
	uint32_t now = now_ts.tv_sec * 1000 + now_ts.tv_nsec / 1000000;

	return KRU.limited(rrl, now, &query) ? KNOT_ELIMIT : KNOT_EOK;
}

bool rrl_slip_roll(int n_slip)
{
	switch (n_slip) {
	case 0:
		return false;
	case 1:
		return true;
	default:
		return (dnssec_random_uint16_t() % n_slip == 0);
	}
}

void rrl_destroy(rrl_table_t *rrl)
{
	free(rrl);
}
