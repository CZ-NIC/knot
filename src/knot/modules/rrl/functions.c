/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "contrib/openbsd/strlcat.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"

/* Hopscotch defines. */
#define HOP_LEN (sizeof(unsigned)*8)
/* Limits (class, ipv6 remote, dname) */
#define RRL_CLSBLK_MAXLEN (1 + 8 + 255)
/* CIDR block prefix lengths for v4/v6 */
#define RRL_V4_PREFIX_LEN 3 /* /24 */
#define RRL_V6_PREFIX_LEN 7 /* /56 */
/* Defaults */
#define RRL_SSTART 2 /* 1/Nth of the rate for slow start */
#define RRL_PSIZE_LARGE 1024
#define RRL_CAPACITY 4 /* Window size in seconds */
#define RRL_LOCK_GRANULARITY 32 /* Last digit granularity */

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

static int rrl_clsname(uint8_t *dst, size_t maxlen, uint8_t cls, rrl_req_t *req,
                       const knot_dname_t *name)
{
	if (name == NULL) {
		/* Fallback for errors etc. */
		name = (const knot_dname_t *)"\x00";
	}

	switch (cls) {
	case CLS_ERROR:    /* Could be a non-existent zone or garbage. */
	case CLS_NXDOMAIN: /* Queries to non-existent names in zone. */
	case CLS_WILDCARD: /* Queries to names covered by a wildcard. */
		break;
	default:
		/* Use QNAME */
		if (req->query) {
			name = knot_pkt_qname(req->query);
		}
		break;
	}

	/* Write to wire */
	return knot_dname_to_wire(dst, name, maxlen);
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

	/* Name */
	int ret = rrl_clsname(dst + blklen, maxlen - blklen, cls, req, name);
	if (ret < 0) {
		return ret;
	}
	uint8_t len = ret;
	blklen += len;

	return blklen;
}

static int bucket_free(rrl_item_t *bucket, uint32_t now)
{
	return bucket->cls == CLS_NULL || (bucket->time + 1 < now);
}

static int bucket_match(rrl_item_t *bucket, rrl_item_t *match)
{
	return bucket->cls    == match->cls &&
	       bucket->netblk == match->netblk &&
	       bucket->qname  == match->qname;
}

static int find_free(rrl_table_t *tbl, unsigned id, uint32_t now)
{
	for (int i = id; i < tbl->size; i++) {
		if (bucket_free(&tbl->arr[i], now)) {
			return i - id;
		}
	}
	for (int i = 0; i < id; i++) {
		if (bucket_free(&tbl->arr[i], now)) {
			return i + (tbl->size - id);
		}
	}

	/* this happens if table is full... force vacate current elm */
	return id;
}

static inline unsigned find_match(rrl_table_t *tbl, uint32_t id, rrl_item_t *m)
{
	unsigned new_id = 0;
	unsigned hop = 0;
	unsigned match_bitmap = tbl->arr[id].hop;
	while (match_bitmap != 0) {
		hop = __builtin_ctz(match_bitmap); /* offset of next potential match */
		new_id = (id + hop) % tbl->size;
		if (bucket_match(&tbl->arr[new_id], m)) {
			return hop;
		} else {
			match_bitmap &= ~(1 << hop); /* clear potential match */
		}
	}

	return HOP_LEN + 1;
}

static inline unsigned reduce_dist(rrl_table_t *tbl, unsigned id, unsigned dist, unsigned *free_id)
{
	unsigned rd = HOP_LEN - 1;
	while (rd > 0) {
		unsigned vacate_id = (tbl->size + *free_id - rd) % tbl->size; /* bucket to be vacated */
		if (tbl->arr[vacate_id].hop != 0) {
			unsigned hop = __builtin_ctz(tbl->arr[vacate_id].hop);  /* offset of first valid bucket */
			if (hop < rd) { /* only offsets in <vacate_id, free_id> are interesting */
				unsigned new_id = (vacate_id + hop) % tbl->size; /* this item will be displaced to [free_id] */
				unsigned keep_hop = tbl->arr[*free_id].hop; /* unpredictable padding */
				memcpy(tbl->arr + *free_id, tbl->arr + new_id, sizeof(rrl_item_t));
				tbl->arr[*free_id].hop = keep_hop;
				tbl->arr[new_id].cls = CLS_NULL;
				tbl->arr[vacate_id].hop &= ~(1 << hop);
				tbl->arr[vacate_id].hop |= 1 << rd;
				*free_id = new_id;
				return dist - (rd - hop);
			}
		}
		--rd;
	}

	assert(rd == 0); /* this happens with p=1/fact(HOP_LEN) */
	*free_id = id;
	dist = 0; /* force vacate initial element */
	return dist;
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

	if (inet_ntop(ss->ss_family, addr, dst, maxlen) != NULL) {
		strlcat(dst, suffix, maxlen);
	} else {
		dst[0] = '\0';
	}
}

static void rrl_log_state(knotd_mod_t *mod, const struct sockaddr_storage *ss,
                          uint16_t flags, uint8_t cls, const knot_dname_t *qname)
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

static void rrl_lock(rrl_table_t *tbl, int lk_id)
{
	assert(lk_id > -1);
	pthread_mutex_lock(tbl->lk + lk_id);
}

static void rrl_unlock(rrl_table_t *tbl, int lk_id)
{
	assert(lk_id > -1);
	pthread_mutex_unlock(tbl->lk + lk_id);
}

static int rrl_setlocks(rrl_table_t *tbl, uint32_t granularity)
{
	assert(!tbl->lk); /* Cannot change while locks are used. */
	assert(granularity <= tbl->size / 10); /* Due to int. division err. */

	if (pthread_mutex_init(&tbl->ll, NULL) < 0) {
		return KNOT_ENOMEM;
	}

	/* Alloc new locks. */
	tbl->lk = malloc(granularity * sizeof(pthread_mutex_t));
	if (!tbl->lk) {
		return KNOT_ENOMEM;
	}
	memset(tbl->lk, 0, granularity * sizeof(pthread_mutex_t));

	/* Initialize. */
	for (size_t i = 0; i < granularity; ++i) {
		if (pthread_mutex_init(tbl->lk + i, NULL) < 0) {
			break;
		}
		++tbl->lk_count;
	}

	/* Incomplete initialization */
	if (tbl->lk_count != granularity) {
		for (size_t i = 0; i < tbl->lk_count; ++i) {
			pthread_mutex_destroy(tbl->lk + i);
		}
		free(tbl->lk);
		tbl->lk_count = 0;
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

rrl_table_t *rrl_create(size_t size, uint32_t rate)
{
	if (size == 0) {
		return NULL;
	}

	const size_t tbl_len = sizeof(rrl_table_t) + size * sizeof(rrl_item_t);
	rrl_table_t *tbl = calloc(1, tbl_len);
	if (!tbl) {
		return NULL;
	}
	tbl->size = size;
	tbl->rate = rate;

	if (dnssec_random_buffer((uint8_t *)&tbl->key, sizeof(tbl->key)) != DNSSEC_EOK) {
		free(tbl);
		return NULL;
	}

	if (rrl_setlocks(tbl, RRL_LOCK_GRANULARITY) != KNOT_EOK) {
		free(tbl);
		return NULL;
	}

	return tbl;
}

static knot_dname_t *buf_qname(uint8_t *buf)
{
	return buf + sizeof(uint8_t) + sizeof(uint64_t);
}

/*! \brief Get bucket for current combination of parameters. */
static rrl_item_t *rrl_hash(rrl_table_t *tbl, const struct sockaddr_storage *remote,
                            rrl_req_t *req, const knot_dname_t *zone, uint32_t stamp,
                            int *lock, uint8_t *buf, size_t buf_len)
{
	int len = rrl_classify(buf, buf_len, remote, req, zone);
	if (len < 0) {
		return NULL;
	}

	uint32_t id = SipHash24(&tbl->key, buf, len) % tbl->size;

	/* Lock for lookup. */
	pthread_mutex_lock(&tbl->ll);

	/* Find an exact match in <id, id + HOP_LEN). */
	knot_dname_t *qname = buf_qname(buf);
	uint64_t netblk;
	memcpy(&netblk, buf + sizeof(uint8_t), sizeof(netblk));
	rrl_item_t match = {
		.hop = 0,
		.netblk = netblk,
		.ntok = tbl->rate * RRL_CAPACITY,
		.cls = buf[0],
		.flags = RRL_BF_NULL,
		.qname = SipHash24(&tbl->key, qname, knot_dname_size(qname)),
		.time = stamp
	};

	unsigned dist = find_match(tbl, id, &match);
	if (dist > HOP_LEN) { /* not an exact match, find free element [f] */
		dist = find_free(tbl, id, stamp);
	}

	/* Reduce distance to fit <id, id + HOP_LEN) */
	unsigned free_id = (id + dist) % tbl->size;
	while (dist >= HOP_LEN) {
		dist = reduce_dist(tbl, id, dist, &free_id);
	}

	/* Assign granular lock and unlock lookup. */
	*lock = free_id % tbl->lk_count;
	rrl_lock(tbl, *lock);
	pthread_mutex_unlock(&tbl->ll);

	/* found free bucket which is in <id, id + HOP_LEN) */
	tbl->arr[id].hop |= (1 << dist);
	rrl_item_t *bucket = &tbl->arr[free_id];
	assert(free_id == (id + dist) % tbl->size);

	/* Inspect bucket state. */
	unsigned hop = bucket->hop;
	if (bucket->cls == CLS_NULL) {
		memcpy(bucket, &match, sizeof(rrl_item_t));
		bucket->hop = hop;
	}
	/* Check for collisions. */
	if (!bucket_match(bucket, &match)) {
		if (!(bucket->flags & RRL_BF_SSTART)) {
			memcpy(bucket, &match, sizeof(rrl_item_t));
			bucket->hop = hop;
			bucket->ntok = tbl->rate + tbl->rate / RRL_SSTART;
			bucket->flags |= RRL_BF_SSTART;
		}
	}

	return bucket;
}

int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *remote,
              rrl_req_t *req, const knot_dname_t *zone, knotd_mod_t *mod)
{
	if (!rrl || !req || !remote) {
		return KNOT_EINVAL;
	}

	uint8_t buf[RRL_CLSBLK_MAXLEN];

	/* Calculate hash and fetch */
	int ret = KNOT_EOK;
	int lock = -1;
	uint32_t now = time_now().tv_sec;
	rrl_item_t *bucket = rrl_hash(rrl, remote, req, zone, now, &lock, buf, sizeof(buf));
	if (!bucket) {
		if (lock > -1) {
			rrl_unlock(rrl, lock);
		}
		return KNOT_ERROR;
	}

	/* Calculate rate for dT */
	uint32_t dt = now - bucket->time;
	if (dt > RRL_CAPACITY) {
		dt = RRL_CAPACITY;
	}
	/* Visit bucket. */
	bucket->time = now;
	if (dt > 0) { /* Window moved. */

		/* Check state change. */
		if ((bucket->ntok > 0 || dt > 1) && (bucket->flags & RRL_BF_ELIMIT)) {
			bucket->flags &= ~RRL_BF_ELIMIT;
			rrl_log_state(mod, remote, bucket->flags, bucket->cls,
			              knot_pkt_qname(req->query));
		}

		/* Add new tokens. */
		uint32_t dn = rrl->rate * dt;
		if (bucket->flags & RRL_BF_SSTART) { /* Bucket in slow-start. */
			bucket->flags &= ~RRL_BF_SSTART;
		}
		bucket->ntok += dn;
		if (bucket->ntok > RRL_CAPACITY * rrl->rate) {
			bucket->ntok = RRL_CAPACITY * rrl->rate;
		}
	}

	/* Last item taken. */
	if (bucket->ntok == 1 && !(bucket->flags & RRL_BF_ELIMIT)) {
		bucket->flags |= RRL_BF_ELIMIT;
		rrl_log_state(mod, remote, bucket->flags, bucket->cls,
		              knot_pkt_qname(req->query));
	}

	/* Decay current bucket. */
	if (bucket->ntok > 0) {
		--bucket->ntok;
	} else if (bucket->ntok == 0) {
		ret = KNOT_ELIMIT;
	}

	if (lock > -1) {
		rrl_unlock(rrl, lock);
	}
	return ret;
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
	if (rrl) {
		if (rrl->lk_count > 0) {
			pthread_mutex_destroy(&rrl->ll);
		}
		for (size_t i = 0; i < rrl->lk_count; ++i) {
			pthread_mutex_destroy(rrl->lk + i);
		}
		free(rrl->lk);
	}

	free(rrl);
}
