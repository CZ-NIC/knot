/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "libdnssec/error.h"
#include "libdnssec/random.h"

/* Hopscotch defines. */
#define HOP_LEN (sizeof(unsigned)*8)
/* Limits */
#define RRL_CLSBLK_MAXLEN (4 + 8 + 1 + 256)
/* CIDR block prefix lengths for v4/v6 */
#define RRL_V4_PREFIX ((uint32_t)0x00ffffff)         /* /24 */
#define RRL_V6_PREFIX ((uint64_t)0x00ffffffffffffff) /* /56 */
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
	switch (knot_wire_get_rcode(p->w)) {
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
	if (knot_wire_get_ancount(p->w) == 0) {
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
		netblk = *((uint64_t *)(&ipv6->sin6_addr)) & RRL_V6_PREFIX;
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)remote;
		netblk = ((uint32_t)ipv4->sin_addr.s_addr) & RRL_V4_PREFIX;
	}
	if (blklen + sizeof(netblk) > maxlen) {
		return KNOT_ESPACE;
	}
	memcpy(dst + blklen, (void *)&netblk, sizeof(netblk));
	blklen += sizeof(netblk);

	/* Name */
	uint16_t *len_pos = (uint16_t *)(dst + blklen);
	blklen += sizeof(uint16_t);
	int ret = rrl_clsname(dst + blklen, maxlen - blklen, cls, req, name);
	if (ret < 0) {
		return ret;
	}
	uint16_t len = ret;
	memcpy(len_pos, &len, sizeof(len));
	blklen += len;

	return blklen;
}

static int bucket_free(rrl_item_t *b, uint32_t now)
{
	return b->cls == CLS_NULL || (b->time + 1 < now);
}

static int bucket_match(rrl_item_t *b, rrl_item_t *m)
{
	return b->cls    == m->cls &&
	       b->netblk == m->netblk &&
	       b->qname  == m->qname;
}

static int find_free(rrl_table_t *tbl, unsigned i, uint32_t now)
{
	rrl_item_t *np = tbl->arr + tbl->size;
	rrl_item_t *b = NULL;
	for (b = tbl->arr + i; b != np; ++b) {
		if (bucket_free(b, now)) {
			return b - (tbl->arr + i);
		}
	}
	np = tbl->arr + i;
	for (b = tbl->arr; b != np; ++b) {
		if (bucket_free(b, now)) {
			return (b - tbl->arr) + (tbl->size - i);
		}
	}

	/* this happens if table is full... force vacate current elm */
	return i;
}

static inline unsigned find_match(rrl_table_t *tbl, uint32_t id, rrl_item_t *m)
{
	unsigned f = 0;
	unsigned d = 0;
	unsigned match = tbl->arr[id].hop;
	while (match != 0) {
		d = __builtin_ctz(match);
		f = (id + d) % tbl->size;
		if (bucket_match(tbl->arr + f, m)) {
			return d;
		} else {
			match &= ~(1<<d); /* clear potential match */
		}
	}

	return HOP_LEN + 1;
}

static inline unsigned reduce_dist(rrl_table_t *tbl, unsigned id, unsigned d, unsigned *f)
{
	unsigned rd = HOP_LEN - 1;
	while (rd > 0) {
		unsigned s = (tbl->size + *f - rd) % tbl->size; /* bucket to be vacated */
		if (tbl->arr[s].hop != 0) {
			unsigned o = __builtin_ctz(tbl->arr[s].hop);  /* offset of first valid bucket */
			if (o < rd) {                               /* only offsets in <s, f> are interesting */
				unsigned e = (s + o) % tbl->size;     /* this item will be displaced to [f] */
				unsigned keep_hop = tbl->arr[*f].hop; /* unpredictable padding */
				memcpy(tbl->arr + *f, tbl->arr + e, sizeof(rrl_item_t));
				tbl->arr[*f].hop = keep_hop;
				tbl->arr[e].cls = CLS_NULL;
				tbl->arr[s].hop &= ~(1<<o);
				tbl->arr[s].hop |= 1<<rd;
				*f = e;
				return d - (rd - o);
			}
		}
		--rd;
	}

	assert(rd == 0); /* this happens with p=1/fact(HOP_LEN) */
	*f = id;
	d = 0; /* force vacate initial element */
	return d;
}

static void rrl_log_state(knotd_mod_t *mod, const struct sockaddr_storage *ss,
                          uint16_t flags, uint8_t cls)
{
	if (mod == NULL) {
		return;
	}

	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)ss);

	const char *what = "leaves";
	if (flags & RRL_BF_ELIMIT) {
		what = "enters";
	}

	knotd_mod_log(mod, LOG_NOTICE, "address %s, class %s, %s limiting",
	              addr_str, rrl_clsstr(cls), what);
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

/*! \brief Get bucket for current combination of parameters. */
static rrl_item_t *rrl_hash(rrl_table_t *tbl, const struct sockaddr_storage *remote,
                            rrl_req_t *req, const knot_dname_t *zone, uint32_t stamp,
                            int *lock)
{
	uint8_t buf[RRL_CLSBLK_MAXLEN];
	int len = rrl_classify(buf, sizeof(buf), remote, req, zone);
	if (len < 0) {
		return NULL;
	}

	uint32_t id = SipHash24(&tbl->key, buf, len) % tbl->size;

	/* Lock for lookup. */
	pthread_mutex_lock(&tbl->ll);

	/* Find an exact match in <id, id + HOP_LEN). */
	uint8_t *qname = buf + sizeof(uint8_t) + sizeof(uint64_t);
	uint64_t netblk;
	memcpy(&netblk, buf + sizeof(uint8_t), sizeof(netblk));
	rrl_item_t match = {
		.hop = 0,
		.netblk = netblk,
		.ntok = tbl->rate * RRL_CAPACITY,
		.cls = buf[0],
		.flags = RRL_BF_NULL,
		.qname = SipHash24(&tbl->key, qname + 1, qname[0]),
		.time = stamp
	};

	unsigned d = find_match(tbl, id, &match);
	if (d > HOP_LEN) { /* not an exact match, find free element [f] */
		d = find_free(tbl, id, stamp);
	}

	/* Reduce distance to fit <id, id + HOP_LEN) */
	unsigned f = (id + d) % tbl->size;
	while (d >= HOP_LEN) {
		d = reduce_dist(tbl, id, d, &f);
	}

	/* Assign granular lock and unlock lookup. */
	*lock = f % tbl->lk_count;
	rrl_lock(tbl, *lock);
	pthread_mutex_unlock(&tbl->ll);

	/* found free elm 'k' which is in <id, id + HOP_LEN) */
	tbl->arr[id].hop |= (1 << d);
	rrl_item_t *b = tbl->arr + f;
	assert(f == (id+d) % tbl->size);

	/* Inspect bucket state. */
	unsigned hop = b->hop;
	if (b->cls == CLS_NULL) {
		memcpy(b, &match, sizeof(rrl_item_t));
		b->hop = hop;
	}
	/* Check for collisions. */
	if (!bucket_match(b, &match)) {
		if (!(b->flags & RRL_BF_SSTART)) {
			memcpy(b, &match, sizeof(rrl_item_t));
			b->hop = hop;
			b->ntok = tbl->rate + tbl->rate / RRL_SSTART;
			b->flags |= RRL_BF_SSTART;
		}
	}

	return b;
}

int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *remote,
              rrl_req_t *req, const knot_dname_t *zone, knotd_mod_t *mod)
{
	if (!rrl || !req || !remote) {
		return KNOT_EINVAL;
	}

	/* Calculate hash and fetch */
	int ret = KNOT_EOK;
	int lock = -1;
	uint32_t now = time_now().tv_sec;
	rrl_item_t *bucket = rrl_hash(rrl, remote, req, zone, now, &lock);
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
			rrl_log_state(mod, remote, bucket->flags, bucket->cls);
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
		rrl_log_state(mod, remote, bucket->flags, bucket->cls);
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
	/* Now n_slip means every Nth answer slips.
	 * That represents a chance of 1/N that answer slips.
	 * Therefore, on average, from 100 answers 100/N will slip. */
	int threshold = RRL_SLIP_MAX / n_slip;
	int roll = dnssec_random_uint16_t() % RRL_SLIP_MAX;
	return (roll < threshold);
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
