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
#include <time.h>

#include "dnssec/random.h"
#include "knot/common/log.h"
#include "knot/server/rrl.h"
#include "knot/zone/zone.h"
#include "libknot/libknot.h"
#include "contrib/murmurhash3/murmurhash3.h"
#include "contrib/sockaddr.h"

/* Hopscotch defines. */
#define HOP_LEN (sizeof(unsigned)*8)
/* Limits */
#define RRL_CLSBLK_MAXLEN (4 + 8 + 1 + 256)
/* CIDR block prefix lengths for v4/v6 */
#define RRL_V4_PREFIX ((uint32_t)0x00ffffff)         /* /24 */
#define RRL_V6_PREFIX ((uint64_t)0x00ffffffffffffff) /* /56 */
/* Defaults */
#define RRL_DEFAULT_RATE 100
#define RRL_CAPACITY 4 /* N seconds. */
#define RRL_SSTART 2 /* 1/Nth of the rate for slow start */
#define RRL_PSIZE_LARGE 1024
/* Enable RRL logging. */
#define RRL_ENABLE_LOG

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
        {CLS_NORMAL,  "POSITIVE" },
        {CLS_ERROR,   "ERROR" },
        {CLS_NXDOMAIN,"NXDOMAIN"},
        {CLS_EMPTY,   "EMPTY"},
        {CLS_LARGE,   "LARGE"},
        {CLS_WILDCARD,"WILDCARD"},
        {CLS_ANY,     "ANY"},
        {CLS_DNSSEC,  "DNSSEC"},
        {CLS_NULL,    "NULL"},
        {CLS_NULL,    NULL}
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
	if (ret == CLS_NORMAL && p->flags & RRL_WILDCARD) {
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

static int rrl_clsname(char *dst, size_t maxlen, uint8_t cls,
                       rrl_req_t *req, const zone_t *zone)
{
	/* Fallback zone (for errors etc.) */
	const knot_dname_t *dn = (const knot_dname_t *)"\x00";

	/* Found associated zone. */
	if (zone != NULL) {
		dn = zone->name;
	} else if (req->name != NULL) {
		dn = req->name;
	}

	switch (cls) {
	case CLS_ERROR:    /* Could be a non-existent zone or garbage. */
	case CLS_NXDOMAIN: /* Queries to non-existent names in zone. */
	case CLS_WILDCARD: /* Queries to names covered by a wildcard. */
		break;
	default:
		/* Use QNAME */
		if (req->query) {
			dn = knot_pkt_qname(req->query);
		}
		break;
	}

	/* Write to wire */
	return knot_dname_to_wire((uint8_t *)dst, dn, maxlen);
}

static int rrl_classify(char *dst, size_t maxlen, const struct sockaddr_storage *a,
                        rrl_req_t *p, const zone_t *z, uint32_t seed)
{
	if (!dst || !p || !a || maxlen == 0) {
		return KNOT_EINVAL;
	}

	/* Class */
	uint8_t cls = rrl_clsid(p);
	*dst = cls;
	int blklen = sizeof(cls);

	/* Address (in network byteorder, adjust masks). */
	uint64_t nb = 0;
	if (a->ss_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)a;
		nb = *((uint64_t *)(&ipv6->sin6_addr)) & RRL_V6_PREFIX;
	} else {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)a;
		nb = ((uint32_t)ipv4->sin_addr.s_addr) & RRL_V4_PREFIX;
	}
	if (blklen + sizeof(nb) > maxlen) {
		return KNOT_ESPACE;
	}
	memcpy(dst + blklen, (void *)&nb, sizeof(nb));
	blklen += sizeof(nb);

	/* Name */
	uint16_t *nlen = (uint16_t *)(dst + blklen);
	blklen += sizeof(uint16_t);
	int len = rrl_clsname(dst + blklen, maxlen - blklen, cls, p, z);
	if (len < 0) {
		return len;
	}
	*nlen = len;
	blklen += len;

	/* Seed. */
	if (blklen + sizeof(seed) > maxlen) {
		return KNOT_ESPACE;
	}
	memcpy(dst + blklen, (void *)&seed, sizeof(seed));
	blklen += sizeof(seed);

	return blklen;
}

static int bucket_free(rrl_item_t *b, uint32_t now) {
	return b->cls == CLS_NULL || (b->time + 1 < now);
}

static int bucket_match(rrl_item_t *b, rrl_item_t *m)
{
	return b->cls    == m->cls &&
	       b->netblk == m->netblk &&
	       b->qname  == m->qname;
}

static int find_free(rrl_table_t *t, unsigned i, uint32_t now)
{
	rrl_item_t *np = t->arr + t->size;
	rrl_item_t *b = NULL;
	for (b = t->arr + i; b != np; ++b) {
		if (bucket_free(b, now)) {
			return b - (t->arr + i);
		}
	}
	np = t->arr + i;
	for (b = t->arr; b != np; ++b) {
		if (bucket_free(b, now)) {
			return (b - t->arr) + (t->size - i);
		}
	}

	/* this happens if table is full... force vacate current elm */
	return i;
}

static inline unsigned find_match(rrl_table_t *t, uint32_t id, rrl_item_t *m)
{
	unsigned f = 0;
	unsigned d = 0;
	unsigned match = t->arr[id].hop;
	while (match != 0) {
		d = __builtin_ctz(match);
		f = (id + d) % t->size;
		if (bucket_match(t->arr + f, m)) {
			return d;
		} else {
			match &= ~(1<<d); /* clear potential match */
		}
	}

	return HOP_LEN + 1;
}

static inline unsigned reduce_dist(rrl_table_t *t, unsigned id, unsigned d, unsigned *f)
{
	unsigned rd = HOP_LEN - 1;
	while (rd > 0) {
		unsigned s = (t->size + *f - rd) % t->size; /* bucket to be vacated */
		unsigned o = __builtin_ctz(t->arr[s].hop); /* offset of first valid bucket */
		if (t->arr[s].hop != 0 && o < rd) {        /* only offsets in <s, f> are interesting */
			unsigned e = (s + o) % t->size;    /* this item will be displaced to [f] */
			unsigned keep_hop = t->arr[*f].hop; /* unpredictable padding */
			memcpy(t->arr + *f, t->arr + e, sizeof(rrl_item_t));
			t->arr[*f].hop = keep_hop;
			t->arr[e].cls = CLS_NULL;
			t->arr[s].hop &= ~(1<<o);
			t->arr[s].hop |= 1<<rd;
			*f = e;
			return d - (rd - o);
		}
		--rd;
	}

	assert(rd == 0); /* this happens with p=1/fact(HOP_LEN) */
	*f = id;
	d = 0; /* force vacate initial element */
	return d;
}

static void rrl_log_state(const struct sockaddr_storage *ss, uint16_t flags, uint8_t cls)
{
#ifdef RRL_ENABLE_LOG
	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)ss);

	const char *what = "leaves";
	if (flags & RRL_BF_ELIMIT) {
		what = "enters";
	}

	log_notice("rate limiting, address '%s' class '%s' %s limiting",
	           addr_str, rrl_clsstr(cls), what);
#endif
}

rrl_table_t *rrl_create(size_t size)
{
	if (size == 0) {
		return NULL;
	}

	const size_t tbl_len = sizeof(rrl_table_t) + size * sizeof(rrl_item_t);
	rrl_table_t *t = malloc(tbl_len);
	if (!t) {
		return NULL;
	}
	memset(t, 0, sizeof(rrl_table_t));
	t->size = size;
	rrl_reseed(t);

	return t;
}

uint32_t rrl_setrate(rrl_table_t *rrl, uint32_t rate)
{
	if (!rrl) {
		return 0;
	}
	uint32_t old = rrl->rate;
	rrl->rate = rate;
	return old;
}

uint32_t rrl_rate(rrl_table_t *rrl)
{
	return rrl ? rrl->rate : 0;
}

int rrl_setlocks(rrl_table_t *rrl, unsigned granularity)
{
	if (!rrl) {
		return KNOT_EINVAL;
	}

	assert(!rrl->lk); /* Cannot change while locks are used. */
	assert(granularity <= rrl->size / 10); /* Due to int. division err. */

	if (pthread_mutex_init(&rrl->ll, NULL) < 0) {
		return KNOT_ENOMEM;
	}

	/* Alloc new locks. */
	rrl->lk = malloc(granularity * sizeof(pthread_mutex_t));
	if (!rrl->lk) {
		return KNOT_ENOMEM;
	}
	memset(rrl->lk, 0, granularity * sizeof(pthread_mutex_t));

	/* Initialize. */
	for (size_t i = 0; i < granularity; ++i) {
		if (pthread_mutex_init(rrl->lk + i, NULL) < 0) {
			break;
		}
		++rrl->lk_count;
	}

	/* Incomplete initialization */
	if (rrl->lk_count != granularity) {
		for (size_t i = 0; i < rrl->lk_count; ++i) {
			pthread_mutex_destroy(rrl->lk + i);
		}
		free(rrl->lk);
		rrl->lk_count = 0;
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

rrl_item_t *rrl_hash(rrl_table_t *t, const struct sockaddr_storage *a, rrl_req_t *p,
                     const zone_t *zone, uint32_t stamp, int *lock)
{
	char buf[RRL_CLSBLK_MAXLEN];
	int len = rrl_classify(buf, sizeof(buf), a, p, zone, t->seed);
	if (len < 0) {
		return NULL;
	}

	uint32_t id = hash(buf, len) % t->size;

	/* Lock for lookup. */
	pthread_mutex_lock(&t->ll);

	/* Find an exact match in <id, id + HOP_LEN). */
	uint16_t *qname = (uint16_t *)(buf + sizeof(uint8_t) + sizeof(uint64_t));
	rrl_item_t match = {
	        0, *((uint64_t *)(buf + 1)), t->rate,    /* hop, netblk, ntok */
	        buf[0], RRL_BF_NULL,                     /* cls, flags */
	        hash((char *)(qname + 1), *qname), stamp /* qname, time */
	};

	unsigned d = find_match(t, id, &match);
	if (d > HOP_LEN) { /* not an exact match, find free element [f] */
		d = find_free(t, id, stamp);
	}

	/* Reduce distance to fit <id, id + HOP_LEN) */
	unsigned f = (id + d) % t->size;
	while (d >= HOP_LEN) {
		d = reduce_dist(t, id, d, &f);
	}

	/* Assign granular lock and unlock lookup. */
	*lock = f % t->lk_count;
	rrl_lock(t, *lock);
	pthread_mutex_unlock(&t->ll);

	/* found free elm 'k' which is in <id, id + HOP_LEN) */
	t->arr[id].hop |= (1 << d);
	rrl_item_t *b = t->arr + f;
	assert(f == (id+d) % t->size);

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
			b->ntok = t->rate + t->rate / RRL_SSTART;
			b->flags |= RRL_BF_SSTART;
		}
	}

	return b;
}

int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *a, rrl_req_t *req,
              const zone_t *zone)
{
	if (!rrl || !req || !a) {
		return KNOT_EINVAL;
	}

	/* Calculate hash and fetch */
	int ret = KNOT_EOK;
	int lock = -1;
	uint32_t now = time(NULL);
	rrl_item_t *b = rrl_hash(rrl, a, req, zone, now, &lock);
	if (!b) {
		if (lock > -1) {
			rrl_unlock(rrl, lock);
		}
		return KNOT_ERROR;
	}

	/* Calculate rate for dT */
	uint32_t dt = now - b->time;
	if (dt > RRL_CAPACITY) {
		dt = RRL_CAPACITY;
	}
	/* Visit bucket. */
	b->time = now;
	if (dt > 0) { /* Window moved. */

		/* Check state change. */
		if ((b->ntok > 0 || dt > 1) && (b->flags & RRL_BF_ELIMIT)) {
			b->flags &= ~RRL_BF_ELIMIT;
			rrl_log_state(a, b->flags, b->cls);
		}

		/* Add new tokens. */
		uint32_t dn = rrl->rate * dt;
		if (b->flags & RRL_BF_SSTART) { /* Bucket in slow-start. */
			b->flags &= ~RRL_BF_SSTART;
		}
		b->ntok += dn;
		if (b->ntok > RRL_CAPACITY * rrl->rate) {
			b->ntok = RRL_CAPACITY * rrl->rate;
		}
	}

	/* Last item taken. */
	if (b->ntok == 1 && !(b->flags & RRL_BF_ELIMIT)) {
		b->flags |= RRL_BF_ELIMIT;
		rrl_log_state(a, b->flags, b->cls);
	}

	/* Decay current bucket. */
	if (b->ntok > 0) {
		--b->ntok;
	} else if (b->ntok == 0) {
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

int rrl_destroy(rrl_table_t *rrl)
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
	return KNOT_EOK;
}

int rrl_reseed(rrl_table_t *rrl)
{
	/* Lock entire table. */
	if (rrl->lk_count > 0) {
		pthread_mutex_lock(&rrl->ll);
		for (unsigned i = 0; i < rrl->lk_count; ++i) {
			rrl_lock(rrl, i);
		}
	}

	memset(rrl->arr, 0, rrl->size * sizeof(rrl_item_t));
	rrl->seed = dnssec_random_uint32_t();

	if (rrl->lk_count > 0) {
		for (unsigned i = 0; i < rrl->lk_count; ++i) {
			rrl_unlock(rrl, i);
		}
		pthread_mutex_unlock(&rrl->ll);
	}

	return KNOT_EOK;
}

int rrl_lock(rrl_table_t *t, int lk_id)
{
	assert(lk_id > -1);
	if (pthread_mutex_lock(t->lk + lk_id) != 0) {
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}

int rrl_unlock(rrl_table_t *t, int lk_id)
{
	assert(lk_id > -1);
	if (pthread_mutex_unlock(t->lk + lk_id)!= 0) {
		return KNOT_ERROR;
	}
	return KNOT_EOK;
}
