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

#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>

#include "knot/server/rrl.h"
#include "knot/common.h"
#include "libknot/consts.h"
#include "libknot/util/wire.h"
#include "common/hattrie/murmurhash3.h"
#include "common/prng.h"
#include "common/errors.h"

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

/* RRL granular locking. */
static int rrl_lock_mx(rrl_table_t *t, int lk_id)
{
	assert(lk_id > -1);
	dbg_rrl_verb("%s: locking id '%d'\n", __func__, lk_id);
	return pthread_mutex_lock(&t->lk[lk_id].mx);
}

static int rrl_unlock_mx(rrl_table_t *t, int lk_id)
{
	assert(lk_id > -1);
	dbg_rrl_verb("%s: unlocking id '%d'\n", __func__, lk_id);
	return pthread_mutex_unlock(&t->lk[lk_id].mx);
}

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
const error_table_t rrl_clsstr_tbl[] = {
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
	return error_to_str(rrl_clsstr_tbl, code);
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
	if (ret == CLS_NORMAL && p->flags & KNOT_PF_WILDCARD) {
		return CLS_WILDCARD;
	}
	
	/* Check query type for spec. classes. */
	if (p->qst) {
		switch(p->qst->qtype) {
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
                       rrl_req_t *p, const knot_zone_t *z)
{
	const knot_dname_t *dn = NULL;
	const uint8_t *n = (const uint8_t*)"\x00"; /* Fallback zone (for errors etc.) */
	int nb = 1;
	if (z) { /* Found associated zone. */
		dn = knot_zone_name(z);
	}
	switch (cls) {
	case CLS_ERROR:    /* Could be a non-existent zone or garbage. */
	case CLS_NXDOMAIN: /* Queries to non-existent names in zone. */
	case CLS_WILDCARD: /* Queries to names covered by a wildcard. */
		dbg_rrl_verb("%s: using zone/fallback name\n", __func__);
		break;
	default:
		if (p->qst) dn = p->qst->qname;
		break;
	}
	
	if (dn) { /* Check used dname. */
		assert(dn); /* Should be always set. */
		n = knot_dname_name(dn);
		nb = (int)knot_dname_size(dn);
	}
	
	/* Write to wire */
	if (nb > maxlen) return KNOT_ESPACE;
	if (memcpy(dst, n, nb) == NULL) {
		dbg_rrl("%s: failed to serialize name=%p len=%u\n",
		        __func__, n, nb);
		return KNOT_ERROR;
	}
	
	return nb;
}

static int rrl_classify(char *dst, size_t maxlen, const sockaddr_t *a,
                        rrl_req_t *p, const knot_zone_t *z, uint32_t seed)
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
	if (a->family == AF_INET6) { /* Take the /56 prefix. */
		nb = *((uint64_t*)&a->addr6.sin6_addr) & RRL_V6_PREFIX;
	} else {                     /* Take the /24 prefix */
		nb = (uint32_t)a->addr4.sin_addr.s_addr & RRL_V4_PREFIX;
	}
	if (blklen + sizeof(nb) > maxlen) return KNOT_ESPACE;
	memcpy(dst + blklen, (void*)&nb, sizeof(nb));
	blklen += sizeof(nb);

	/* Name */
	int len = rrl_clsname(dst + blklen, maxlen - blklen, cls, p, z);
	if (len < 0) return len;
	blklen += len;
	
	/* Seed. */
	if (blklen + sizeof(seed) > maxlen) return KNOT_ESPACE;
	if (memcpy(dst + blklen, (void*)&seed, sizeof(seed)) == 0) {
		blklen += sizeof(seed);
	}
	
	return blklen;
}

static rrl_item_t* rrl_hash(rrl_table_t *t, const sockaddr_t *a, rrl_req_t *p,
                            const knot_zone_t *zone, uint32_t stamp, int *lk)
{
	char buf[RRL_CLSBLK_MAXLEN];
	int len = rrl_classify(buf, sizeof(buf), a, p, zone, t->seed);
	if (len < 0) {
		return NULL;
	}
	
	uint32_t id = hash(buf, len) % t->size;
	
	/* Check locking. */
	*lk = -1;
	if (t->lk_count > 0) {
		*lk = id % t->lk_count;
		rrl_lock_mx(t, *lk);
	}
	
	rrl_item_t *b = t->arr + id;
	dbg_rrl("%s: classified pkt as '0x%x' bucket=%p\n", __func__, id, b);

	/* Inspect bucket state. */
	uint64_t nprefix = *((uint64_t*)(buf + sizeof(uint8_t)));
	if (b->cls == CLS_NULL) {
		b->cls = *buf; /* Stored as a first byte in clsblock. */
		b->flags = RRL_BF_NULL;
		b->ntok = t->rate;
		b->time = stamp;
		b->pref = nprefix; /* Invalidate */
	}
	/* Check for collisions. */
	if (b->pref != nprefix) {
		dbg_rrl("%s: collision in bucket '0x%4x'\n", __func__, id);
		if (!(b->flags & RRL_BF_SSTART)) {
			b->pref = nprefix;
			b->cls = *buf;
			b->flags = RRL_BF_NULL; /* Reset flags. */
			b->time = stamp; /* Reset time */
			b->ntok = t->rate / RRL_SSTART;
			b->flags |= RRL_BF_SSTART;
			dbg_rrl("%s: bucket '0x%4x' slow-start\n", __func__, id);
		}
	}
	
	return b;
}

static void rrl_log_state(const sockaddr_t *a, uint16_t flags, uint8_t cls)
{
#ifdef RRL_ENABLE_LOG
	char saddr[SOCKADDR_STRLEN];
	memset(saddr, 0, sizeof(saddr));
	sockaddr_tostr(a, saddr, sizeof(saddr));
	const char *what = "leaves";
	if (flags & RRL_BF_ELIMIT) {
		what = "enters";
	}
	
	log_server_notice("Address '%s' %s rate-limiting (class '%s').\n",
	                  saddr, what, rrl_clsstr(cls));
#endif
}

rrl_table_t *rrl_create(size_t size)
{
	const size_t tbl_len = sizeof(rrl_table_t) + size * sizeof(rrl_item_t);
	rrl_table_t *t = malloc(tbl_len);
	if (!t) return NULL;
	
	memset(t, 0, tbl_len);
	t->rate = 0;
	t->seed = (uint32_t)(tls_rand() * (double)UINT32_MAX);
	t->size = size;
	dbg_rrl("%s: created table size '%zu'\n", __func__, t->size);
	return t;
}

uint32_t rrl_setrate(rrl_table_t *rrl, uint32_t rate)
{
	if (!rrl) return 0;
	uint32_t old = rrl->rate;
	rrl->rate = rate;
	return old;
}

uint32_t rrl_rate(rrl_table_t *rrl)
{
	if (!rrl) return 0;
	return rrl->rate;
}

int rrl_setlocks(rrl_table_t *rrl, size_t granularity)
{
	if (!rrl) return KNOT_EINVAL;
	assert(!rrl->lk); /* Cannot change while locks are used. */
	
	/* Alloc new locks. */
	rrl->lk = malloc(granularity * sizeof(rrl_lock_t));
	if (!rrl->lk) return KNOT_ENOMEM;
	memset(rrl->lk, 0, granularity * sizeof(rrl_lock_t));
	
	/* Initialize. */
	for (size_t i = 0; i < granularity; ++i) {
		if (pthread_mutex_init(&rrl->lk[i].mx, NULL) < 0) break;
		++rrl->lk_count;
	}
	/* Incomplete initialization */
	if (rrl->lk_count != granularity) {
		for (size_t i = 0; i < rrl->lk_count; ++i) {
			pthread_mutex_destroy(&rrl->lk[i].mx);
		}
		free(rrl->lk);
		rrl->lk_count = 0;
		dbg_rrl("%s: failed to init locks\n", __func__);
		return KNOT_ERROR;
	}
	
	dbg_rrl("%s: set granularity to '%zu'\n", __func__, granularity);
	return KNOT_EOK;
}

int rrl_query(rrl_table_t *rrl, const sockaddr_t *a, rrl_req_t *req,
              const knot_zone_t *zone)
{
	if (!rrl || !req || !a) return KNOT_EINVAL;
	
	/* Calculate hash and fetch */
	int ret = KNOT_EOK;
	int lock = -1;
	uint32_t now = time(NULL);
	rrl_item_t *b = rrl_hash(rrl, a, req, zone, now, &lock);
	if (!b) {
		assert(lock < 0);
		dbg_rrl("%s: failed to compute bucket from packet\n", __func__);
		return KNOT_ERROR;
	}
	
	/* Calculate rate for dT */
	uint32_t dt = now - b->time;
	if (dt > RRL_CAPACITY) {
		dt = RRL_CAPACITY;
	}
	/* Visit bucket. */
	b->time = now;
	dbg_rrl("%s: bucket=0x%x tokens=%hu flags=%x dt=%u\n",
	        __func__, (unsigned)(b - rrl->arr), b->ntok, b->flags, dt);
	if (dt > 0) { /* Window moved. */

		/* Check state change. */
		if ((b->ntok > 0 || dt > 1) && (b->flags & RRL_BF_ELIMIT)) {
			b->flags &= ~RRL_BF_ELIMIT;
			rrl_log_state(a, b->flags, b->cls);
		}
	
		/* Add new tokens. */
		uint32_t dn = rrl->rate * dt;
		if (b->flags & RRL_BF_SSTART) { /* Bucket in slow-start. */
			dn /= RRL_SSTART;
			b->flags &= ~RRL_BF_SSTART;
			dbg_rrl("%s: bucket '0x%x' slow-start finished\n",
			        __func__, (unsigned)(b - rrl->arr));
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

	/* Unlock bucket. */
	if (lock > -1) {
		rrl_unlock_mx(rrl, lock);
	}
	
	return ret;
}

int rrl_destroy(rrl_table_t *rrl)
{
	if (rrl) {
		dbg_rrl("%s: freeing table %p\n", __func__, rrl);
		for (size_t i = 0; i < rrl->lk_count; ++i) {
			pthread_mutex_destroy(&rrl->lk[i].mx);
		}
		free(rrl->lk);
	}
	
	free(rrl);
	return KNOT_EOK;
}
