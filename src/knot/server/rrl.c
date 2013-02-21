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
#include <sys/socket.h>

#include "knot/server/rrl.h"
#include "knot/common.h"
#include "common/hattrie/murmurhash3.h"

/* Limits */
#define RRL_CLSBLK_MAXLEN (4 + 8 + 1 + 256)
/* CIDR block prefix lengths for v4/v6 */
#define RRL_V4_PREFIX ((uint32_t)0x00ffffff)         /* /24 */
#define RRL_V6_PREFIX ((uint64_t)0x00ffffffffffffff) /* /56 */
/* Defaults */
#define RRL_DEFAULT_RATE 100
#define RRL_CAPACITY 8 /* N seconds. */
#define RRL_SSTART 4 /* 1/Nth of the rate for slow start */

/* Classification */
enum {
	CLS_NULL     = 0 << 0, /* Empty bucket. */
	CLS_NORMAL   = 1 << 0, /* Normal response. */
	CLS_ERROR    = 1 << 1, /* Error response. */
	CLS_NXDOMAIN = 1 << 2, /* NXDOMAIN (special case of error). */
	CLS_EMPTY    = 1 << 3, /* Empty response. */
	CLS_SSTART   = 1 << 4  /* Bucket in slow-start after collision. */
};

static uint8_t rrl_clsid(knot_packet_t *p) {
	/*! \todo */
	return CLS_NORMAL;
}

static int rrl_clsname(char *dst, uint8_t cls, knot_packet_t *p)
{
	/*! \todo */
	return 0;
}

static int rrl_classify(char *dst, size_t maxlen,
                        sockaddr_t *a, knot_packet_t *p, uint32_t seed)
{
	/* Class */
	int blklen = 0;
	uint8_t cls = rrl_clsid(p);
	*dst = cls;
	blklen += sizeof(cls);
	
	/* Address (in network byteorder, adjust masks). */
	uint64_t nb = 0;
	if (a->family == AF_INET6) { /* Take the /56 prefix. */
		nb = *((uint64_t*)&a->addr6.sin6_addr) & RRL_V6_PREFIX;
	} else {                     /* Take the /24 prefix */
		nb = (uint32_t)a->addr4.sin_addr.s_addr & RRL_V4_PREFIX;
	}
	memcpy(dst + blklen, (void*)&nb, sizeof(nb));
	blklen += sizeof(nb);

	/* Name */
	int len = rrl_clsname(dst + blklen, cls, p);
	if (len < 0) {
		return KNOT_ERROR;
	} else {
		blklen += len;
	}
	
	/* Seed. */
	len = sizeof(seed);
	if (memcpy(dst + blklen, (void*)&seed, len) == 0) {
		blklen += len;
	}
	
	return blklen;
}

static rrl_item_t* rrl_hash(rrl_table_t *t, sockaddr_t *a, knot_packet_t *p, uint32_t stamp)
{
	char buf[RRL_CLSBLK_MAXLEN];
	int len = rrl_classify(buf, sizeof(buf), a, p, t->seed);
	if (len < 0) {
		return NULL;
	}
	
	uint32_t id = hash(buf, len) % t->size;
	rrl_item_t *b = t->arr + id;
	dbg_rrl("%s: classified pkt as '0x%x' bucket=%p\n", __func__, id, b);

	/* Inspect bucket state. */
	uint64_t nprefix = *((uint64_t*)(buf + sizeof(uint8_t)));
	if (b->flags == CLS_NULL) {
		b->flags = *buf; /* Stored as a first byte in clsblock. */
		b->ntok = t->rate;
		b->time = stamp;
		b->pref = nprefix; /* Invalidate */
	}
	/* Check for collisions. */
	if (b->pref != nprefix) {
		dbg_rrl("%s: collising in bucket '0x%4x'\n", __func__, id);
		b->pref= nprefix;
		b->time = stamp; /* Reset time */
		b->ntok = t->rate / RRL_SSTART; /*! Slow start, better to track rep. collisions */
	}
	
	return b;
}

rrl_table_t *rrl_create(size_t size)
{
	const size_t tbl_len = sizeof(rrl_table_t) + size * sizeof(rrl_item_t);
	rrl_table_t *t = malloc(tbl_len);
	if (!t) return NULL;
	
	memset(t, 0, tbl_len);
	t->rate = RRL_DEFAULT_RATE;
	t->seed = time(NULL);
	t->size = size;
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

int rrl_query(rrl_table_t *rrl, sockaddr_t* src, knot_packet_t *resp)
{
	if (!rrl || !src || !resp) return KNOT_EINVAL;
	
	/* Calculate hash and fetch */
	int ret = KNOT_EOK;
	uint32_t now = time(NULL);
	rrl_item_t *b = rrl_hash(rrl, src, resp, now);
	if (!b) {
		dbg_rrl("%s: failed to compute bucket from packet\n", __func__);
		return KNOT_ERROR;
	}

	/* Calculate rate for dT */
	uint32_t dt = now - b->time;
	if (dt > RRL_CAPACITY) {
		dt = RRL_CAPACITY;
	}
	dbg_rrl("%s: bucket=%p tokens=%hu flags=%x dt=%u\n",
	        __func__, b, b->ntok, b->flags, dt);
	if (dt > 0) { /* Window moved. */
		uint32_t dn = rrl->rate * dt; /*! \todo Interpolate. */
		if (b->flags & CLS_SSTART) { /* Bucket in slow-start. */
			dn /= RRL_SSTART;
			b->flags &= ~CLS_SSTART;
		}
		b->ntok += dn;
		if (b->ntok > RRL_CAPACITY * rrl->rate) {
			b->ntok = RRL_CAPACITY * rrl->rate;
		}
	}
	
	/* Visit bucket. */
	b->time = now;
	
	/* Check token count */
	if (b->ntok > 0) {
		--b->ntok;
	} else {
		ret = KNOT_ELIMIT; /* No available token. */
	}
	
	return ret;
}

int rrl_destroy(rrl_table_t *rrl)
{
	free(rrl);
	return KNOT_EOK;
}
