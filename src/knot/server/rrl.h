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
/*!
 * \file rrl.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief Response-rate limiting API.
 *
 * \addtogroup network
 * @{
 */

#ifndef _KNOTD_RRL_H_
#define _KNOTD_RRL_H_

#include <stdint.h>
#include <pthread.h>
#include "common/sockaddr.h"
#include "libknot/packet/packet.h"
#include "libknot/zone/zone.h"

/* Defaults */
#define RRL_LOCK_GRANULARITY 10 /* Last digit granularity */

typedef struct rrl_item {
	uint64_t pref;       /* Prefix associated. */
	uint16_t ntok;        /* Tokens available */
	uint16_t flags;      /* Flags */
	uint32_t time;       /* Timestamp */
} rrl_item_t;

typedef struct rrl_lock {    /* Wrapper around lock struct. */
	pthread_mutex_t mx;
} rrl_lock_t;

typedef struct rrl_table {
	uint32_t rate;       /* Configured RRL limit */
	uint32_t seed;       /* Pseudorandom seed for hashing. */
	rrl_lock_t *lk;      /* Table locks. */
	size_t lk_count;     /* Table lock count (granularity). */
	size_t size;         /* Number of buckets */
	rrl_item_t arr[];    /* Buckets */
} rrl_table_t;

typedef struct rrl_req {
	const uint8_t *w;
	uint16_t len;
	unsigned flags;
	const knot_question_t *qst;
} rrl_req_t;

rrl_table_t *rrl_create(size_t size);
uint32_t rrl_setrate(rrl_table_t *rrl, uint32_t rate);
uint32_t rrl_rate(rrl_table_t *rrl);
int rrl_setlocks(rrl_table_t *rrl, size_t granularity);
int rrl_query(rrl_table_t *rrl, const sockaddr_t *a, rrl_req_t *req,
              const knot_zone_t *zone);
int rrl_destroy(rrl_table_t *rrl);


#endif /* _KNOTD_RRL_H_ */

/*! @} */
