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

#pragma once

#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include "libknot/packet/pkt.h"

/* Defaults */
#define RRL_SLIP_MAX 100
#define RRL_LOCK_GRANULARITY 32 /* Last digit granularity */

/*! \brief RRL flags. */
enum {
	RRL_NOFLAG    = 0 << 0, /*!< No flags. */
	RRL_WILDCARD  = 1 << 1  /*!< Query to wildcard name. */
};

struct zone;

/*!
 * \brief RRL hash bucket.
 */
typedef struct rrl_item {
	unsigned hop;        /* Hop bitmap. */
	uint64_t netblk;     /* Prefix associated. */
	uint16_t ntok;       /* Tokens available */
	uint8_t  cls;        /* Bucket class */
	uint8_t  flags;      /* Flags */
	uint32_t qname;      /* imputed(QNAME) hash */
	uint32_t time;       /* Timestamp */
} rrl_item_t;

/*!
 * \brief RRL hash bucket table.
 *
 * Table is fixed size, so collisions may occur and are dealt with
 * in a way, that hashbucket rate is reset and enters slow-start for 1 dt.
 * When a bucket is in a slow-start mode, it cannot reset again for the time
 * period.
 *
 * To avoid lock contention, N locks are created and distributed amongst buckets.
 * As of now lock K for bucket N is calculated as K = N % (num_buckets).
 */

typedef struct rrl_table {
	uint32_t rate;       /* Configured RRL limit */
	uint32_t seed;       /* Pseudorandom seed for hashing. */
	pthread_mutex_t ll;
	pthread_mutex_t *lk;      /* Table locks. */
	unsigned lk_count;   /* Table lock count (granularity). */
	size_t size;         /* Number of buckets */
	rrl_item_t arr[];    /* Buckets */
} rrl_table_t;

/*!
 * \brief RRL request descriptor.
 */
typedef struct rrl_req {
	const uint8_t *w;
	uint16_t len;
	unsigned flags;
	knot_pkt_t *query;
	const knot_dname_t *name;
} rrl_req_t;

/*!
 * \brief Create a RRL table.
 * \param size Fixed hashtable size (reasonable large prime is recommended).
 * \return created table or NULL.
 */
rrl_table_t *rrl_create(size_t size);

/*!
 * \brief Get RRL table default rate.
 * \param rrl RRL table.
 * \return rate
 */
uint32_t rrl_rate(rrl_table_t *rrl);

/*!
 * \brief Set RRL table default rate.
 *
 * \note When changing the rate, it is NOT applied to all buckets immediately.
 *
 * \param rrl RRL table.
 * \param rate New rate (in pkts/sec).
 * \return old rate
 */
uint32_t rrl_setrate(rrl_table_t *rrl, uint32_t rate);

/*!
 * \brief Set N distributed locks for the RRL table.
 *
 * \param rrl RRL table.
 * \param granularity Number of created locks.
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int rrl_setlocks(rrl_table_t *rrl, unsigned granularity);

/*!
 * \brief Get bucket for current combination of parameters.
 * \param t RRL table.
 * \param a Source address.
 * \param p RRL request.
 * \param zone Relate zone.
 * \param stamp Timestamp (current time).
 * \param lock Held lock.
 * \return assigned bucket
 */
rrl_item_t* rrl_hash(rrl_table_t *t, const struct sockaddr_storage *a, rrl_req_t *p,
                     const struct zone *zone, uint32_t stamp, int* lock);

/*!
 * \brief Query the RRL table for accept or deny, when the rate limit is reached.
 *
 * \param rrl RRL table.
 * \param a Source address.
 * \param req RRL request (containing resp., flags and question).
 * \param zone Zone related to the response (or NULL).
 * \retval KNOT_EOK if passed.
 * \retval KNOT_ELIMIT when the limit is reached.
 */
int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *a, rrl_req_t *req,
              const struct zone *zone);

/*!
 * \brief Roll a dice whether answer slips or not.
 * \param n_slip Number represents every Nth answer that is slipped.
 * \return true or false
 */
bool rrl_slip_roll(int n_slip);

/*!
 * \brief Destroy RRL table.
 * \param rrl RRL table.
 * \return KNOT_EOK
 */
int rrl_destroy(rrl_table_t *rrl);

/*!
 * \brief Reseed RRL table secret.
 * \param rrl RRL table.
 * \return KNOT_EOK
 */
int rrl_reseed(rrl_table_t *rrl);

/*!
 * \brief Lock specified element lock.
 * \param rrl RRL table.
 * \param lk_id Specified lock.
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 */
int rrl_lock(rrl_table_t *rrl, int lk_id);

/*!
 * \brief Unlock specified element lock.
 * \param rrl RRL table.
 * \param lk_id Specified lock.
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 */
int rrl_unlock(rrl_table_t *rrl, int lk_id);

/*! @} */
