/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>

#include "libknot/libknot.h"
#include "knot/include/module.h"
#include "contrib/openbsd/siphash.h"

/* Defaults */
#define RRL_SLIP_MAX 100

/*!
 * \brief RRL hash bucket.
 */
typedef struct {
	unsigned hop;        /* Hop bitmap. */
	uint64_t netblk;     /* Prefix associated. */
	uint16_t ntok;       /* Tokens available. */
	uint8_t  cls;        /* Bucket class. */
	uint8_t  flags;      /* Flags. */
	uint32_t qname;      /* imputed(QNAME) hash. */
	uint32_t time;       /* Timestamp. */
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

typedef struct {
	SIPHASH_KEY key;     /* Siphash key. */
	uint32_t rate;       /* Configured RRL limit. */
	pthread_mutex_t ll;
	pthread_mutex_t *lk; /* Table locks. */
	unsigned lk_count;   /* Table lock count (granularity). */
	size_t size;         /* Number of buckets. */
	rrl_item_t arr[];    /* Buckets. */
} rrl_table_t;

/*! \brief RRL request flags. */
typedef enum {
	RRL_REQ_NOFLAG    = 0 << 0, /*!< No flags. */
	RRL_REQ_WILDCARD  = 1 << 1  /*!< Query to wildcard name. */
} rrl_req_flag_t;

/*!
 * \brief RRL request descriptor.
 */
typedef struct {
	const uint8_t *w;
	uint16_t len;
	rrl_req_flag_t flags;
	knot_pkt_t *query;
} rrl_req_t;

/*!
 * \brief Create a RRL table.
 * \param size Fixed hashtable size (reasonable large prime is recommended).
 * \param rate Rate (in pkts/sec).
 * \return created table or NULL.
 */
rrl_table_t *rrl_create(size_t size, uint32_t rate);

/*!
 * \brief Query the RRL table for accept or deny, when the rate limit is reached.
 *
 * \param rrl RRL table.
 * \param a Source address.
 * \param req RRL request (containing resp., flags and question).
 * \param zone Zone name related to the response (or NULL).
 * \param mod Query module (needed for logging).
 * \retval KNOT_EOK if passed.
 * \retval KNOT_ELIMIT when the limit is reached.
 */
int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *a, rrl_req_t *req,
              const knot_dname_t *zone, knotd_mod_t *mod);

/*!
 * \brief Roll a dice whether answer slips or not.
 * \param n_slip Number represents every Nth answer that is slipped.
 * \return true or false
 */
bool rrl_slip_roll(int n_slip);

/*!
 * \brief Destroy RRL table.
 * \param rrl RRL table.
 */
void rrl_destroy(rrl_table_t *rrl);
