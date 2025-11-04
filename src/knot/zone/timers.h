/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdint.h>
#include <time.h>

#include "contrib/sockaddr.h"
#include "libknot/dname.h"
#include "knot/journal/knot_lmdb.h"

#define LAST_NOTIFIED_SERIAL_VALID (1LLU << 32)
#define LAST_SIGNED_SERIAL_FOUND (1 << 0)
#define LAST_SIGNED_SERIAL_VALID (1 << 1)

/*!
 * \brief Persistent zone timers.
 */
struct zone_timers {
	time_t last_flush;             //!< Last zone file synchronization.
	time_t next_refresh;           //!< Next zone refresh attempt.
	uint32_t last_signed_serial;   //!< SOA serial of last signed zone version.
	uint8_t last_signed_s_flags;   //!< If last signed serial detected and valid;
	bool last_refresh_ok;          //!< Last zone refresh attempt was successful.
	uint64_t last_notified_serial; //!< SOA serial of last successful NOTIFY; (1<<32) if none.
	time_t next_ds_check;          //!< Next parent DS check.
	time_t next_ds_push;           //!< Next DDNS to parent zone with updated DS record.
	time_t catalog_member;         //!< This catalog member zone created.
	time_t next_expire;            //!< Timestamp of the zone to expire.
	struct sockaddr_in6 last_master; //!< Address of pinned master (used last time).
	time_t master_pin_hit;         //!< Fist occurence of another master more updated than the pinned one.
};

typedef struct zone_timers zone_timers_t;

/*!
 * \brief From zonedb.h
 */
typedef struct knot_zonedb knot_zonedb_t;

/*!
 * \brief Load timers for one zone.
 *
 * \param[in]  db      Timer database.
 * \param[in]  zone    Zone name.
 * \param[out] timers  Loaded timers
 *
 * \return KNOT_E*
 * \retval KNOT_ENOENT  Zone not found in the database.
 */
int zone_timers_read(knot_lmdb_db_t *db, const knot_dname_t *zone,
                     zone_timers_t *timers);

/*!
 * \brief Write timers for one zone.
 *
 * \param db      Timer database.
 * \param zone    Zone name.
 * \param timers  Loaded timers
 *
 * \return KNOT_E*
 */
int zone_timers_write(knot_lmdb_db_t *db, const knot_dname_t *zone,
                      const zone_timers_t *timers);

/*!
 * \brief Write timers for all zones.
 *
 * \param db      Timer database.
 * \param zonedb  Zones database.
 *
 * \return KNOT_E*
 */
int zone_timers_write_all(knot_lmdb_db_t *db, knot_zonedb_t *zonedb);

/*!
 * \brief Selectively delete zones from the database.
 *
 * \param db         Timer database.
 * \param keep_zone  Filtering callback.
 * \param cb_data    Data passed to callback function.
 *
 * \return KNOT_E*
 */
int zone_timers_sweep(knot_lmdb_db_t *db, sweep_cb keep_zone, void *cb_data);

/*!
 * \brief Tell if the specified serial has already been notified according to timers.
 */
bool zone_timers_serial_notified(const zone_timers_t *timers, uint32_t serial);
