/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <stdint.h>
#include <time.h>

#include "libknot/dname.h"
#include "knot/journal/knot_lmdb.h"

/*!
 * \brief Persistent zone timers.
 */
struct zone_timers {
	uint32_t soa_expire;     //!< SOA expire value.
	time_t last_flush;       //!< Last zone file synchronization.
	time_t last_refresh;     //!< Last successful zone refresh attempt.
	time_t next_refresh;     //!< Next zone refresh attempt.
	time_t last_resalt;      //!< Last NSEC3 resalt.
	time_t next_ds_check;    //!< Next parent DS check.
	time_t next_ds_push;     //!< Next DDNS to parent zone with updated DS record.
	time_t catalog_member;   //!< This catalog member zone created.
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
 * \param db      Timer databse.
 * \param zonedb  Zones database.
 *
 * \return KNOT_E*
 */
int zone_timers_write_all(knot_lmdb_db_t *db, knot_zonedb_t *zonedb);

/*!
 * \brief Selectively delete zones from the database.
 *
 * \param db         Timer dababase.
 * \param keep_zone  Filtering callback.
 * \param cb_data    Data passed to callback function.
 *
 * \return KNOT_E*
 */
int zone_timers_sweep(knot_lmdb_db_t *db, sweep_cb keep_zone, void *cb_data);
