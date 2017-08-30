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
#include <time.h>

#include "libknot/db/db.h"
#include "libknot/dname.h"

/*!
 * \brief Persistent zone timers.
 */
struct zone_timers {
	uint32_t soa_expire;     //!< SOA expire value.
	time_t last_flush;       //!< Last zone file synchronization.
	time_t last_refresh;     //!< Last successful zone refresh attempt.
	time_t next_refresh;     //!< Next zone refresh attempt.
	time_t last_resalt;      //!< Last NSEC3 resalt
	time_t next_parent_ds_q; //!< Next parent ds query
};

typedef struct zone_timers zone_timers_t;

/*!
 * \brief Open zone timers database.
 *
 * \param[in]  path     Path to a directory with the database.
 * \param[out] db       Created database.
 * \param[in]  mapsize  LMDB mapsize.
 *
 * \return KNOT_E*
 */
int zone_timers_open(const char *path, knot_db_t **db, size_t mapsize);

/*!
 * \brief Closes zone timers database.
 *
 * \param db  Timer database.
 */
void zone_timers_close(knot_db_t *db);

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
int zone_timers_read(knot_db_t *db, const knot_dname_t *zone,
                     zone_timers_t *timers);

/*!
 * \brief Init txn for zone_timers_write()
 *
 * \param db      Timer database.
 * \param txn     Handler to be initialized.
 *
 * \return KNOT_E*
 */
int zone_timers_write_begin(knot_db_t *db, knot_db_txn_t *txn);

/*!
 * \brief Close txn for zone_timers_write()
 *
 * \param txn     Handler to be closed.
 *
 * \return KNOT_E*
 */
int zone_timers_write_end(knot_db_txn_t *txn);

/*!
 * \brief Write timers for one zone.
 *
 * \param db      Timer database.
 * \param zone    Zone name.
 * \param timers  Loaded timers
 * \param txn     Transaction handler obtained from zone_timers_write_begin()
 *
 * \return KNOT_E*
 */
int zone_timers_write(knot_db_t *db, const knot_dname_t *zone,
                      const zone_timers_t *timers, knot_db_txn_t *txn);

/*!
 * \brief Callback used in \ref zone_timers_sweep.
 *
 * \retval true for zones to preserve.
 * \retval false for zones to remove.
 */
typedef bool (*sweep_cb)(const knot_dname_t *zone, void *data);

/*!
 * \brief Selectively delete zones from the database.
 *
 * \param db         Timer dababase.
 * \param keep_zone  Filtering callback.
 * \param cb_data    Data passed to callback function.
 *
 * \return KNOT_E*
 */
int zone_timers_sweep(knot_db_t *db, sweep_cb keep_zone, void *cb_data);
