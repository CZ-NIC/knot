/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/journal/knot_lmdb.h"

/*!
 * \brief Data passed to the signal handler.
 */
typedef struct {
	knot_lmdb_db_t *close_db; // LMDB database to be closed
	bool color;               // do a terminal color reset
} signal_ctx_t;

/*!
 * \brief Prepares a signal handler for a clean shutdown.
 *
 * \note  Configures common break signals to initiate close of confdb
 *        and of another LMDB database defined by the global variable
 *        signal_ctx_t signal_ctx. If set to NULL, only confdb
 *        is closed.
 */
void signal_init_std(void);
