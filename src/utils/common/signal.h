/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
