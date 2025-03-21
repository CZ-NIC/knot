/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/libknot.h"
#include "knot/server/server.h"

#define CTL_MAX_CONCURRENT 8 // Number of CTL threads EXCLUDING the main thread which can also process CTL.

/*!
 * Processes incoming control commands.
 *
 * \param[in]  ctl        Control context.
 * \param[in]  server     Server instance.
 * \param[in]  thread_idx Index of a thread which performs the operation.
 * \param[out] exclusive  All following CTLs shall (not) be processed exclusively by this thread.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int ctl_process(knot_ctl_t *ctl, server_t *server, int thread_idx, bool *exclusive);
