/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>

extern volatile bool signals_req_stop;
extern volatile bool signals_req_reload;
extern volatile bool signals_req_zones_reload;

/*! \brief Setup signal handlers and blocking mask. */
void signals_setup(void);

/*! \brief Unblock server control signals. */
void signals_enable(void);
