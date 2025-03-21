/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#define COL_RST(active)   ((active) ? "\x1B[0m"  : "")

#define COL_BOLD(active)  ((active) ? "\x1B[1m"  : "")
#define COL_DIM(active)   ((active) ? "\x1B[2m"  : "")
#define COL_UNDR(active)  ((active) ? "\x1B[4m"  : "")

#define COL_RED(active)   ((active) ? "\x1B[31m" : "")
#define COL_GRN(active)   ((active) ? "\x1B[32m" : "")
#define COL_YELW(active)  ((active) ? "\x1B[93m" : "")
#define COL_BLUE(active)  ((active) ? "\x1B[34m" : "")
#define COL_MGNT(active)  ((active) ? "\x1B[35m" : "")
#define COL_CYAN(active)  ((active) ? "\x1B[36m" : "")
#define COL_WHIT(active)  ((active) ? "\x1B[97m" : "")
