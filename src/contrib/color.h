/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
