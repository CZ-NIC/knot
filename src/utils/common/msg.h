/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>

#define ERROR_		";; ERROR: "
#define INFO_		";; INFO: "
#define WARNING_	";; WARNING: "
#define DEBUG_		";; DEBUG: "

#define ERR(msg, ...)	{ fprintf(stderr, ERROR_   msg "\n", ##__VA_ARGS__); fflush(stderr); }
#define INFO(msg, ...)	{ fprintf(stdout, INFO_    msg "\n", ##__VA_ARGS__); fflush(stdout); }
#define WARN(msg, ...)	{ fprintf(stderr, WARNING_ msg "\n", ##__VA_ARGS__); fflush(stderr); }
#define DBG(msg, ...)	{ msg_debug(DEBUG_         msg "\n", ##__VA_ARGS__); fflush(stdout); }

/*! \brief Enable/disable debugging. */
int msg_enable_debug(int val);

/*! \brief Print debug message. */
int msg_debug(const char *fmt, ...);

/*! \brief Debug message for null input. */
#define DBG_NULL	DBG("%s: null parameter", __func__)

#define ERR2(msg, ...)	{ fprintf(stderr, "error: "   msg "\n", ##__VA_ARGS__); fflush(stderr); }
#define WARN2(msg, ...)	{ fprintf(stderr, "warning: " msg "\n", ##__VA_ARGS__); fflush(stderr); }
#define INFO2(msg, ...)	{ fprintf(stdout,             msg "\n", ##__VA_ARGS__); fflush(stdout); }
