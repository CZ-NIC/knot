/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file msg.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Simple output formatting framework.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _UTILS__MSG_H_
#define _UTILS__MSG_H_

#include <stdio.h>			// printf

#define ERROR_		"; Error: "
#define INFO_		"; Info: "
#define WARNING_	"; Warning: "
#define DEBUG_		"; Debug: "

#define ERR(m...)	{ printf(ERROR_ m); fflush(stdout); }
#define INFO(m...)	{ printf(INFO_ m); fflush(stdout); }
#define WARN(m...)	{ printf(WARNING_ m); fflush(stdout); }

/*! \brief Enable/disable debugging. */
int msg_enable_debug(int val);

/*! \brief Print debug message. */
int msg_debug(const char *fmt, ...);

#ifndef NDEBUG
 #define DBG(m...) msg_debug(DEBUG_ m)
#else
 #define DBG(m...)
#endif

/*! \brief Debug message for null input. */
#define DBG_NULL	DBG("%s: null parameter\n", __func__)

#endif // _UTILS__MSG_H_

/*! @} */
