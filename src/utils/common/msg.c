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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils/common/msg.h"

static volatile int MSG_DBG_STATE = 0; /* True if debugging is enabled. */

int msg_enable_debug(int val)
{
	return MSG_DBG_STATE = val;
}

int msg_debug(const char *fmt, ...)
{
	int n = 0;
	if (MSG_DBG_STATE) {
		va_list ap;
		va_start(ap, fmt);
		n = vprintf(fmt, ap);
		va_end(ap);
	}
	return n;
}
