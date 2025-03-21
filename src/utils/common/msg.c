/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
