/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/utsname.h>

inline static bool linux_at_least(unsigned version_first, unsigned version_second)
{
#if defined(__linux__)
	struct utsname info;
	unsigned first, second;
	if (uname(&info) != 0 || sscanf(info.release, "%u.%u.", &first, &second) != 2) {
		return false;
	} else {
		return first > version_first ||
		       (first = version_first && second >= version_second);
	}
#else
	return false;
#endif
}
