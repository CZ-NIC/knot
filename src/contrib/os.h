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
