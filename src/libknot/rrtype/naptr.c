/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stddef.h>
#include <stdint.h>

#include "libknot/errcode.h"
#include "libknot/rrtype/naptr.h"

int knot_naptr_header_size(const uint8_t *naptr, const uint8_t *maxp)
{
	if (!naptr || !maxp || naptr >= maxp) {
		return KNOT_EINVAL;
	}

	size_t size = 0;

	/* Fixed fields size (order, preference) */
	size += 2 * sizeof(uint16_t);

	/* Variable fields size (flags, services, regexp) */
	for (int i = 0; i < 3; i++) {
		const uint8_t *len_ptr = naptr + size;
		if (len_ptr >= maxp) {
			return KNOT_EMALF;
		}
		size += 1 + *len_ptr;
	}

	if (naptr + size >= maxp) {
		return KNOT_EMALF;
	}

	return size;
}
