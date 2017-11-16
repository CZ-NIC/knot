/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include "contrib/openbsd/siphash.h"

int main(void)
{
	plan_lazy();

	SIPHASH_KEY key = {
		0x0706050403020100,
		0x0f0e0d0c0b0a0908
	};

	const char *data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e";
	size_t data_len = 15;

	uint64_t ret = SipHash24(&key, data, data_len);
	ok(ret == 0xa129ca6149be45e5, "siphash: correct hash result");

	return 0;
}
