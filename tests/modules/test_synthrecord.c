/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <tap/basic.h>

#include "knot/modules/synthrecord/synthrecord.c"
#include "stdio.h"

int main(int argc, char *argv[])
{
	plan_lazy();
	const char * const ipv6s[] = {
		"0123:4567:89AB:CDEF::1"
	};
	char buffer[50];
	for(size_t i = 0; i < sizeof(ipv6s)/sizeof(const char *); ++i) {
		synth_addr_cpy(buffer, ipv6s[i], AF_INET6, true);
		printf("%s", buffer);
	}

	return 0;
}
