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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>

#include "libknot/libknot.h"

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	uint8_t *copy = malloc(size);
	assert(copy);
	memcpy(copy, data, size);

	knot_pkt_t *pkt = knot_pkt_new(copy, size, NULL);
	knot_pkt_parse(pkt, 0);
	knot_pkt_free(&pkt);

	free(copy);

	return 0;
}
