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
#include "afl-loop.h"

int main(void)
{
	while (__AFL_LOOP(1000)) {
		uint8_t buffer[UINT16_MAX + 1] = { 0 };
		size_t len = fread(buffer, 1, sizeof(buffer), stdin);

		knot_pkt_t *pkt = knot_pkt_new(buffer, len, NULL);
		assert(pkt);
		int r = knot_pkt_parse(pkt, 0);
		knot_pkt_free(&pkt);

		return (r == KNOT_EOK ? 0 : 1);
	}
}
