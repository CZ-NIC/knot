/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <arpa/inet.h> /* ntohl() */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/attribute.h"
#include "libknot/cookies/server-parse.h"
#include "libknot/errcode.h"

_public_
int knot_scookie_parse_simple(const uint8_t *sc, uint16_t sc_len,
                              struct knot_scookie_inbound *inbound)
{
	if (!sc || !sc_len || !inbound) {
		return KNOT_EINVAL;
	}

	//memset(inbound, 0, sizeof(*inbound));
	inbound->hash_data = sc; /* Entire server cookie contains data. */
	inbound->hash_len = sc_len;

	return KNOT_EOK;
}

_public_
int knot_scookie_parse(const uint8_t *sc, uint16_t sc_len,
                       struct knot_scookie_inbound *inbound)
{
	if (!sc || !sc_len || !inbound) {
		return KNOT_EINVAL;
	}

	if (sc_len <= (2 * sizeof(uint32_t))) { /* nonce + time */
		return KNOT_EINVAL;
	}

	uint32_t aux;

	memcpy(&aux, sc, sizeof(aux));
	inbound->nonce = ntohl(aux);
	memcpy(&aux, sc + sizeof(aux), sizeof(aux));
	inbound->time = ntohl(aux);
	inbound->hash_data = sc + (2 * sizeof(aux));
	inbound->hash_len = sc_len - (2 * sizeof(aux));

	return KNOT_EOK;
}
