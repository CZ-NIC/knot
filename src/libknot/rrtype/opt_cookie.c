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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "contrib/wire_ctx.h"
#include "libknot/consts.h" // knot_addr_family_t -- is unused
#include "libknot/errcode.h"
#include "libknot/rrtype/opt.h"
#include "libknot/rrtype/opt_cookie.h"

_public_
int knot_edns_opt_cookie_write(const uint8_t *cc, uint16_t cc_len,
                               const uint8_t *sc, uint16_t sc_len,
                               uint8_t *data, uint16_t *data_len)
{
	assert(cc != NULL);

	if ((cc == NULL && cc_len > 0) || (sc == NULL && sc_len > 0)) {
		return KNOT_EINVAL;
	}

	if (data == NULL || data_len == NULL) {
		return KNOT_EINVAL;
	}

	uint16_t cookies_size = knot_edns_opt_cookie_data_len(cc_len, sc_len);
	if (cookies_size == 0) {
		return KNOT_EINVAL;
	}
	if (*data_len < cookies_size) {
		return KNOT_ESPACE;
	}

	wire_ctx_t wire = wire_ctx_init(data, *data_len);
	wire_ctx_write(&wire, cc, cc_len);
	if (sc_len) {
		wire_ctx_write(&wire, sc, sc_len);
	}

	if (wire.error != KNOT_EOK) {
		return wire.error;
	}

	*data_len = wire_ctx_offset(&wire);

	return KNOT_EOK;
}

_public_
int knot_edns_opt_cookie_parse(const uint8_t *data, uint16_t data_len,
                               const uint8_t **cc, uint16_t *cc_len,
                               const uint8_t **sc, uint16_t *sc_len)
{
	if (data == NULL || !cookie_len_ok(data_len)) {
		return KNOT_EINVAL;
	}

	if (cc != NULL && cc_len != NULL) {
		*cc_len = KNOT_OPT_COOKIE_CLNT;
		*cc = data;
	}

	if (sc != NULL && sc_len != NULL) {
		*sc_len = data_len - KNOT_OPT_COOKIE_CLNT;
		*sc = (*sc_len == 0) ? NULL : (data + KNOT_OPT_COOKIE_CLNT);
	}

	return KNOT_EOK;
}
