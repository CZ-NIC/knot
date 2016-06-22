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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/attribute.h"
#include "libknot/cookies/server.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt-cookie.h"

_public_
int knot_scookie_check(const struct knot_dns_cookies *cookies,
                       const struct knot_scookie_check_ctx *check_ctx,
                       const struct knot_sc_alg *sc_alg)
{
	if (!cookies || !check_ctx || !sc_alg) {
		return KNOT_EINVAL;
	}

	if (!cookies->cc || !cookies->cc_len ||
	    !cookies->sc || !cookies->sc_len) {
		return KNOT_EINVAL;
	}

	if (!check_ctx->clnt_sockaddr ||
	    !check_ctx->secret_data || !check_ctx->secret_len) {
		return KNOT_EINVAL;
	}

	if (!sc_alg->sc_size || !sc_alg->parse_func || !sc_alg->gen_func) {
		return KNOT_EINVAL;
	}

	if (sc_alg->sc_size > KNOT_OPT_COOKIE_SRVR_MAX) {
		return KNOT_ESPACE;
	}

	if (cookies->sc_len != sc_alg->sc_size) {
		/* Cookie size does to match. */
		return KNOT_EINVAL;
	}

	struct knot_scookie_inbound inbound = { 0, };

	/* Obtain data from received server cookie. */
	int ret = sc_alg->parse_func(cookies->sc, cookies->sc_len, &inbound);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint8_t generated_sc[KNOT_OPT_COOKIE_SRVR_MAX] = { 0, };
	uint16_t generated_sc_len = KNOT_OPT_COOKIE_SRVR_MAX;
	struct knot_scookie_input sc_input = {
		.cc = cookies->cc,
		.cc_len = cookies->cc_len,
		.nonce = inbound.nonce,
		.time = inbound.time,
		.srvr_data = check_ctx
	};

	/* Generate a new server cookie. */
	ret = sc_alg->gen_func(&sc_input, generated_sc, &generated_sc_len);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = memcmp(cookies->sc, generated_sc, generated_sc_len);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
