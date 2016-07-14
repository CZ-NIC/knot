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

#include <string.h>

#include "libknot/attribute.h"
#include "libknot/cookies/server.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt-cookie.h"

_public_
bool knot_sc_input_is_valid(const struct knot_sc_input *input)
{
	/*
	 * RFC7873 4.2 -- Server cookie should be generated from request
	 * source IP address, a secret quantity and request client cookie.
	 */

	return input && input->cc && input->cc_len > 0 && input->srvr_data &&
	       input->srvr_data->secret_data && input->srvr_data->secret_len > 0;
}

_public_
int knot_sc_parse(uint16_t nonce_len, const uint8_t *sc, uint16_t sc_len,
                  struct knot_sc_content *content)
{
	if (!sc || !sc_len || !content) {
		return KNOT_EINVAL;
	}

	if (nonce_len >= sc_len) {
		return KNOT_EINVAL;
	}

	content->nonce = nonce_len ? sc : NULL;
	content->nonce_len = nonce_len;
	/* Rest of server cookie contains hash. */
	content->hash = sc + nonce_len;
	content->hash_len = sc_len - nonce_len;

	return KNOT_EOK;
}

_public_
int knot_sc_check(uint16_t nonce_len, const struct knot_dns_cookies *cookies,
                  const struct knot_sc_private *srvr_data,
                  const struct knot_sc_alg *sc_alg)
{
	if (!cookies || !srvr_data || !sc_alg) {
		return KNOT_EINVAL;
	}

	if (!cookies->cc || !cookies->cc_len ||
	    !cookies->sc || !cookies->sc_len) {
		return KNOT_EINVAL;
	}

	if (!srvr_data->clnt_sockaddr ||
	    !srvr_data->secret_data || !srvr_data->secret_len) {
		return KNOT_EINVAL;
	}

	if (!sc_alg->hash_size || !sc_alg->hash_func) {
		return KNOT_EINVAL;
	}

	if ((nonce_len + sc_alg->hash_size) > KNOT_OPT_COOKIE_SRVR_MAX) {
		return KNOT_EINVAL;
	}

	if (cookies->sc_len != (nonce_len + sc_alg->hash_size)) {
		return KNOT_EINVAL;
	}

	struct knot_sc_content content = { 0 };

	/* Obtain data from received server cookie. */
	int ret = knot_sc_parse(nonce_len, cookies->sc, cookies->sc_len, &content);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint8_t generated_hash[KNOT_OPT_COOKIE_SRVR_MAX] = { 0 };
	uint16_t generated_hash_len = KNOT_OPT_COOKIE_SRVR_MAX;
	struct knot_sc_input sc_input = {
		.cc = cookies->cc,
		.cc_len = cookies->cc_len,
		.nonce = content.nonce,
		.nonce_len = content.nonce_len,
		.srvr_data = srvr_data
	};

	/* Generate a new hash. */
	generated_hash_len = sc_alg->hash_func(&sc_input, generated_hash, generated_hash_len);
	if (generated_hash_len == 0) {
		return KNOT_EINVAL;
	}

	/* Compare hashes. */
	ret = memcmp(content.hash, generated_hash, generated_hash_len);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
