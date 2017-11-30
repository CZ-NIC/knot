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

#include <assert.h>
#include <string.h>

#include "libknot/attribute.h"
#include "libknot/cookies/server.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/opt-cookie.h"
#include "contrib/string.h"
#include "contrib/sockaddr.h"

#define SERVER_HASH_LEN 8

_public_
bool knot_sc_input_is_valid(const struct knot_sc_input *input)
{
	/*
	 * RFC7873 4.2 -- Server cookie should be generated from request
	 * source IP address, a secret quantity and request client cookie.
	 */

	return input && input->cc && input->cc_len > 0 && input->srvr_data;
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

static uint64_t generate_server_cookie(const struct knot_sc_input *input)
{
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, &input->srvr_data->secret);

	if (input->srvr_data->clnt_sockaddr) {
		size_t addr_len = 0;
		void *addr = sockaddr_raw(input->srvr_data->clnt_sockaddr, &addr_len);
		if (addr) {
			SipHash24_Update(&ctx, addr, addr_len);
		}
	}

	if (input->nonce && input->nonce_len > 0) {
		SipHash24_Update(&ctx, input->nonce, input->nonce_len);
	}

	if (input->cc && input->cc_len == KNOT_OPT_COOKIE_CLNT) {
		SipHash24_Update(&ctx, input->cc, input->cc_len);
	}

	return SipHash24_End(&ctx);
}

_public_
int knot_sc_check(uint16_t nonce_len, const struct knot_dns_cookies *cookies,
                  const struct knot_sc_private *srvr_data)
{
	if (!cookies || !srvr_data) {
		return KNOT_EINVAL;
	}

	if (!cookies->cc || !cookies->cc_len ||
	    !cookies->sc || !cookies->sc_len) {
		return KNOT_EINVAL;
	}

	if (!srvr_data->clnt_sockaddr) {
		return KNOT_EINVAL;
	}

	if ((nonce_len + SERVER_HASH_LEN) > KNOT_OPT_COOKIE_SRVR_MAX) {
		return KNOT_EINVAL;
	}

	if (cookies->sc_len != (nonce_len + SERVER_HASH_LEN)) {
		return KNOT_EINVAL;
	}

	struct knot_sc_content content = { 0 };

	/* Obtain data from received server cookie. */
	int ret = knot_sc_parse(nonce_len, cookies->sc, cookies->sc_len, &content);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (content.hash_len != SERVER_HASH_LEN) {
		return KNOT_EINVAL;
	}

	struct knot_sc_input sc_input = {
		.cc = cookies->cc,
		.cc_len = cookies->cc_len,
		.nonce = content.nonce,
		.nonce_len = content.nonce_len,
		.srvr_data = srvr_data
	};

	if (!knot_sc_input_is_valid(&sc_input)) {
		return KNOT_EINVAL;
	}

	/* Generate a new hash. */
	uint64_t generated_hash = generate_server_cookie(&sc_input);
	assert(sizeof(generated_hash) == SERVER_HASH_LEN);

	/* Compare hashes. */
	ret = const_time_memcmp(content.hash, &generated_hash, SERVER_HASH_LEN);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
