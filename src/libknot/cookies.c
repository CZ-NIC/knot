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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdbool.h>
#include <time.h>

#include "libknot/attribute.h"
#include "libknot/cookies.h"
#include "libknot/errcode.h"
#include "contrib/string.h"
#include "contrib/sockaddr.h"
#include "contrib/openbsd/siphash.h"

_public_
int knot_edns_cookie_client_generate(knot_edns_cookie_t *out,
                                     const knot_edns_cookie_params_t *params)
{
	if (out == NULL || params == NULL || params->client_addr == NULL ||
	    params->server_addr == NULL) {
		return KNOT_EINVAL;
	}

	SIPHASH_CTX ctx;
	assert(sizeof(params->secret) == sizeof(SIPHASH_KEY));
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)params->secret);

	size_t addr_len = 0;
	void *addr = sockaddr_raw(params->client_addr, &addr_len);
	SipHash24_Update(&ctx, addr, addr_len);

	addr_len = 0;
	addr = sockaddr_raw(params->server_addr, &addr_len);
	SipHash24_Update(&ctx, addr, addr_len);

	uint64_t hash = SipHash24_End(&ctx);
	memcpy(out->data, &hash, sizeof(hash));
	out->len = sizeof(hash);

	return KNOT_EOK;
}

_public_
int knot_edns_cookie_client_check(const knot_edns_cookie_t *cc,
                                  const knot_edns_cookie_params_t *params)
{
	if (cc == NULL || cc->len != KNOT_EDNS_COOKIE_CLNT_SIZE) {
		return KNOT_EINVAL;
	}

	knot_edns_cookie_t ref;
	int ret = knot_edns_cookie_client_generate(&ref, params);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(ref.len == KNOT_EDNS_COOKIE_CLNT_SIZE);

	ret = const_time_memcmp(cc->data, ref.data, KNOT_EDNS_COOKIE_CLNT_SIZE);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

_public_
int knot_edns_cookie_server_generate(knot_edns_cookie_t *out,
                                     const knot_edns_cookie_t *cc,
                                     const knot_edns_cookie_params_t *params)
{
	if (out == NULL || cc == NULL || cc->len != KNOT_EDNS_COOKIE_CLNT_SIZE ||
	    params == NULL) {
		return KNOT_EINVAL;
	}

	out->data[0] = KNOT_EDNS_COOKIE_VERSION;
	out->data[1] = KNOT_EDNS_COOKIE_ALGO_SIPHASH24;
	out->data[2] = 0; /* reserved */
	out->data[3] = 0; /* reserved */
	out->len = 4;

	uint32_t now = htobe32((uint32_t)time(NULL));
	memcpy(&out->data[out->len], &now, sizeof(uint32_t));
	out->len += sizeof(uint32_t);

	SIPHASH_CTX ctx;
	assert(sizeof(params->secret) == sizeof(SIPHASH_KEY));
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)params->secret);
	SipHash24_Update(&ctx, cc->data, cc->len);
	SipHash24_Update(&ctx, out->data, out->len);
	uint64_t hash = SipHash24_End(&ctx);
	memcpy(out->data + out->len, &hash, sizeof(hash));
	out->len += sizeof(hash);

	return KNOT_EOK;
}

_public_
int knot_edns_cookie_server_check(const knot_edns_cookie_t *sc,
                                  const knot_edns_cookie_t *cc,
                                  const knot_edns_cookie_params_t *params)
{

	if (sc == NULL || sc->len != 16 || cc == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t version = sc->data[0];
	uint8_t algo = sc->data[1];
	if (version != KNOT_EDNS_COOKIE_VERSION ||
	    algo != KNOT_EDNS_COOKIE_ALGO_SIPHASH24) {
		return KNOT_EINVAL;
	}

	uint32_t cookie_now;
	uint32_t now = time(NULL);
	memcpy(&cookie_now, &sc->data[4], sizeof(uint32_t));
	cookie_now = htobe32(cookie_now);
	if (0) {
		return KNOT_EINVAL;
	}

	uint64_t cookie_hash;
	memcpy(&cookie_hash, &sc->data[8], sizeof(uint64_t));
	SIPHASH_CTX ctx;
	assert(sizeof(params->secret) == sizeof(SIPHASH_KEY));
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)params->secret);
	SipHash24_Update(&ctx, cc->data, cc->len);
	SipHash24_Update(&ctx, sc->data, sc->len - sizeof(uint64_t));
	uint64_t hash = SipHash24_End(&ctx);

	if (cookie_hash != hash) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
