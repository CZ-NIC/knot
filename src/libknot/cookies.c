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

#include <assert.h>
#include <stdbool.h>

#include "libknot/attribute.h"
#include "libknot/cookies.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "contrib/string.h"
#include "contrib/sockaddr.h"
#include "contrib/openbsd/siphash.h"

_public_
int knot_edns_cookie_client_generate(knot_edns_cookie_t *out,
                                     const knot_edns_cookie_params_t *params)
{
	if (out == NULL || params == NULL || params->server_addr == NULL) {
		return KNOT_EINVAL;
	}

	SIPHASH_CTX ctx;
	assert(sizeof(params->secret) == sizeof(SIPHASH_KEY));
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)params->secret);

	size_t addr_len = 0;
	void *addr = sockaddr_raw(params->server_addr, &addr_len);
	assert(addr);
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

static int cookie_server_generate(knot_edns_cookie_t *out,
                                  const knot_edns_cookie_t *cc,
                                  const knot_edns_cookie_params_t *params)
{
	assert(out && params);

	if (cc == NULL || cc->len != KNOT_EDNS_COOKIE_CLNT_SIZE ||
	    params->client_addr == NULL) {
		return KNOT_EINVAL;
	} else if (out->data[0] != KNOT_EDNS_COOKIE_VERSION) {
		return KNOT_ENOTSUP;
	}

	SIPHASH_CTX ctx;
	assert(sizeof(params->secret) == sizeof(SIPHASH_KEY));
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)params->secret);

	SipHash24_Update(&ctx, cc->data, cc->len);
	SipHash24_Update(&ctx, out->data, out->len);

	size_t addr_len = 0;
	void *addr = sockaddr_raw(params->client_addr, &addr_len);
	assert(addr);
	SipHash24_Update(&ctx, addr, addr_len);

	uint64_t hash = SipHash24_End(&ctx);
	memcpy(out->data + out->len, &hash, sizeof(hash));
	out->len += sizeof(hash);

	return KNOT_EOK;

}

_public_
int knot_edns_cookie_server_generate(knot_edns_cookie_t *out,
                                     const knot_edns_cookie_t *cc,
                                     const knot_edns_cookie_params_t *params)
{
	if (out == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	out->data[0] = params->version;
	out->data[1] = 0; /* reserved */
	out->data[2] = 0; /* reserved */
	out->data[3] = 0; /* reserved */
	out->len = 4;

	uint32_t now = htobe32(params->timestamp);
	memcpy(&out->data[out->len], &now, sizeof(now));
	out->len += sizeof(now);

	return cookie_server_generate(out, cc, params);
}

_public_
int knot_edns_cookie_server_check(const knot_edns_cookie_t *sc,
                                  const knot_edns_cookie_t *cc,
                                  const knot_edns_cookie_params_t *params)
{
	if (sc == NULL || sc->len < KNOT_EDNS_COOKIE_SRVR_MIN_SIZE || params == NULL) {
		return KNOT_EINVAL;
	}

	uint32_t cookie_time;
	memcpy(&cookie_time, &sc->data[4], sizeof(cookie_time));
	cookie_time = be32toh(cookie_time);

	uint32_t min_time = params->timestamp - params->lifetime_before;
	uint32_t max_time = params->timestamp + params->lifetime_after;
	if (cookie_time < min_time || cookie_time > max_time) {
		return KNOT_ERANGE;
	}

	const int fixed_len = 8;
	knot_edns_cookie_t ref;
	memcpy(ref.data, sc->data, fixed_len);
	ref.len = fixed_len;

	int ret = cookie_server_generate(&ref, cc, params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (sc->len != ref.len) {
		return KNOT_EINVAL;
	}

	ret = const_time_memcmp(sc->data + fixed_len, ref.data + fixed_len,
	                        sc->len - fixed_len);
	if (ret != 0) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
