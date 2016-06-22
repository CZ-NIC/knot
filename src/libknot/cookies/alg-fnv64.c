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

#include <arpa/inet.h> /* htonl(), ... */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/fnv/fnv.h"
#include "libknot/cookies/alg-fnv64.h"
#include "libknot/cookies/server-parse.h"
#include "libknot/rrtype/opt-cookie.h"
#include "libknot/errcode.h"

/* When defined, client address will be used when generating client cookie. */
//#define CC_HASH_USE_CLIENT_ADDRESS

/*!
 * Compute client cookie using FNV-64.
 *
 * \note At least one input address must be provided.
 *
 * \param[in]     input   Input parameters.
 * \param[in]     cc_out  Buffer for computed client cookie.
 * \param[in,out] cc_len  Size of buffer/written data.
 *
 * \return KNOT_EOK on success, error code else.
 */
static int cc_gen_fnv64(const struct knot_ccookie_input *input,
                        uint8_t *cc_out, uint16_t *cc_len)
{
	if (!input || !cc_out || !cc_len) {
		return KNOT_EINVAL;
	}

	if ((!input->clnt_sockaddr && !input->srvr_sockaddr) ||
	    !(input->secret_data && input->secret_len)) {
		return KNOT_EINVAL;
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	Fnv64_t hash_val = FNV1A_64_INIT;

#if defined(CC_HASH_USE_CLIENT_ADDRESS)
	if (input->clnt_sockaddr) {
		if (KNOT_EOK == knot_sockaddr_bytes(input->clnt_sockaddr,
		                                    &addr, &alen)) {
			assert(addr && alen);
			hash_val = fnv_64a_buf(addr, alen, hash_val);
		}
	}
#endif /* defined(CC_HASH_USE_CLIENT_ADDRESS) */

	if (input->srvr_sockaddr) {
		if (KNOT_EOK == knot_sockaddr_bytes(input->srvr_sockaddr,
		                                    &addr, &alen)) {
			assert(addr && alen);
			hash_val = fnv_64a_buf((void *) addr, alen, hash_val);
		}
	}

	hash_val = fnv_64a_buf((void *) input->secret_data, input->secret_len,
	                       hash_val);

	assert(KNOT_OPT_COOKIE_CLNT == sizeof(hash_val));
	if (*cc_len < KNOT_OPT_COOKIE_CLNT) {
		return KNOT_ESPACE;
	}

	*cc_len = KNOT_OPT_COOKIE_CLNT;
	memcpy(cc_out, &hash_val, *cc_len);

	return KNOT_EOK;
}

#define SRVR_FNV64_SIMPLE_HASH_SIZE 8

/*!
 * \brief Compute server cookie using FNV-64 (hash only).
 *
 * Server cookie = FNV-64(client IP | client cookie | server secret)
 *
 * \param[in]     input   Data to compute cookie from.
 * \param[in]     sc_out  Server cookie output buffer.
 * \param[in,out] sc_len  Buffer size/written data size.
 *
 * \return KNOT_EOK or error code.
 */
static int sc_gen_fnv64_simple(const struct knot_scookie_input *input,
                               uint8_t *sc_out, uint16_t *sc_len)
{
	if (!input || !sc_out ||
	    !sc_len || (*sc_len < SRVR_FNV64_SIMPLE_HASH_SIZE)) {
		return KNOT_EINVAL;
	}

	if (!input->cc || !input->cc_len || !input->srvr_data ||
	    !input->srvr_data->secret_data || !input->srvr_data->secret_len) {
		return KNOT_EINVAL;
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	Fnv64_t hash_val = FNV1A_64_INIT;

	if (KNOT_EOK == knot_sockaddr_bytes(input->srvr_data->clnt_sockaddr,
	                                    &addr, &alen)) {
		assert(addr && alen);
		hash_val = fnv_64a_buf((void *) addr, alen, hash_val);
	}

	hash_val = fnv_64a_buf((void *) input->cc, input->cc_len, hash_val);

	hash_val = fnv_64a_buf((void *) input->srvr_data->secret_data,
	                       input->srvr_data->secret_len, hash_val);

	memcpy(sc_out, &hash_val, sizeof(hash_val));
	*sc_len = sizeof(hash_val);
	assert(SRVR_FNV64_SIMPLE_HASH_SIZE == *sc_len);

	return KNOT_EOK;
}

#define SRVR_FNV64_SIZE 16

/**
 * \brief Compute server cookie using FNV-64.
 *
 * Server cookie = nonce | time | FNV-64(client IP | nonce | time | client cookie | server secret)
 *
 * \param[in]     input   Data to compute cookie from.
 * \param[in]     sc_out  Server cookie output buffer.
 * \param[in,out] sc_len  Buffer size/written data size.
 *
 * \return KNOT_EOK or error code.
 */
static int sc_gen_fnv64(const struct knot_scookie_input *input,
                        uint8_t *sc_out, uint16_t *sc_len)
{
	if (!input || !sc_out ||
	    !sc_len || (*sc_len < SRVR_FNV64_SIZE)) {
		return KNOT_EINVAL;
	}

	if (!input->cc || !input->cc_len || !input->srvr_data ||
	    !input->srvr_data->secret_data || !input->srvr_data->secret_len) {
		return KNOT_EINVAL;
	}

	const uint8_t *addr = NULL;
	size_t alen = 0; /* Address length. */

	Fnv64_t hash_val = FNV1A_64_INIT;

	if (input->srvr_data->clnt_sockaddr) {
		if (KNOT_EOK == knot_sockaddr_bytes(input->srvr_data->clnt_sockaddr,
		                                    &addr, &alen)) {
			assert(addr && alen);
			hash_val = fnv_64a_buf((void *) addr, alen, hash_val);
		}
	}

	hash_val = fnv_64a_buf((void *) &input->nonce, sizeof(input->nonce),
	                       hash_val);

	hash_val = fnv_64a_buf((void *) &input->time, sizeof(input->time),
	                       hash_val);

	hash_val = fnv_64a_buf((void *) input->cc, input->cc_len, hash_val);

	hash_val = fnv_64a_buf((void *) input->srvr_data->secret_data,
	                       input->srvr_data->secret_len, hash_val);

	uint32_t aux = htonl(input->nonce);
	memcpy(sc_out, &aux, sizeof(aux));
	aux = htonl(input->time);
	memcpy(sc_out + sizeof(aux), &aux, sizeof(aux));

	memcpy(sc_out + (2 * sizeof(aux)), &hash_val, sizeof(hash_val));
	*sc_len = (2 * sizeof(aux)) + sizeof(hash_val);
	assert(SRVR_FNV64_SIZE == *sc_len);

	return KNOT_EOK;
}

_public_
const struct knot_cc_alg knot_cc_alg_fnv64 = {
	KNOT_OPT_COOKIE_CLNT,
	cc_gen_fnv64
};

_public_
const struct knot_sc_alg knot_sc_alg_fnv64_simple = {
	SRVR_FNV64_SIMPLE_HASH_SIZE,
	knot_scookie_parse_simple,
	sc_gen_fnv64_simple
};

_public_
const struct knot_sc_alg knot_sc_alg_fnv64 = {
	SRVR_FNV64_SIZE,
	knot_scookie_parse,
	sc_gen_fnv64
};
