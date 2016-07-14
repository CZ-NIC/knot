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
#include <string.h>

#include "contrib/fnv/fnv.h"
#include "contrib/sockaddr.h"
#include "libknot/attribute.h"
#include "libknot/cookies/alg-fnv64.h"
#include "libknot/rrtype/opt-cookie.h"
#include "libknot/errcode.h"

/*!
 * \brief Update hash value.
 *
 * \param hash_val  Hash value to be updated.
 * \param sa        Socket address.
 */
static inline void update_hash(Fnv64_t *hash_val, const struct sockaddr *sa)
{
	assert(hash_val && sa);

	size_t addr_len = 0;
	void *addr = sockaddr_raw(sa, &addr_len);
	if (addr) {
		assert(addr_len);
		*hash_val = fnv_64a_buf(addr, addr_len, *hash_val);
	}
}

/*!
 * \brief Compute client cookie using FNV-64.
 *
 * \note At least one input address must be provided.
 *
 * \param input   Input parameters.
 * \param cc_out  Buffer for computed client cookie.
 * \param cc_len  Buffer size.
 *
 * \retval non-zero size of written data on successful return
 * \retval 0 on error
 */
static uint16_t cc_gen_fnv64(const struct knot_cc_input *input,
                             uint8_t *cc_out, uint16_t cc_len)
{
	if (!input || !cc_out || cc_len < KNOT_OPT_COOKIE_CLNT) {
		return 0;
	}

	if ((!input->clnt_sockaddr && !input->srvr_sockaddr) ||
	    !(input->secret_data && input->secret_len)) {
		return 0;
	}

	Fnv64_t hash_val = FNV1A_64_INIT;

	if (input->clnt_sockaddr) {
		update_hash(&hash_val, input->clnt_sockaddr);
	}

	if (input->srvr_sockaddr) {
		update_hash(&hash_val, input->srvr_sockaddr);
	}

	hash_val = fnv_64a_buf((void *)input->secret_data, input->secret_len,
	                       hash_val);

	assert(KNOT_OPT_COOKIE_CLNT == sizeof(hash_val));

	cc_len = sizeof(hash_val);
	memcpy(cc_out, &hash_val, cc_len);

	return cc_len;
}

#define SRVR_FNV64_HASH_SIZE 8

/*!
 * \brief Compute server cookie hash using FNV-64.
 *
 * Server cookie = nonce | FNV-64(client IP | nonce | client cookie | server secret)
 *
 * \note This function computes only the hash value.
 *
 * \param input     Data to compute cookie from.
 * \param hash_out  Buffer to write the resulting hash data into.
 * \param hash_len  Buffer size.
 *
 * \retval non-zero size of written data on successful return
 * \retval 0 on error
 */
static uint16_t sc_gen_fnv64(const struct knot_sc_input *input,
                             uint8_t *hash_out, uint16_t hash_len)
{
	if (!input || !hash_out || hash_len < SRVR_FNV64_HASH_SIZE) {
		return 0;
	}

	if (!input->cc || !input->cc_len || !input->srvr_data ||
	    !input->srvr_data->secret_data || !input->srvr_data->secret_len) {
		return 0;
	}

	Fnv64_t hash_val = FNV1A_64_INIT;

	if (input->srvr_data->clnt_sockaddr) {
		update_hash(&hash_val, input->srvr_data->clnt_sockaddr);
	}

	if (input->nonce && input->nonce_len) {
		hash_val = fnv_64a_buf((void *)input->nonce, input->nonce_len, hash_val);
	}

	hash_val = fnv_64a_buf((void *)input->cc, input->cc_len, hash_val);

	hash_val = fnv_64a_buf((void *)input->srvr_data->secret_data,
	                       input->srvr_data->secret_len, hash_val);

	assert(SRVR_FNV64_HASH_SIZE == sizeof(hash_val));

	hash_len = sizeof(hash_val);
	memcpy(hash_out, &hash_val, hash_len);

	return hash_len;
}

_public_
const struct knot_cc_alg knot_cc_alg_fnv64 = {
	KNOT_OPT_COOKIE_CLNT,
	cc_gen_fnv64
};

_public_
const struct knot_sc_alg knot_sc_alg_fnv64 = {
	SRVR_FNV64_HASH_SIZE,
	sc_gen_fnv64
};
