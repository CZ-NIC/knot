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

#pragma once

#include "libknot/dname.h"
#include "dnssec/tsig.h"

/*!
 * \brief TSIG key.
 */
struct knot_tsig_key {
	dnssec_tsig_algorithm_t algorithm;
	knot_dname_t *name;
	dnssec_binary_t secret;
};
typedef struct knot_tsig_key knot_tsig_key_t;

/*!
 * \brief Packet signing context.
 */
typedef struct knot_sign_context {
	knot_tsig_key_t tsig_key;
	uint8_t *tsig_buf;
	uint8_t *tsig_digest;
	size_t tsig_buflen;
	size_t tsig_digestlen;
	uint8_t tsig_runlen;
	uint64_t tsig_time_signed;
	size_t pkt_count;
} knot_sign_context_t;

/*!
 * \brief Initialize a new TSIG key from individual key parameters.
 *
 * \param[out] key         Key to be initialized.
 * \param[in]  algorithm   Algorithm name. NULL for default (hmac-md5).
 * \param[in]  name        Key name (domain name in presentation format).
 * \param[in]  secret_b64  Secret encoded using Base 64.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_tsig_key_init(knot_tsig_key_t *key, const char *algorithm,
                       const char *name, const char *secret_b64);

/*!
 * \brief Create a new TSIG key from a string encoding all parameters.
 *
 * \param params  Parameters in a form \a [algorithm:]name:base64_secret
 */
int knot_tsig_key_init_str(knot_tsig_key_t *key, const char *params);

/*!
 * \brief Create a new TSIG key by reading the parameters from a file.
 *
 * The file content is parsed by \a tsig_key_create_str.
 */
int knot_tsig_key_init_file(knot_tsig_key_t *key, const char *filename);

/*!
 * \brief Deinitialize TSIG key.
 */
void knot_tsig_key_deinit(knot_tsig_key_t *key);

/*!
 * \brief Duplicate a TSIG key.
 */
int knot_tsig_key_copy(knot_tsig_key_t *dst, const knot_tsig_key_t *src);
