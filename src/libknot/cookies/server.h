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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/*!
 * \brief Convenience structure holding both, server and client, cookies.
 */
struct knot_dns_cookies {
	const uint8_t *cc; /*!< Client cookie. */
	uint16_t cc_len;   /*!< Client cookie size. */
	const uint8_t *sc; /*!< Server cookie. */
	uint16_t sc_len;   /*!< Server cookie size. */
};

/*!
 * \brief Private data known to the server.
 *
 * \note Contains data needed to check the inbound server cookie and to
 *       generate a new one.
 */
struct knot_sc_private {
	const struct sockaddr *clnt_sockaddr; /*!< Client (remote) socket address. */
	const uint8_t *secret_data; /*!< Server secret data. */
	size_t secret_len;          /*!< Secret data length. */
};

/*!
 * \brief Inbound server cookie content structure.
 *
 * \note These data are obtained from an incoming server cookie.
 */
struct knot_sc_content {
	const uint8_t *nonce; /*!< Some value prefixed to the hash. */
	uint16_t nonce_len;   /*!< Nonce data length. */
	const uint8_t *hash;  /*!< Hash data. */
	uint16_t hash_len;    /*!< Hash data length. */
};

/*!
 * \brief Input data needed to compute the server cookie value.
 *
 * \note All these data are needed to generate a new server cookie hash.
 */
struct knot_sc_input {
	const uint8_t *cc;    /*!< Client cookie. */
	uint16_t cc_len;      /*!< Client cookie size. */
	const uint8_t *nonce; /*!< Some value prefixed before the hash. */
	uint16_t nonce_len;   /*!< Nonce data length. */
	const struct knot_sc_private *srvr_data; /*!< Private data known to the server. */
};

/*!
 * \brief Check server cookie input data for basic sanity.
 *
 * \param input  Data which to generate the cookie from.
 *
 * \retval true if input contains client cookie and server secret data
 * \retval false if input is insufficient or NULL pointer passed
 */
bool knot_sc_input_is_valid(const struct knot_sc_input *input);

/*!
 * \brief Reads a server cookie that contains \a nonce_len bytes of data
 *        prefixed before the actual hash.
 *
 * \see DNS Cookies, RFC 7873, Appendix B.1 and B.2
 *
 * \param nonce_len  Expected nonce data size.
 * \param sc         Server cookie.
 * \param sc_len     Server cookie length.
 * \param content    Server cookie content structure to be set.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_sc_parse(uint16_t nonce_len, const uint8_t *sc, uint16_t sc_len,
                  struct knot_sc_content *content);

/*!
 * \brief Hash generator function type.
 *
 * \note The function writes only the hash value. It does not write any nonce
 *       data prefixed before the actual hash value. Nonce data must be written
 *       by an external function into the server cookie.
 *
 * \param input     Data which to generate the cookie from.
 * \param hash_out  Buffer to write the resulting hash data into.
 * \param hash_len  Hash buffer size.
 *
 * \retval non-zero size of written data on successful return
 * \retval 0 on error
 */
typedef uint16_t (knot_sc_hash_t)(const struct knot_sc_input *input,
                                  uint8_t *hash_out, uint16_t hash_len);

/*!
 * \brief Holds description of the server cookie algorithm.
 */
struct knot_sc_alg {
	const uint16_t hash_size;  /*!< Hash size the algorithm operates with. */
	knot_sc_hash_t *hash_func; /*!< Cookie generator function. */
};

/*!
 * \brief Check whether supplied client and server cookies match.
 *
 * \param nonce_len  Expected nonce data size.
 * \param cookies    Cookie data.
 * \param srvr_data  Data known to the server needed for cookie validation.
 * \param sc_alg     Server cookie algorithm.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_sc_check(uint16_t nonce_len, const struct knot_dns_cookies *cookies,
                  const struct knot_sc_private *srvr_data,
                  const struct knot_sc_alg *sc_alg);
