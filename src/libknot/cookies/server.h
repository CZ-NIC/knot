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
 * \brief Inbound server cookie checking context.
 *
 * Additional data needed to check the inbound server cookie.
 */
struct knot_scookie_check_ctx {
	const struct sockaddr *clnt_sockaddr; /*!< Client (remote) socket address. */
	const uint8_t *secret_data; /*!< Server secret data. */
	size_t secret_len;          /*!< Secret data length. */
};

/*!
 * \brief Inbound server cookie content structure.
 */
struct knot_scookie_inbound {
	uint32_t nonce;           /*!< Some value. */
	uint32_t time;            /*!< Time stamp. */
	const uint8_t *hash_data; /*!< Hash data. */
	uint16_t hash_len;        /*!< Hash data length. */
};

/*!
 * \brief Input data needed to compute the client cookie value.
 */
struct knot_scookie_input {
	const uint8_t *cc; /*!< Client cookie. */
	uint16_t cc_len;   /*!< Client cookie size. */
	uint32_t nonce;    /*!< Some generated value. */
	uint32_t time;     /*!< Time stamp. */
	const struct knot_scookie_check_ctx *srvr_data; /*!< Private data known to the server. */
};

/*!
 * \brief Server cookie parser function type.
 *
 * \param sc        Server cookie data.
 * \param data_len  Server cookie data length.
 * \param inbound   Inbound cookie structure to be set.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
typedef int (knot_sc_parse_t)(const uint8_t *sc, uint16_t sc_len,
                              struct knot_scookie_inbound *inbound);
/*!
 * \brief Server cookie generator function type.
 *
 * \param input   Data which to generate the cookie from.
 * \param sc_out  Buffer to write the resulting client cookie data into.
 * \param sc_len  On input set to cookie buffer size.
 *                On successful return contains size of server cookie.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_EINVAL
 */
typedef int (knot_sc_gen_t)(const struct knot_scookie_input *input,
                            uint8_t *sc_out, uint16_t *sc_len);

/*!
 * \brief Holds description of the server cookie algorithm.
 */
struct knot_sc_alg {
	const uint16_t sc_size;      /*!< Cookie size the algorithm operates with. */
	knot_sc_parse_t *parse_func; /*!< Cookie parser function. */
	knot_sc_gen_t *gen_func;     /*!< Cookie generator function. */
};

/*!
 * \brief Check whether supplied client and server cookies match.
 *
 * \param cookies    Cookie data.
 * \param check_ctx  Data known to the server needed for cookie validation.
 * \param sc_alg     Server cookie algorithm.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_EINVAL
 */
int knot_scookie_check(const struct knot_dns_cookies *cookies,
                       const struct knot_scookie_check_ctx *check_ctx,
                       const struct knot_sc_alg *sc_alg);
