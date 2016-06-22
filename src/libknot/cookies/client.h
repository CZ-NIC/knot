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
 * \brief Input data needed to compute the client cookie value.
 */
struct knot_ccookie_input {
	const struct sockaddr *clnt_sockaddr; /*!< Client (local) socket address. */
	const struct sockaddr *srvr_sockaddr; /*!< Server (remote) socket address. */
	const uint8_t *secret_data; /*!< Client secret data. */
	size_t secret_len;          /*!< Secret data length. */
};

/*!
 * \brief Client cookie generator function type.
 *
 * \param[in]     input   Data which to generate the cookie from.
 * \param[in]     cc_out  Buffer to write the resulting client cookie data into.
 * \param[in,out] cc_len  On input set to cookie buffer size. On successful
 *                        return contains size of client cookie.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_EINVAL
 */
typedef int (knot_cc_gen_t)(const struct knot_ccookie_input *input,
                            uint8_t *cc_out, uint16_t *cc_len);

/*!
 * \brief Holds description of the client cookie algorithm.
 */
struct knot_cc_alg {
	const uint16_t cc_size;  /*!< Cookie size the algorithm operates with. */
	knot_cc_gen_t *gen_func; /*!< Cookie generator function. */
};

/*!
 * \brief Check whether client cookie \a cc was generated from given \a input.
 *
 * \param cc      Client cookie that should be checked.
 * \param cc_len  Client cookie size.
 * \param input   Client cookie input algorithm parameters.
 * \param cc_alg  Client cookie algorithm.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_EINVAL
 */
int knot_ccookie_check(const uint8_t *cc, uint16_t cc_len,
                       const struct knot_ccookie_input *input,
                       const struct knot_cc_alg *cc_alg);
