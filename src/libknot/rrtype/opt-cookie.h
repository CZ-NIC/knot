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

#define KNOT_OPT_COOKIE_MIN  8
#define KNOT_OPT_COOKIE_CLNT KNOT_OPT_COOKIE_MIN
#define KNOT_OPT_COOKIE_SRVR_MIN 8
#define KNOT_OPT_COOKIE_SRVR_MAX 32

/*!
 * \brief Returns the size of the buffer required to store the cookie.
 *
 * \note The value of \a clen and \a slen must be within defined limits.
 *
 * \param clen  Client cookie portion length.
 * \param slen  Server cookie portion length.
 *
 * \retval <> 0 if the supplied arguments are within limits
 * \retval 0 if the supplied parameters violate the requirements
 */
uint16_t knot_edns_opt_cookie_data_len(uint16_t clen, uint16_t slen);

/*!
 * \brief Write cookie wire data.
 *
 * \param cc        Client cookie.
 * \param cc_len    Client cookie size.
 * \param sc        Server cookie.
 * \param sc_len    Server cookie size.
 * \param data      Output data buffer.
 * \param data_len  Size of output data buffer.
 *
 * \retval non-zero size of written data on successful return
 * \retval 0 on error
 */
uint16_t knot_edns_opt_cookie_write(const uint8_t *cc, uint16_t cc_len,
                                    const uint8_t *sc, uint16_t sc_len,
                                    uint8_t *data, uint16_t data_len);

/*!
 * \brief Parse cookie wire data.
 *
 * \note The function only sets the pointers into the buffer. It does not
 * copy any data.
 *
 * \param data      Input data buffer containing whole cookie option.
 * \param data_len  Length of input data buffer.
 * \param cc        Client cookie.
 * \param cc_len    Client cookie size.
 * \param sc        Server cookie.
 * \param sc_len    Server cookie size.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_EMALF
 */
int knot_edns_opt_cookie_parse(const uint8_t *data, uint16_t data_len,
                               const uint8_t **cc, uint16_t *cc_len,
                               const uint8_t **sc, uint16_t *sc_len);
