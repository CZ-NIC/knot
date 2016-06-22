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
/*!
 * \file
 *
 * \brief Functions for reading server cookie values.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include "libknot/cookies/server.h"

/*!
 * \brief Reads a server cookie that consists only of a hash value.
 *
 * \note DNS Cookies -- Appendix B.1
 *
 * \param sc       Server cookie.
 * \param sc_len   Server cookie length.
 * \param inbound  Inbound server cookie structure to be populated.
 *
 * \retval KNOT_EOK
 * \ratval KNOT_EINVAL
 */
int knot_scookie_parse_simple(const uint8_t *sc, uint16_t sc_len,
                              struct knot_scookie_inbound *inbound);

/*!
 * \brief Reads a server cookie contains nonce and times stamp before actual
 *        hash value.
 *
 * \note DNS Cookies -- Appendix B.2
 *
 * \param sc       Server cookie.
 * \param sc_len   Server cookie length.
 * \param inbound  Inbound server cookie structure to be populated.
 *
 * \retval KNOT_EOK
 * \ratval KNOT_EINVAL
 */
int knot_scookie_parse(const uint8_t *sc, uint16_t sc_len,
                       struct knot_scookie_inbound *inbound);

/*! @} */
