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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
* \file
*
* \brief DNS cookies processing.
*
* \addtogroup libknot
* @{
*/

#pragma once

#include <stdint.h>
#include <sys/socket.h>

#include "libknot/rrtype/opt.h"

#define KNOT_EDNS_COOKIE_SECRET_SIZE 16

/*!
 * \brief DNS Cookie parameters needed to compute the cookie value.
 *
 * \note Server address is not used for the server cookie check.
 */
typedef struct {
	const struct sockaddr *client_addr; /*!< Client socket address. */
	const struct sockaddr *server_addr; /*!< Server socket address. */
	uint8_t secret[KNOT_EDNS_COOKIE_SECRET_SIZE]; /*!< Cookie secret data. */
} knot_edns_cookie_params_t;

/*!
 * \brief Generate a client cookie using given parameters.
 *
 * \param out     Generated client cookie.
 * \param params  Client cookie parameters.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_edns_cookie_client_generate(knot_edns_cookie_t *out,
                                     const knot_edns_cookie_params_t *params);

/*!
 * \brief Check whether client cookie was generated using given parameters.
 *
 * \param cc      Client cookie that should be checked.
 * \param params  Client cookie parameters.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_edns_cookie_client_check(const knot_edns_cookie_t *cc,
                                  const knot_edns_cookie_params_t *params);

/*!
 * \brief Generate a server cookie using given parameters.
 *
 * \param out     Generated server cookie.
 * \param cc      Client cookie parameter.
 * \param params  Server cookie parameters.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_edns_cookie_server_generate(knot_edns_cookie_t *out,
                                     const knot_edns_cookie_t *cc,
                                     const knot_edns_cookie_params_t *params);

/*!
 * \brief Check whether server cookie was generated using given parameters.
 *
 * \param sc      Server cookie that should be checked.
 * \param cc      Client cookie parameter.
 * \param params  Server cookie parameters.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_edns_cookie_server_check(const knot_edns_cookie_t *sc,
                                  const knot_edns_cookie_t *cc,
                                  const knot_edns_cookie_params_t *params);

/*! @} */
