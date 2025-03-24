/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
 * \brief DNS Cookie parameters needed to generate/check the cookie value.
 *
 * \note Client address is not used for the client cookie generation/check.
 * \note Server address is not used for the server cookie generation/check.
 */
typedef struct {
	uint8_t version;          /*!< Server cookie version to generate. */
	uint32_t timestamp;       /*!< [s] Server cookie generate or check time. */
	uint32_t lifetime_before; /*!< [s] Server cookie lifetime in the past. */
	uint32_t lifetime_after;  /*!< [s] Server cookie lifetime in the future. */
	const struct sockaddr_storage *client_addr;   /*!< Client socket address. */
	const struct sockaddr_storage *server_addr;   /*!< Server socket address. */
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
