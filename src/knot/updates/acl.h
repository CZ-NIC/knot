/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <sys/socket.h>

#include "libknot/quic/tls_common.h"
#include "libknot/tsig.h"
#include "knot/conf/conf.h"

/*! \brief ACL actions. */
typedef enum {
	ACL_ACTION_QUERY    = 0,
	ACL_ACTION_NOTIFY   = 1,
	ACL_ACTION_TRANSFER = 2,
	ACL_ACTION_UPDATE   = 3
} acl_action_t;

/*! \brief ACL update owner matching options. */
typedef enum {
	ACL_UPDATE_OWNER_NONE = 0,
	ACL_UPDATE_OWNER_KEY  = 1,
	ACL_UPDATE_OWNER_ZONE = 2,
	ACL_UPDATE_OWNER_NAME = 3,
} acl_update_owner_t;

/*! \bref ACL update owner comparison options. */
typedef enum {
	ACL_UPDATE_MATCH_SUBEQ   = 0,
	ACL_UPDATE_MATCH_EQ      = 1,
	ACL_UPDATE_MATCH_SUB     = 2,
	ACL_UPDATE_MATCH_PATTERN = 3,
} acl_update_owner_match_t;

/*! \bref ACL protocol options. */
typedef enum {
	ACL_PROTOCOL_NONE = 0,
	ACL_PROTOCOL_UDP  = (1 << 0),
	ACL_PROTOCOL_TCP  = (1 << 1),
	ACL_PROTOCOL_TLS  = (1 << 2),
	ACL_PROTOCOL_QUIC = (1 << 3),
} acl_protocol_t;

/*!
 * \brief Checks if the address and/or tsig key matches given ACL list.
 *
 * If a proper ACL rule is found and tsig.name is not empty, tsig.secret is filled.
 *
 * \param conf         Configuration.
 * \param acl          Pointer to ACL config multivalued identifier.
 * \param action       ACL action.
 * \param addr         IP address.
 * \param tsig         TSIG parameters.
 * \param zone_name    Zone name.
 * \param query        Update query.
 * \param tls_session  Possible TLS session.
 * \param proto        Transport protocol.
 *
 * \retval True if authenticated.
 */
bool acl_allowed(conf_t *conf, conf_val_t *acl, acl_action_t action,
                 const struct sockaddr_storage *addr, knot_tsig_key_t *tsig,
                 const knot_dname_t *zone_name, knot_pkt_t *query,
                 struct gnutls_session_int *tls_session,
                 knotd_query_proto_t proto);

/*!
 * \brief Checks if the address and/or tsig key matches a remote from the list.
 *
 * Global (server.automatic-acl) and per remote automatic ACL functionality
 * must be enabled in order to decide the remote is allowed.
 *
 * If a proper REMOTE is found and tsig.name is not empty, tsig.secret is filled.
 *
 * \param conf         Configuration.
 * \param rmts         Pointer to REMOTE config multivalued identifier.
 * \param addr         IP address.
 * \param tsig         TSIG parameters.
 * \param tls_session  Possible TLS session.
 * \param proto        Transport protocol.
 *
 * \retval True if authenticated.
 */
bool rmt_allowed(conf_t *conf, conf_val_t *rmts, const struct sockaddr_storage *addr,
                 knot_tsig_key_t *tsig, struct gnutls_session_int *tls_session,
                 knotd_query_proto_t proto);
