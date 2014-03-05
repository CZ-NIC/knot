/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file acl.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Access control lists.
 *
 * Simple access control list is implemented as a linked list, sorted by
 * prefix length. This way, longest prefix match is always found first.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_ACL_H_
#define _KNOTD_ACL_H_

#include "common/lists.h"
#include "common/sockaddr.h"
#include "common/mempattern.h"
#include "libknot/tsig.h"

struct knot_tsig_key;

/*! \brief ACL structure. */
typedef list_t acl_t;

/*! \brief Netblock (address and prefix). */
typedef struct netblock {
	struct sockaddr_storage ss; /*!< Address storage. */
	uint8_t prefix;               /*!< Address prefix. */
} netblock_t;

/*! \brief Single ACL match. */
typedef struct acl_match {
	node_t n;
	netblock_t netblock;
	struct knot_tsig_key *key; /*!< \brief TSIG key. */
} acl_match_t;

/*! \brief Match address against netblock. */
int netblock_match(const netblock_t *a1, const struct sockaddr_storage *a2);

/*!
 * \brief Create a new ACL.
 *
 * \retval New ACL instance when successful.
 * \retval NULL on errors.
 */
acl_t *acl_new();

/*!
 * \brief Delete ACL structure.
 *
 * \param acl Pointer to ACL instance.
 */
void acl_delete(acl_t **acl);

/*!
 * \brief Insert new ACL match.
 *
 * \param acl Pointer to ACL instance.
 * \param addr Address.
 * \param prefix Netblock prefix.
 * \param key TSIG key.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int acl_insert(acl_t *acl, const struct sockaddr_storage *addr, uint8_t prefix, knot_tsig_key_t *key);

/*!
 * \brief Match address against ACL.
 *
 * \param acl Pointer to ACL instance.
 * \param addr IP address.
 *
 * \retval Matching rule instance if found.
 * \retval NULL if it didn't find a match.
 */
acl_match_t* acl_find(acl_t *acl, const struct sockaddr_storage *addr, const knot_dname_t *key_name);

/*!
 * \brief Truncate ACL.
 *
 * All but the default rule will be dropped.
 *
 * \param acl Pointer to ACL instance.
 */
void acl_truncate(acl_t *acl);

#endif /* _KNOTD_ACL_H_ */

/*! @} */
