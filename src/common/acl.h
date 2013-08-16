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

/*! \brief ACL structure. */
typedef list acl_t;

/*! \brief Single ACL match. */
typedef struct acl_match {
	node n;
	sockaddr_t addr; /*!< \brief Address for comparison. */
	void *val;       /*!< \brief Associated value (or NULL). */
} acl_match_t;

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
 * \param addr IP address.
 * \param val Value to be stored for given address (or NULL).
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int acl_insert(acl_t *acl, const sockaddr_t *addr, void *val);

/*!
 * \brief Match address against ACL.
 *
 * \param acl Pointer to ACL instance.
 * \param addr IP address.
 *
 * \retval Matching rule instance if found.
 * \retval NULL if it didn't find a match.
 */
acl_match_t* acl_find(acl_t *acl, const sockaddr_t *addr);

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
