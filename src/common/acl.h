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
 * An access control list is a named structure
 * for efficient IP address and port matching.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_ACL_H_
#define _KNOTD_ACL_H_

#include "common/skip-list.h"
#include "common/sockaddr.h"

/*! \brief ACL rules types. */
typedef enum acl_rule_t {
	ACL_ERROR  = -1,
	ACL_DENY   =  0,
	ACL_ACCEPT =  1
} acl_rule_t;

/*! \brief ACL structure. */
typedef struct acl_t {
	acl_rule_t default_rule; /*!< \brief Default rule. */
	skip_list_t *rules;      /*!< \brief Data container. */
	const char name[];       /*!< \brief ACL semantic name. */
} acl_t;

/*! \brief Single ACL value. */
typedef struct acl_key_t {
	sockaddr_t addr; /*!< \brief Address for comparison. */
	acl_rule_t rule; /*!< \brief Rule for address. */
	void *val;       /*!< \brief Associated value (or NULL). */
} acl_key_t;

/*!
 * \brief Create a new ACL.
 *
 * \param default_rule Default rule for address matching.
 * \param name ACL symbolic name (or NULL).
 *
 * \retval New ACL instance when successful.
 * \retval NULL on errors.
 */
acl_t *acl_new(acl_rule_t default_rule, const char *name);

/*!
 * \brief Delete ACL structure.
 *
 * \param acl Pointer to ACL instance.
 */
void acl_delete(acl_t **acl);

/*!
 * \brief Create new ACL rule.
 *
 * \todo Support address subnets (issue #1366).
 *
 * \param acl Pointer to ACL instance.
 * \param addr IP address.
 * \param rule Rule for given address.
 * \param val Value to be stored for given address (or NULL).
 *
 * \retval ACL_ACCEPT if successful.
 * \retval ACP_ERROR on error.
 */
int acl_create(acl_t *acl, const sockaddr_t* addr, acl_rule_t rule, void *val);

/*!
 * \brief Match address against ACL.
 *
 * \param acl Pointer to ACL instance.
 * \param addr IP address.
 * \param key Set to related key or NULL if not found.
 *
 * \retval Address rule if the address is accepted.
 * \retval Default rule if the address is not accepted.
 * \retval ACP_ERROR on error.
 */
int acl_match(acl_t *acl, const sockaddr_t* addr, acl_key_t **key);

/*!
 * \brief Truncate ACL.
 *
 * All but the default rule will be dropped.
 *
 * \param acl Pointer to ACL instance.
 *
 * \retval ACL_ACCEPT if successful.
 * \retval ACP_ERROR on error.
 */
int acl_truncate(acl_t *acl);

/*!
 * \brief Return ACL name.
 *
 * \param acl Pointer to ACL instance.
 *
 * \retval ACL name.
 */
static inline const char* acl_name(acl_t *acl) {
	if (!acl) {
		return 0;
	}

	return acl->name;
}

/*!
 * \brief Return ACL rules.
 *
 * \param acl Pointer to ACL instance.
 *
 * \retval ACL rules skip-list.
 */
static inline skip_list_t* acl_rules(acl_t *acl) {
        if (!acl) {
                return 0;
        }

        return acl->rules;
}

#endif /* _KNOTD_ACL_H_ */

/*! @} */
