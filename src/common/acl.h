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

#ifndef _KNOT_ACL_H_
#define _KNOT_ACL_H_

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
	acl_rule_t default_rule;
	skip_list_t *rules;
	const char name[];
} acl_t;

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
 * \todo Support address subnets.
 *
 * \param acl Pointer to ACL instance.
 * \param addr IP address (will be duplicated).
 * \param rule Rule.
 *
 * \retval ACL_ACCEPT if successful.
 * \retval ACP_ERROR on error.
 */
int acl_create(acl_t *acl, const sockaddr_t* addr, acl_rule_t rule);

/*!
 * \brief Match address against ACL.
 *
 * \param acl Pointer to ACL instance.
 * \param addr IP address.
 *
 * \retval ACL_ACCEPT if the address is accepted.
 * \retval ACL_DENY if the address is not accepted.
 * \retval ACP_ERROR on error.
 */
int acl_match(acl_t *acl, sockaddr_t* addr);

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

#endif /* _KNOT_ACL_H_ */

/*! @} */
