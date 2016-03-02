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
 * \file
 *
 * \brief DNS zone semantic checks.
 *
 * \addtogroup zone
 * @{
 */

#pragma once

#include "knot/zone/node.h"
#include "knot/zone/contents.h"
#include "contrib/ucw/lists.h"
#include "libknot/mm_ctx.h"


enum check_levels {
	SEM_CHECK_MANDATORY = 1 << 0,
	SEM_CHECK_OPTIONAL =  1 << 1,
	SEM_CHECK_NSEC =      1 << 2,
	SEM_CHECK_NSEC3 =     1 << 3,
};

/*!
 *\brief Internal error constants. General errors are added for convenience,
 *       so that code does not have to change if new errors are added.
 */
enum zonechecks_errors {
	ZC_ERR_UNKNOWN = -50,

	ZC_ERR_MISSING_SOA,
	ZC_ERR_MISSING_NS_DEL_POINT,
	ZC_ERR_TTL_MISMATCH,

	ZC_ERR_GENERIC_GENERAL_ERROR, /* Generic error delimiter. */

	ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
	ZC_ERR_RRSIG_RDATA_TTL,
	ZC_ERR_RRSIG_RDATA_EXPIRATION,
	ZC_ERR_RRSIG_RDATA_LABELS,
	ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER,
	ZC_ERR_RRSIG_NO_DNSKEY,
	ZC_ERR_RRSIG_RDATA_SIGNED_WRONG,
	ZC_ERR_RRSIG_NO_RRSIG,
	ZC_ERR_RRSIG_SIGNED,
	ZC_ERR_RRSIG_OWNER,
	ZC_ERR_RRSIG_CLASS,
	ZC_ERR_RRSIG_TTL,

	ZC_ERR_RRSIG_GENERAL_ERROR, /* RRSIG error delimiter. */

	ZC_ERR_NO_NSEC,
	ZC_ERR_NSEC_RDATA_BITMAP,
	ZC_ERR_NSEC_RDATA_MULTIPLE,
	ZC_ERR_NSEC_RDATA_CHAIN,
	ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC,

	ZC_ERR_NSEC_GENERAL_ERROR, /* NSEC error delimiter. */

	ZC_ERR_NSEC3_UNSECURED_DELEGATION,
	ZC_ERR_NSEC3_NOT_FOUND,
	ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT,
	ZC_ERR_NSEC3_RDATA_TTL,
	ZC_ERR_NSEC3_RDATA_CHAIN,
	ZC_ERR_NSEC3_EXTRA_RECORD,

	ZC_ERR_NSEC3_GENERAL_ERROR, /* NSEC3 error delimiter. */

	ZC_ERR_CNAME_EXTRA_RECORDS,
	ZC_ERR_DNAME_CHILDREN,
	ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC,
	ZC_ERR_CNAME_MULTIPLE,
	ZC_ERR_DNAME_MULTIPLE,
	ZC_ERR_CNAME_WILDCARD_SELF,
	ZC_ERR_DNAME_WILDCARD_SELF,

	ZC_ERR_CNAME_GENERAL_ERROR, /* CNAME/DNAME error delimiter. */

	ZC_ERR_GLUE_NODE,
	ZC_ERR_GLUE_RECORD,

	ZC_ERR_GLUE_GENERAL_ERROR, /* GLUE error delimiter. */
	ZC_ERR_LAST = ZC_ERR_GLUE_GENERAL_ERROR,
};

extern const char *zonechecks_error_messages[];

/*!
 * \brief Structure for handling semantic errors.
 */
struct err_handler {
	/* Consider moving error messages here */
	unsigned errors[(-ZC_ERR_UNKNOWN) + 1]; /*!< Counting errors by type */
	unsigned error_count; /*!< Total error count */
	list_t error_list; /*!< List of all errors */
};

typedef struct err_handler err_handler_t;

typedef struct err_node {
	node_t node;  ///< must be first
	int error;
	char *zone_name;
	char *name;
	char *data;
} err_node_t;

/*!
 * \brief Inits semantic error handler. No optional events will be logged.
 *
 * \param handler Variable to be initialized.
 */
void err_handler_init(err_handler_t *err_handler);

/*!
 * \brief Free all allocated memory and deinit error handler.
 *
 * \param handler Handler to be freed
 */
void err_handler_deinit(err_handler_t *h);

/*!
 * \brief Called when error has been encountered in node. Will save error to
 *        list for future possibility to log it.
 *
 * \param handler Error handler.
 * \param zone Zone content which is being checked.
 * \param node Node with semantic error in it.
 * \param error Type of error.
 * \param data Additional info in string.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOMEM if memory error.
 */
int err_handler_handle_error(err_handler_t *handler,
                             const zone_contents_t *zone,
                             const zone_node_t *node,
                             int error, const char *data);

/*!
 * \brief Helper function - wraps its arguments into arg_t structure and
 *        calls function that does the actual work.
 *
 * \param zone Zone to be searched / checked
 * \param optional To do also optional check
 * \param handler Semantic error handler.
 */
int zone_do_sem_checks(zone_contents_t *zone, bool optional,
                       err_handler_t *handler);

/*!
 * \brief Log all found errors using standard knot log.
 *
 * \param handler Error handler
 */
void err_handler_log_errors(err_handler_t *handler);

/*! @} */
