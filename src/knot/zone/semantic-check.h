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

enum check_levels {
	SEM_CHECK_MANDATORY = 0,
	SEM_CHECK_UNSIGNED = 1,
	SEM_CHECK_NSEC = 2,
	SEM_CHECK_NSEC3 = 3
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
	ZC_ERR_NSEC3_RDATA_BITMAP,
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
	/// \TODO ADD LAST DELIMITER
};


/*!
 * \brief Structure representing handle options.
 */
struct handler_options {
	char log_cname; /*!< Log all CNAME related semantic errors. */
	char log_glue; /*!< Log all glue related semantic errors. */
	char log_rrsigs; /*!< Log all RRSIG related semantic errors. */
	char log_nsec; /*!< Log all NSEC related semantic errors. */
	char log_nsec3; /*!< Log all NSEC3 related semantic errors. */
};

/*!
 * \brief Structure for handling semantic errors.
 */
struct err_handler {
	/* Consider moving error messages here */
	struct handler_options options; /*!< Handler options. */
	unsigned errors[(-ZC_ERR_UNKNOWN) + 1]; /*!< Counting errors by type */
	unsigned error_count; /*!< Total error count */
	list_t error_list; /*!< List of all errors */
	//mm_ctx_t mm;
};

typedef struct err_handler err_handler_t;

typedef struct err_node {
	node_t node;  /// < must be first
	int error;
	knot_dname_t *zone_name;
	knot_dname_t *name;
	char *data;
} err_node_t;


typedef struct semchecks_data {
	zone_contents_t *zone;
	err_handler_t *handler; // < include fatal error or
	bool fatal_error;
	zone_node_t *last_node;
	enum check_levels level;
} semchecks_data_t;



/*!
 * \brief Inits semantic error handler. No optional events will be logged.
 *
 * \param handler Variable to be initialized.
 */
void err_handler_init(err_handler_t *err_handler);

void err_handler_del(err_handler_t *h);

/*!
 * \brief Creates new semantic error handler.
 *
 * \return err_handler_t * Created error handler.
 */
err_handler_t *err_handler_new(void);

/*!
 * \brief Called when error has been encountered in node. Will either log error
 *        or print it, depending on handler's options.
 *
 * \param handler Error handler.
 * \param zone Zone content which is being checked.
 * \param node Node with semantic error in it.
 * \param error Type of error.
 * \param data Additional info in string.
 *
 * \retval KNOT_EOK on success.
 * \retval ZC_ERR_UNKNOWN if unknown error.
 * \retval ZC_ERR_ALLOC if memory error.
 */
int err_handler_handle_error(err_handler_t *handler,
                             const zone_contents_t *zone,
                             const zone_node_t *node,
                             int error, const char *data);

/*!
 * \brief Checks if last node in NSEC/NSEC3 chain points to first node in the
 *        chain and prints possible errors.
 *
 * \param handler Semantic error handler.
 * \param zone Current zone.
 * \param last_node Last node in NSEC/NSEC3 chain.
 * \param do_checks Level of semantic checks.
 */
void log_cyclic_errors_in_zone(err_handler_t *handler,
                               zone_contents_t *zone,
                               zone_node_t *last_node,
                               const zone_node_t *first_nsec3_node,
                               const zone_node_t *last_nsec3_node,
                               char do_checks);

/*!
 * \brief Helper function - wraps its arguments into arg_t structure and
 *        calls function that does the actual work.
 *
 * \param zone Zone to be searched / checked
 * \param check_level Level of semantic checks.
 * \param handler Semantic error handler.
 * \param last_node Last checked node, that is a part of NSEC(3) chain.
 */
int zone_do_sem_checks(zone_contents_t *zone, int check_level,
                       err_handler_t *handler, zone_node_t *first_nsec3_node,
                       zone_node_t *last_nsec3_node);

/*!
 * \brief Does a non-DNSSEC semantic node check. Logs errors via error handler.
 *
 * \param zone            Zone containing the node.
 * \param node            Node to be tested.
 * \param handler         Error handler.
 * \param only_mandatory  Mandatory/optional switch.
 * \param fatal_error     Fatal error out param.
 *
 * \return KNOT_E*
 */
int sem_check_node_plain(const zone_contents_t *zone,
                         const zone_node_t *node,
                         err_handler_t *handler,
                         bool only_mandatory,
                         bool *fatal_error);

const char *error_to_message(int error);

void err_handler_log_errors(err_handler_t *handler);

/*! @} */
