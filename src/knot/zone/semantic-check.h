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
 * \file semantic-check.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief DNS zone semantic checks.
 *
 * \addtogroup zoneparser
 * @{
 */

#ifndef _KNOT_SEMANTIC_CHECK_H_
#define _KNOT_SEMANTIC_CHECK_H_

#include "libknot/zone/node.h"
#include "libknot/zone/zone-contents.h"

/*!
 *\brief Internal error constants. General errors are added for convenience,
 *       so that code does not have to change if new errors are added.
 */
enum zonechecks_errors {
	ZC_ERR_UNKNOWN = -50,

	ZC_ERR_MISSING_SOA,
	ZC_ERR_MISSING_NS_DEL_POINT,

	ZC_ERR_GENERIC_GENERAL_ERROR, /* isn't there a better name? */

	ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
	ZC_ERR_RRSIG_RDATA_TTL,
	ZC_ERR_RRSIG_RDATA_LABELS,
	ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER,
	ZC_ERR_RRSIG_RDATA_SIGNED_WRONG,
	ZC_ERR_RRSIG_NO_RRSIG,
	ZC_ERR_RRSIG_SIGNED,
	ZC_ERR_RRSIG_OWNER,
	ZC_ERR_RRSIG_CLASS,
	ZC_ERR_RRSIG_TTL,
	ZC_ERR_RRSIG_NOT_ALL,

	ZC_ERR_RRSIG_GENERAL_ERROR,

	ZC_ERR_NO_NSEC,
	ZC_ERR_NSEC_RDATA_BITMAP,
	ZC_ERR_NSEC_RDATA_MULTIPLE,
	ZC_ERR_NSEC_RDATA_CHAIN,
	ZC_ERR_NSEC_RDATA_CHAIN_NOT_CYCLIC,

	ZC_ERR_NSEC_GENERAL_ERROR,

	ZC_ERR_NSEC3_UNSECURED_DELEGATION,
	ZC_ERR_NSEC3_NOT_FOUND,
	ZC_ERR_NSEC3_UNSECURED_DELEGATION_OPT,
	ZC_ERR_NSEC3_RDATA_TTL,
	ZC_ERR_NSEC3_RDATA_CHAIN,
	ZC_ERR_NSEC3_RDATA_BITMAP,
	ZC_ERR_NSEC3_EXTRA_RECORD,

	ZC_ERR_NSEC3_GENERAL_ERROR,

	ZC_ERR_CNAME_EXTRA_RECORDS,
	ZC_ERR_DNAME_CHILDREN,
	ZC_ERR_CNAME_EXTRA_RECORDS_DNSSEC,
	ZC_ERR_CNAME_MULTIPLE,
	ZC_ERR_DNAME_MULTIPLE,
	ZC_ERR_CNAME_WILDCARD_SELF,
	ZC_ERR_DNAME_WILDCARD_SELF,

	ZC_ERR_CNAME_GENERAL_ERROR,

	ZC_ERR_GLUE_NODE,
	ZC_ERR_GLUE_RECORD,

	ZC_ERR_GLUE_GENERAL_ERROR,
};

/*!
 * \brief Arguments to be used with tree traversal functions. Uses void pointers
 *        to be more versatile.
 * \todo This is not needed. Just enumerate all the variables.
 *
 */
struct arg {
	void *arg1; /* FILE *f / zone */
	void *arg2; /* skip_list_t */
	void *arg3; /* zone */
	void *arg4; /* first node */
	void *arg5; /* last node */
	void *arg6; /* error handler */
	void *arg7; /* CRC */
	int error_code; /* Error code. */
};

typedef struct arg arg_t;

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
	uint errors[(-ZC_ERR_UNKNOWN) + 1]; /*!< Array with error messages */
	uint error_count; /*!< Total error count */
};

typedef struct err_handler err_handler_t;

/*!
 * \brief Creates new semantic error handler.
 *
 * \param log_cname If true, log all CNAME related events.
 * \param log_glue If true, log all Glue related events.
 * \param log_rrsigs If true, log all RRSIGs related events.
 * \param log_nsec If true, log all NSEC related events.
 * \param log_nsec3 If true, log all NSEC3 related events.
 *
 * \return err_handler_t * Created error handler.
 */
err_handler_t *handler_new(int log_cname, int log_glue, int log_rrsigs,
                           int log_nsec, int log_nsec3);

/*!
 * \brief Called when error has been encountered in node. Will either log error
 *        or print it, depending on handler's options.
 *
 * \param handler Error handler.
 * \param node Node with semantic error in it.
 * \param error Type of error.
 * \param data Additional info in string.
 *
 * \retval KNOT_EOK on success.
 * \retval ZC_ERR_UNKNOWN if unknown error.
 * \retval ZC_ERR_ALLOC if memory error.
 */
int err_handler_handle_error(err_handler_t *handler,
				    const knot_node_t *node,
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
				      knot_zone_contents_t *zone,
				      knot_node_t *last_node,
				      const knot_node_t *first_nsec3_node,
				      const knot_node_t *last_nsec3_node,
				      char do_checks);

/*!
 * \brief This function prints all errors that occured in zone.
 *
 * \param handler Error handler containing found errors.
 */
void err_handler_log_all(err_handler_t *handler);

/*!
 * \brief Helper function - wraps its arguments into arg_t structure and
 *        calls function that does the actual work.
 *
 * \param zone Zone to be searched / checked
 * \param check_level Level of semantic checks.
 * \param handler Semantic error handler.
 * \param last_node Last checked node, that is a part of NSEC(3) chain.
 */
int zone_do_sem_checks(knot_zone_contents_t *zone, int check_level,
                       err_handler_t *handler, knot_node_t *first_nsec3_node,
                       knot_node_t *last_nsec3_node);

int sem_check_node_plain(knot_zone_contents_t *zone,
                         knot_node_t *node,
                         int do_checks,
                         err_handler_t *handler,
                         int only_mandatory,
                         int *fatal_error);

#endif // _KNOT_SEMANTIC_CHECK_H_

/*! @} */
