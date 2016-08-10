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



/*!
 *\brief Internal error constants. General errors are added for convenience,
 *       so that code does not have to change if new errors are added.
 */
enum zonechecks_errors {
	ZC_ERR_UNKNOWN = -50,

	ZC_ERR_MISSING_SOA,
	ZC_ERR_MISSING_NS_DEL_POINT,

	ZC_ERR_GENERIC_GENERAL_ERROR, /* Generic error delimiter. */

	ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
	ZC_ERR_RRSIG_RDATA_TTL,
	ZC_ERR_RRSIG_RDATA_EXPIRATION,
	ZC_ERR_RRSIG_RDATA_LABELS,
	ZC_ERR_RRSIG_RDATA_DNSKEY_OWNER,
	ZC_ERR_RRSIG_NO_RRSIG,
	ZC_ERR_RRSIG_SIGNED,
	ZC_ERR_RRSIG_TTL,

	ZC_ERR_RRSIG_GENERAL_ERROR, /* RRSIG error delimiter. */

	ZC_ERR_NO_NSEC,
	ZC_ERR_NSEC_RDATA_BITMAP,
	ZC_ERR_NSEC_RDATA_MULTIPLE,
	ZC_ERR_NSEC_RDATA_CHAIN,

	ZC_ERR_NSEC_GENERAL_ERROR, /* NSEC error delimiter. */

	ZC_ERR_NSEC3_NOT_FOUND,
	ZC_ERR_NSEC3_INSECURE_DELEGATION_OPT,
	ZC_ERR_NSEC3_TTL,
	ZC_ERR_NSEC3_RDATA_CHAIN,
	ZC_ERR_NSEC3_EXTRA_RECORD,

	ZC_ERR_NSEC3_GENERAL_ERROR, /* NSEC3 error delimiter. */

	ZC_ERR_CNAME_EXTRA_RECORDS,
	ZC_ERR_DNAME_CHILDREN,
	ZC_ERR_CNAME_MULTIPLE,
	ZC_ERR_DNAME_MULTIPLE,
	ZC_ERR_CNAME_WILDCARD_SELF,
	ZC_ERR_DNAME_WILDCARD_SELF,

	ZC_ERR_CNAME_GENERAL_ERROR, /* CNAME/DNAME error delimiter. */

	ZC_ERR_GLUE_RECORD,

	ZC_ERR_LAST,
};

const char *semantic_check_error_msg(int ecode);

/*!
 * \brief Structure for handling semantic errors.
 */

typedef struct err_handler err_handler_t;


/*!
 * \brief Callback for handle error.
 *
 * Return KNOT_EOK to continue in semantic checks.
 * Return other KNOT_E* to stop semantic check with error.
 */
typedef int (*error_cb) (err_handler_t *ctx, const zone_contents_t *zone,
                         const zone_node_t *node, int error, const char *data);

struct err_handler {
	error_cb cb;
};


/*!
 * \brief Check zone for semantic errors.
 *
 * Errors are logged in error handler.
 *
 * \param zone Zone to be searched / checked
 * \param optional To do also optional check
 * \param handler Semantic error handler.
 * \retval KNOT_EOK no error found
 * \retval KNOT_ESEMCHECK found semantic error
 * \retval KNOT_EINVAL or other error
 */
int zone_do_sem_checks(zone_contents_t *zone, bool optional,
                       err_handler_t *handler);

/*! @} */
