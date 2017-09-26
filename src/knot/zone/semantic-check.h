/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/zone/node.h"
#include "knot/zone/contents.h"

/*!
 *\brief Internal error constants. General errors are added for convenience,
 *       so that code does not have to change if new errors are added.
 */
typedef enum {
	ZC_ERR_UNKNOWN = -50,

	ZC_ERR_MISSING_SOA,
	ZC_ERR_MISSING_NS_DEL_POINT,

	ZC_ERR_GENERIC_GENERAL_ERROR, /* Generic error delimiter. */

	ZC_ERR_RRSIG_RDATA_TYPE_COVERED,
	ZC_ERR_RRSIG_RDATA_TTL,
	ZC_ERR_RRSIG_RDATA_EXPIRATION,
	ZC_ERR_RRSIG_RDATA_INCEPTION,
	ZC_ERR_RRSIG_RDATA_LABELS,
	ZC_ERR_RRSIG_RDATA_OWNER,
	ZC_ERR_RRSIG_NO_RRSIG,
	ZC_ERR_RRSIG_SIGNED,
	ZC_ERR_RRSIG_TTL,
	ZC_ERR_RRSIG_UNVERIFIABLE,

	ZC_ERR_RRSIG_GENERAL_ERROR, /* RRSIG error delimiter. */

	ZC_ERR_NSEC_NONE,
	ZC_ERR_NSEC_RDATA_BITMAP,
	ZC_ERR_NSEC_RDATA_MULTIPLE,
	ZC_ERR_NSEC_RDATA_CHAIN,

	ZC_ERR_NSEC_GENERAL_ERROR, /* NSEC error delimiter. */

	ZC_ERR_NSEC3_NONE,
	ZC_ERR_NSEC3_INSECURE_DELEGATION_OPT,
	ZC_ERR_NSEC3_EXTRA_RECORD,
	ZC_ERR_NSEC3_RDATA_TTL,
	ZC_ERR_NSEC3_RDATA_CHAIN,
	ZC_ERR_NSEC3_RDATA_BITMAP,
	ZC_ERR_NSEC3_RDATA_FLAGS,
	ZC_ERR_NSEC3_RDATA_SALT,
	ZC_ERR_NSEC3_RDATA_ALG,
	ZC_ERR_NSEC3_RDATA_ITERS,

	ZC_ERR_NSEC3_PARAM_RDATA_FLAGS,
	ZC_ERR_NSEC3_PARAM_RDATA_ALG,

	ZC_ERR_NSEC3_GENERAL_ERROR, /* NSEC3 error delimiter. */

	ZC_ERR_CNAME_EXTRA_RECORDS,
	ZC_ERR_CNAME_MULTIPLE,
	ZC_ERR_DNAME_CHILDREN,

	ZC_ERR_CNAME_GENERAL_ERROR, /* CNAME/DNAME error delimiter. */

	ZC_ERR_GLUE_RECORD,

	ZC_ERR_DS_RDATA_ALG,
	ZC_ERR_DS_RDATA_DIGLEN,

	ZC_ERR_INVALID_KEY,

	ZC_ERR_CDS_CDNSKEY,

	ZC_ERR_LAST,
} zc_error_t;

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
typedef void (*error_cb) (err_handler_t *ctx, const zone_contents_t *zone,
                          const zone_node_t *node, zc_error_t error, const char *data);

struct err_handler {
	error_cb cb;
	bool fatal_error;
};

/*!
 * \brief Check zone for semantic errors.
 *
 * Errors are logged in error handler.
 *
 * \param zone      Zone to be searched / checked.
 * \param optional  To do also optional check.
 * \param handler   Semantic error handler.
 * \param time      Check zone at given time (rrsig expiration).
 *
 * \retval KNOT_EOK no error found
 * \retval KNOT_ESEMCHECK found semantic error
 * \retval KNOT_EINVAL or other error
 */
int zone_do_sem_checks(zone_contents_t *zone, bool optional,
                       err_handler_t *handler, time_t time);
