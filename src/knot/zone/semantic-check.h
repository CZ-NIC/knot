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
 *\brief Internal error constants.
 */
typedef enum {
	// Mandatory checks.
	SEM_ERR_SOA_NONE,

	SEM_ERR_CNAME_EXTRA_RECORDS,
	SEM_ERR_CNAME_MULTIPLE,

	SEM_ERR_DNAME_CHILDREN,

	// Optional checks.
	SEM_ERR_NS_APEX,
	SEM_ERR_NS_GLUE,

	SEM_ERR_RRSIG_RDATA_TYPE_COVERED,
	SEM_ERR_RRSIG_RDATA_TTL,
	SEM_ERR_RRSIG_RDATA_EXPIRATION,
	SEM_ERR_RRSIG_RDATA_INCEPTION,
	SEM_ERR_RRSIG_RDATA_LABELS,
	SEM_ERR_RRSIG_RDATA_OWNER,
	SEM_ERR_RRSIG_NO_RRSIG,
	SEM_ERR_RRSIG_SIGNED,
	SEM_ERR_RRSIG_TTL,
	SEM_ERR_RRSIG_UNVERIFIABLE,

	SEM_ERR_NSEC_NONE,
	SEM_ERR_NSEC_RDATA_BITMAP,
	SEM_ERR_NSEC_RDATA_MULTIPLE,
	SEM_ERR_NSEC_RDATA_CHAIN,

	SEM_ERR_NSEC3_NONE,
	SEM_ERR_NSEC3_INSECURE_DELEGATION_OPT,
	SEM_ERR_NSEC3_EXTRA_RECORD,
	SEM_ERR_NSEC3_RDATA_TTL,
	SEM_ERR_NSEC3_RDATA_CHAIN,
	SEM_ERR_NSEC3_RDATA_BITMAP,
	SEM_ERR_NSEC3_RDATA_FLAGS,
	SEM_ERR_NSEC3_RDATA_SALT,
	SEM_ERR_NSEC3_RDATA_ALG,
	SEM_ERR_NSEC3_RDATA_ITERS,

	SEM_ERR_NSEC3PARAM_RDATA_FLAGS,
	SEM_ERR_NSEC3PARAM_RDATA_ALG,

	SEM_ERR_DS_RDATA_ALG,
	SEM_ERR_DS_RDATA_DIGLEN,

	SEM_ERR_DNSKEY_NONE,
	SEM_ERR_DNSKEY_INVALID,
	SEM_ERR_DNSKEY_RDATA_PROTOCOL,

	SEM_ERR_CDS_NONE,
	SEM_ERR_CDS_MULTIPLE,
	SEM_ERR_CDS_NOT_MATCH,

	SEM_ERR_CDNSKEY_NONE,
	SEM_ERR_CDNSKEY_MULTIPLE,
	SEM_ERR_CDNSKEY_NO_DNSKEY,

	// General error!
	SEM_ERR_UNKNOWN
} sem_error_t;

const char *sem_error_msg(sem_error_t code);

/*!
 * \brief Structure for handling semantic errors.
 */
typedef struct sem_handler sem_handler_t;

/*!
 * \brief Callback for handle error.
 *
 * Return KNOT_EOK to continue in semantic checks.
 * Return other KNOT_E* to stop semantic check with error.
 */
typedef void (*sem_callback) (sem_handler_t *ctx, const zone_contents_t *zone,
                              const zone_node_t *node, sem_error_t error, const char *data);

struct sem_handler {
	sem_callback cb;
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
int sem_checks_process(zone_contents_t *zone, bool optional, sem_handler_t *handler,
                       time_t time);
