/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/packet/pkt.h"

struct kdig_dnssec_ctx;

typedef enum {
	KDIG_VALIDATION_LOG_NONE,
	KDIG_VALIDATION_LOG_OUTCOME,
	KDIG_VALIDATION_LOG_ERRORS,
	KDIG_VALIDATION_LOG_INFOS,
} kdig_validation_log_level_t;

/*!
 * \brief Detailed DNSSEC validation of response pkt, logging to stdout.
 *
 * \param pkt            The packet with a DNS response.
 * \param dv_ctx         In/out: context structure persistent across calling this function.
 * \param level          Verbosity of the logging.
 * \param zone_name      Detected zone name.
 * \param type_needed    Out: RRtype to re-query for.
 *
 * \retval KNOT_EAGAIN   The caller shall re-query the detected zone's apex (zone_name) for requested RRtye (type_needed) and call this function again with the same context (dv_ctx) and the new DNS response packet.
 * \retval KNOT_EOK      The validation successfully took place, either finding errors and logging them, or finding all OK.
 * \return KNOT_E*       An error occured so that the validation couldn't take place.
 */
int kdig_dnssec_validate(knot_pkt_t *pkt, struct kdig_dnssec_ctx **dv_ctx,
                         kdig_validation_log_level_t level,
                         knot_dname_t zone_name[KNOT_DNAME_MAXLEN], uint16_t *type_needed);

/*!
 * \brief Free DNSSEC validation context.
 *
 * \param dv_ctx         Context structure to free.
 */
void kdig_dnssec_free(struct kdig_dnssec_ctx *dv_ctx);
