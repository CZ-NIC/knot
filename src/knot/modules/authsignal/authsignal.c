/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/include/module.h"

static knotd_in_state_t signal_query(knotd_in_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	// Applicable when search in zone fails.
	if (!(state == KNOTD_IN_STATE_MISS || state == KNOTD_IN_STATE_NODATA)) {
		return state;
	}

	const unsigned name_len = knot_dname_size(qdata->name);

	// Check for prefix mismatch.
	const char *prefix = "\x07_dsboot";
	const size_t prefix_len = 8;
	if (name_len < prefix_len || memcmp(qdata->name, prefix, prefix_len) != 0) {
		// promote NXDOMAIN to NODATA to accommodate synthesis below (= may be ENT)
		qdata->rcode = KNOT_RCODE_NOERROR;
		return KNOTD_IN_STATE_NODATA;
	}

	// Check for qtype match
	const uint16_t qtype = knot_pkt_qtype(qdata->query);
	if (!(qtype == KNOT_RRTYPE_CDS || qtype == KNOT_RRTYPE_CDNSKEY)) {
		// promote NXDOMAIN to NODATA to accommodate CDS/CDNSKEY synthesis
		qdata->rcode = KNOT_RCODE_NOERROR;
		return KNOTD_IN_STATE_NODATA;
	}

	// Copy target zone name
	knot_dname_storage_t target;
	unsigned target_len = name_len - knot_dname_size(knotd_qdata_zone_name(qdata)) - prefix_len;
	memcpy(target, qdata->name + prefix_len, target_len);
	target[target_len] = '\0';

	// Fetch CDS/CDNSKEY rrset
	knot_rrset_t rrset;
	int ret = knotd_qdata_zone_rrset(qdata, target, NULL, qtype, &rrset);
	if (ret == KNOT_ENOZONE) { // unknown zone
		return state;
	} else if (ret != KNOT_EOK) { // something weird (zone empty, apex missing, ...)
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return KNOTD_IN_STATE_ERROR;
	} else if (knot_rrset_empty(&rrset)) { // zone apex doesn't have requested type
		// promote NXDOMAIN to NODATA to accommodate synthesis of other qtype
		qdata->rcode = KNOT_RCODE_NOERROR;
		return KNOTD_IN_STATE_NODATA;
	}

	// Replace owner
	rrset.owner = (knot_dname_t *)qdata->name;

	// Insert synthetic response into packet.
	if (knot_pkt_put(pkt, 0, &rrset, KNOT_PF_FREE) != KNOT_EOK) {
		return KNOTD_IN_STATE_ERROR;
	}

	// Authoritative response.
	knot_wire_set_aa(pkt->wire);

	return KNOTD_IN_STATE_HIT;
}

int auth_signal_load(knotd_mod_t *mod)
{
	return knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, signal_query);
}

KNOTD_MOD_API(authsignal, KNOTD_MOD_FLAG_SCOPE_ZONE | KNOTD_MOD_FLAG_OPT_CONF,
              auth_signal_load, NULL, NULL, NULL);
