/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include "knot/dnssec/policy.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

int event_dnskeysign(conf_t *conf, zone_t *zone, zone_evflag_t flags)
{
	zone_update_t up = { 0 };
	kdnssec_ctx_t ctx = { 0 };
	zone_keyset_t keyset = { 0 };

	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EEMPTYZONE;
	}

	int ret = zone_update_init(&up, zone, UPDATE_INCREMENTAL | UPDATE_NO_CHSET | UPDATE_KEEPSOA);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = kdnssec_ctx_init(conf, &ctx, zone->name, zone_kaspdb(zone), NULL);
	if (ret == KNOT_EOK) {
		update_policy_from_zone(ctx.policy, zone->contents);
		ctx.policy->unsafe |= UNSAFE_KEYSET;
		ret = load_zone_keys(&ctx, &keyset, true, true);
	}
	if (ret == KNOT_EOK) {
		ret = knot_zone_sign_update_dnskeys(&up, &keyset, &ctx);
	}
	if (ret == KNOT_EOK) {
		ret = knot_zone_sign_apex_rr(&up, KNOT_RRTYPE_DNSKEY, &keyset, &ctx);
	}
	if (ret == KNOT_EOK) {
		ret = zone_update_commit(conf, &up);
	} else {
		zone_update_clear(&up);
		zone_update_error(conf, zone);
	}

	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return ret;
}
