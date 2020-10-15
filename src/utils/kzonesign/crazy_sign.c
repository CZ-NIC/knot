/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "crazy_sign.h"

#include "knot/dnssec/key-events.h"
#include "knot/dnssec/rrset-sign.h"

static int crazy_sign_node(zone_node_t *node, zone_sign_ctx_t *sign_ctx)
{
	knot_rrset_t rrsigs;
	knot_rrset_init(&rrsigs, node->owner, KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, 0);

	int ret = KNOT_EOK;

	for (int i = 0; i < node->rrset_count && ret == KNOT_EOK; i++) {
		knot_rrset_t rr = node_rrset_at(node, i);

		for (size_t j = 0; j < sign_ctx->count && ret == KNOT_EOK; j++) {
			const zone_key_t *key = &sign_ctx->keys[j];

			ret = knot_sign_rrset(&rrsigs, &rr, key->key, sign_ctx->sign_ctxs[j], sign_ctx->dnssec_ctx, NULL, NULL);
		}
	}

	if (ret == KNOT_EOK) {
		ret = node_add_rrset(node, &rrsigs, NULL);
	}
	rrsigs.owner = NULL;
	knot_rrset_clear(&rrsigs, NULL);
	return ret;
}

int crazy_sign_zone(conf_t *conf, zone_t *zone)
{
	kdnssec_ctx_t kdctx = { 0 };
	int ret = kdnssec_ctx_init(conf, &kdctx, zone->name, zone->kaspdb, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_sign_ctx_t *sign_ctx = NULL;
	zone_keyset_t keyset = { 0 };
	ret = load_zone_keys(&kdctx, &keyset, false);
	if (ret == KNOT_DNSSEC_ENOKEY) {
		zone_sign_reschedule_t unused = { 0 };
		ret = knot_dnssec_key_rollover(&kdctx, KEY_ROLL_ALLOW_ALL, &unused);
		if (ret == KNOT_EOK) {
			ret = load_zone_keys(&kdctx, &keyset, false);
		}
	}
	if (ret != KNOT_EOK) {
		goto end;
	}

	sign_ctx = zone_sign_ctx(&keyset, &kdctx);
	if (sign_ctx == NULL) {
		ret = KNOT_ENOMEM;
		goto end;
	}

	ret = zone_tree_apply(zone->contents->nodes, (zone_tree_apply_cb_t)crazy_sign_node, sign_ctx);
	if (ret == KNOT_EOK) {
		ret = zone_tree_apply(zone->contents->nsec3_nodes, (zone_tree_apply_cb_t)crazy_sign_node, sign_ctx);
	}

end:
	zone_sign_ctx_free(sign_ctx);
	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&kdctx);
	return ret;
}
