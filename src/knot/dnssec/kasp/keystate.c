/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/dnssec/kasp/keystate.h"

key_state_t get_key_state(const knot_kasp_key_t *key, knot_time_t moment)
{
	if (!key || moment <= 0) {
		return DNSSEC_KEY_STATE_INVALID;
	}

	const knot_kasp_key_timing_t *t = &key->timing;

	bool removed = (knot_time_cmp(t->remove, moment) <= 0);
	bool revoked = (knot_time_cmp(t->revoke, moment) <= 0);
	bool post_active = (knot_time_cmp(t->post_active, moment) <= 0);
	bool retired = (knot_time_cmp(t->retire, moment) <= 0);
	bool retire_active = (knot_time_cmp(t->retire_active, moment) <= 0);
	bool active = (knot_time_cmp(t->active, moment) <= 0);
	bool ready = (knot_time_cmp(t->ready, moment) <= 0);
	bool published = (knot_time_cmp(t->publish, moment) <= 0);
	bool pre_active = (knot_time_cmp(t->pre_active, moment) <= 0);
	bool created = (knot_time_cmp(t->created, moment) <= 0);

	if (removed) {
		return DNSSEC_KEY_STATE_REMOVED;
	}
	if (revoked) {
		return DNSSEC_KEY_STATE_REVOKED;
	}
	if (post_active) {
		if (retired) {
			return DNSSEC_KEY_STATE_INVALID;
		} else {
			return DNSSEC_KEY_STATE_POST_ACTIVE;
		}
	}
	if (retired) {
		return DNSSEC_KEY_STATE_RETIRED;
	}
	if (retire_active) {
		return DNSSEC_KEY_STATE_RETIRE_ACTIVE;
	}
	if (active) {
		return DNSSEC_KEY_STATE_ACTIVE;
	}
	if (ready) {
		return DNSSEC_KEY_STATE_READY;
	}
	if (published) {
		return DNSSEC_KEY_STATE_PUBLISHED;
	}
	if (pre_active) {
		return DNSSEC_KEY_STATE_PRE_ACTIVE;
	}
	if (created) {
		// don't care
	}

	return DNSSEC_KEY_STATE_INVALID;
}
