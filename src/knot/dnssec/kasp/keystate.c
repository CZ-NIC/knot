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

#include <assert.h>
#include <time.h>
#include <string.h>

#include "knot/dnssec/kasp/policy.h"
#include "knot/dnssec/kasp/keystate.h"

key_state_t get_key_state(const knot_kasp_key_t *key, knot_time_t moment)
{
	if (!key || moment <= 0)
	{
		return DNSSEC_KEY_STATE_INVALID;
	}

	/*
	 * The meaning of unset timing parameter is different for key
	 * introduction and withdrawal. This is expected by the server.
	 * The keys can be used without timing metadata.
	 *
	 * However, it creates a lot of complications. It would be easier
	 * to find a different approach (persistent key states, different
	 * meaning of unset parameter when policy is used, etc.).
	 */

	const knot_kasp_key_timing_t *t = &key->timing;

	bool removed = (knot_time_cmp(t->remove, moment) <= 0);
	bool retired = (knot_time_cmp(t->retire, moment) <= 0);

	bool published = !removed && (knot_time_cmp(t->publish, moment) <= 0);
	bool ready = !retired && (knot_time_cmp(t->ready, moment) <= 0);
	bool activated = !retired && (knot_time_cmp(t->active, moment) <= 0);

	/*
	 * Evaluate special transition states as invalid. E.g., when signatures
	 * are pre-published during algorithm rotation.
	 */

	if (retired && removed) {
		return DNSSEC_KEY_STATE_REMOVED;
	}

	if (retired && !removed) {
		return DNSSEC_KEY_STATE_RETIRED;
	}

	if (published && activated) {
		return DNSSEC_KEY_STATE_ACTIVE;
	}

	if (published && !ready) {
		return DNSSEC_KEY_STATE_PUBLISHED;
	}

	if (ready && !activated) {
		return DNSSEC_KEY_STATE_READY;
	}

	return DNSSEC_KEY_STATE_INVALID;
}
