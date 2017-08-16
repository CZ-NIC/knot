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



	const knot_kasp_key_timing_t *t = &key->timing;

	bool removed = (knot_time_cmp(t->remove, moment) <= 0);
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
