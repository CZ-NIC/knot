/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include <string.h>

#include "dnssec/keystate.h"

#define PAST   1426852710
#define NOW    1426852711
#define FUTURE 1426852712

static const dnssec_kasp_key_timing_t INITIAL_TIMING = {
	.created = PAST,
	.publish = FUTURE,
	.active  = FUTURE,
	.retire  = FUTURE,
	.remove  = FUTURE
};

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_kasp_key_t key = { .key = NULL, .timing = INITIAL_TIMING };

	// valid states

	key.timing.publish = PAST;
	ok(get_key_state(&key, NOW) == DNSSEC_KEY_STATE_PUBLISHED, "published");

	key.timing.active = PAST;
	ok(get_key_state(&key, NOW) == DNSSEC_KEY_STATE_ACTIVE, "active");

	key.timing.retire = PAST;
	ok(get_key_state(&key, NOW) == DNSSEC_KEY_STATE_RETIRED, "retired");

	key.timing.remove = PAST;
	ok(get_key_state(&key, NOW) == DNSSEC_KEY_STATE_REMOVED, "removed");

	memset(&key.timing, 0, sizeof(key.timing));
	ok(get_key_state(&key, NOW) == DNSSEC_KEY_STATE_ACTIVE, "default (active)");

	// currently unsupported

	key.timing = INITIAL_TIMING;
	ok(get_key_state(&key, NOW) == DNSSEC_KEY_STATE_INVALID, "created");

	key.timing.publish = FUTURE;
	key.timing.active = PAST;
	ok(get_key_state(&key, NOW) == DNSSEC_KEY_STATE_INVALID, "signature pre-publish");

	return 0;
}
