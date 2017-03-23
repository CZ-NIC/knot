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

#include <time.h>

#include "knot/dnssec/kasp/policy.h"

enum key_state {
	DNSSEC_KEY_STATE_INVALID = 0,
	DNSSEC_KEY_STATE_PUBLISHED,
	DNSSEC_KEY_STATE_READY,
	DNSSEC_KEY_STATE_ACTIVE,
	DNSSEC_KEY_STATE_RETIRED,
	DNSSEC_KEY_STATE_REMOVED,
};

typedef enum key_state key_state_t;

key_state_t get_key_state(const knot_kasp_key_t *key, time_t moment);
