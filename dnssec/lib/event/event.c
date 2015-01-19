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

#include <assert.h>
#include <stdbool.h>

#include "dnssec/error.h"
#include "dnssec/event.h"
#include "dnssec/kasp.h"
#include "key/internal.h"
#include "shared.h"

static dnssec_kasp_key_t *get_last_key(dnssec_kasp_zone_t *zone, bool ksk)
{
	assert(zone);

	dnssec_kasp_key_t *last = NULL;

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(i, keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(i);
		if (dnssec_key_get_flags(key->key) != dnskey_flags(ksk)) {
			continue;
		}

		last = key;
	}

	return last;
}

_public_
int dnssec_event_get_next(dnssec_event_ctx_t *ctx, dnssec_event_t *event_ptr)
{
	if (!ctx || !event_ptr) {
		return DNSSEC_EINVAL;
	}

	// TODO: additional checks on ctx content

	dnssec_event_t event = { 0 };

	// initial keys

	dnssec_kasp_key_t *last_ksk = get_last_key(ctx->zone, true);
	dnssec_kasp_key_t *last_zsk = get_last_key(ctx->zone, false);
	if (!last_ksk || !last_zsk) {
		event.time = ctx->now;
		event.type = DNSSEC_EVENT_GENERATE_INITIAL_KEY;
	}

	*event_ptr = event;
	return DNSSEC_EOK;
}
