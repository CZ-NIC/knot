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

#include "event/keysearch.h"
#include "key/internal.h"

static bool newer_key(const dnssec_kasp_key_t *prev, const dnssec_kasp_key_t *cur)
{
	return cur->timing.created == 0 ||
	       cur->timing.created >= prev->timing.created;
}

dnssec_kasp_key_t *last_matching_key(dnssec_kasp_zone_t *zone,
				     key_match_cb match_cb, void *data)
{
	assert(zone);

	dnssec_kasp_key_t *match = NULL;

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(i, keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(i);
		if ((match == NULL || newer_key(match, key)) && match_cb(key, data)) {
			match = key;
		}
	}

	return match;
}

void zone_check_ksk_and_zsk(dnssec_kasp_zone_t *zone,
			    bool *has_ksk, bool *has_zsk)
{
	assert(zone);
	assert(has_ksk);
	assert(has_zsk);

	*has_ksk = false;
	*has_zsk = false;

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(i, keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(i);
		uint16_t flags = dnssec_key_get_flags(key->key);
		if (flags == DNSKEY_FLAGS_KSK) {
			*has_ksk = true;
		} else if (flags == DNSKEY_FLAGS_ZSK) {
			*has_zsk = true;
		}
	}
}
