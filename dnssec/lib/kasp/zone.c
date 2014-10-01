/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdlib.h>
#include <string.h>

#include "dname.h"
#include "kasp.h"
#include "kasp/internal.h"
#include "kasp/zone.h"
#include "shared.h"

/*!
 * Allocate new KASP zone.
 */
_public_
dnssec_kasp_zone_t *dnssec_kasp_zone_new(const char *name)
{
	dnssec_kasp_zone_t *zone = malloc(sizeof(*zone));
	clear_struct(zone);

	zone->dname = dname_from_ascii(name);
	dname_normalize(zone->dname);

	zone->name = dname_to_ascii(zone->dname);

	zone->keys = dnssec_list_new();

	if (!zone->keys || !zone->dname || !zone->name) {
		dnssec_kasp_zone_free(zone);
		return NULL;
	}

	return zone;
}

static void free_kasp_key(void *data, void *ctx _unused_)
{
	assert(data);
	dnssec_kasp_key_t *kasp_key = data;

	dnssec_key_free(kasp_key->key);
	free(kasp_key);
}

/*!
 * Free KASP zone keys.
 */
void kasp_zone_keys_free(dnssec_list_t *keys)
{
	dnssec_list_free_full(keys, free_kasp_key, NULL);
}

/*!
 * Free KASP zone.
 */
_public_
void dnssec_kasp_zone_free(dnssec_kasp_zone_t *zone)
{
	if (!zone) {
		return;
	}

	kasp_zone_keys_free(zone->keys);
	free(zone->dname);
	free(zone->name);

	free(zone);
}

/*!
 * Get the set of keys associated with the zone.
 */
_public_
dnssec_list_t *dnssec_kasp_zone_get_keys(dnssec_kasp_zone_t *zone)
{
	if (!zone) {
		return NULL;
	}

	return zone->keys;
}
