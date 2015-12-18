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

#include "dnssec/error.h"
#include "event/action.h"
#include "kasp/zone.h"
#include "key/internal.h"
#include "shared.h"

/*!
 * Generate new key with parameters from KASP policy and add it into zone.
 */
int generate_key(dnssec_event_ctx_t *ctx, bool ksk, dnssec_kasp_key_t **key_ptr)
{
	assert(ctx);
	assert(ctx->zone);
	assert(ctx->keystore);
	assert(ctx->policy);

	dnssec_key_algorithm_t algorithm = ctx->policy->algorithm;
	unsigned size = ksk ? ctx->policy->ksk_size : ctx->policy->zsk_size;

	// generate key in the keystore

	char *id = NULL;
	int r = dnssec_keystore_generate_key(ctx->keystore, algorithm, size, &id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// create KASP key

	dnssec_key_t *dnskey = NULL;
	r = dnssec_key_new(&dnskey);
	if (r != DNSSEC_EOK) {
		free(id);
		return r;
	}

	r = dnssec_key_set_dname(dnskey, ctx->zone->dname);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(dnskey);
		free(id);
		return r;
	}

	dnssec_key_set_flags(dnskey, dnskey_flags(ksk));
	dnssec_key_set_algorithm(dnskey, algorithm);

	r = dnssec_key_import_keystore(dnskey, ctx->keystore, id);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(dnskey);
		free(id);
		return r;
	}

	dnssec_kasp_key_t *key = calloc(1, sizeof(*key));
	if (!key) {
		dnssec_key_free(dnskey);
		free(id);
		return DNSSEC_ENOMEM;
	}

	key->id = id;
	key->key = dnskey;
	key->timing.created = ctx->now;

	// add into KASP zone

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(ctx->zone);
	dnssec_list_append(keys, key);

	if (key_ptr) {
		*key_ptr = key;
	}

	return DNSSEC_EOK;
}
