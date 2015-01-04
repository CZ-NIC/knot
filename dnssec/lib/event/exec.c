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
#include "dnssec/event.h"
#include "dnssec/kasp.h"
#include "dnssec/key.h"
#include "dnssec/keystore.h"
#include "shared.h"

/*!
 * Generate initial KSK or ZSK key.
 */
static int generate_key(dnssec_event_ctx_t *ctx, bool ksk)
{
	assert(ctx->zone);
	assert(ctx->keystore);
	assert(ctx->policy);

	dnssec_key_algorithm_t algorithm = ctx->policy->algorithm;
	unsigned bits = ksk ? ctx->policy->ksk_size : ctx->policy->zsk_size;

	// generate key in the keystore

	_cleanup_free_ char *id = NULL;
	int r = dnssec_keystore_generate_key(ctx->keystore, algorithm, bits, &id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// create KASP key

	dnssec_key_t *dnskey = NULL;
	r = dnssec_key_new(&dnskey);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_key_import_keystore(dnskey, ctx->keystore, id, algorithm);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(dnskey);
		return r;
	}

	dnssec_kasp_key_t *key = calloc(1, sizeof(*key));
	if (!key) {
		dnssec_key_free(dnskey);
		return DNSSEC_ENOMEM;
	}

	key->key = dnskey;
	key->timing.publish = ctx->now;
	key->timing.active  = ctx->now;

	// add into KASP zone

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(ctx->zone);
	dnssec_list_append(keys, key);

	return DNSSEC_EOK;
}

static int generate_initial_keys(dnssec_event_ctx_t *ctx)
{
	assert(ctx);

	int r = generate_key(ctx, true);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = generate_key(ctx, false);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

_public_
int dnssec_event_execute(dnssec_event_ctx_t *ctx, dnssec_event_t *event)
{
	if (!ctx || !event) {
		return DNSSEC_EINVAL;
	}

	// TODO: additional checks on ctx content

	switch (event->type) {
	case DNSSEC_EVENT_NONE:
		return DNSSEC_EOK;
	case DNSSEC_EVENT_GENERATE_INITIAL_KEY:
		return generate_initial_keys(ctx);
	default:
		return DNSSEC_EINVAL;
	};
}
