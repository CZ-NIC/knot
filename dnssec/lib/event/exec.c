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
#include "event/keysearch.h"
#include "kasp/zone.h"
#include "key/internal.h"
#include "shared.h"

/*!
 * Generate initial KSK or ZSK key.
 */
static int generate_key(dnssec_event_ctx_t *ctx, bool ksk, dnssec_kasp_key_t **key_ptr)
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

	r = dnssec_key_set_dname(dnskey, ctx->zone->dname);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(dnskey);
		return r;
	}

	dnssec_key_set_flags(dnskey, dnskey_flags(ksk));

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

#warning Needs more systematic approach for initial timing values.
	key->key = dnskey;
	key->timing.created = ctx->now;
	key->timing.publish = ctx->now;
	key->timing.active  = ctx->now;

	// add into KASP zone

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(ctx->zone);
	dnssec_list_append(keys, key);

	if (key_ptr) {
		*key_ptr = key;
	}

	return DNSSEC_EOK;
}

static int generate_initial_keys(dnssec_event_ctx_t *ctx)
{
	assert(ctx);

	bool has_ksk, has_zsk;
	zone_check_ksk_and_zsk(ctx->zone, &has_ksk, &has_zsk);
	if (has_ksk && has_zsk) {
		return DNSSEC_EINVAL;
	}

	int r;

	if (!has_ksk) {
		r = generate_key(ctx, true, NULL);
		if (r != DNSSEC_EOK) {
			return r;
		}
	}

	if (!has_zsk) {
		r = generate_key(ctx, false, NULL);
		if (r != DNSSEC_EOK) {
			return r;
		}
	}

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

static int zsk_rotation_init(dnssec_event_ctx_t *ctx)
{
	dnssec_kasp_key_t *new_key = NULL;
	int r = generate_key(ctx, false, &new_key);
	if (r != DNSSEC_EOK) {
		return r;
	}

#warning Can't set "active" to zero.
	new_key->timing.publish = ctx->now;
	new_key->timing.active = UINT32_MAX;

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

#warning COPY-PASTE
#include "event/keystate.h"
static bool active_zsk_key(const dnssec_kasp_key_t *key, void *data)
{
	dnssec_event_ctx_t *ctx = data;

	return dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK &&
	       get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_ACTIVE;
}

#warning COPY-PASTE
static bool rolling_zsk_key(const dnssec_kasp_key_t *key, void *data)
{
	dnssec_event_ctx_t *ctx = data;

	return dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK &&
	       get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_PUBLISHED;
}


static int zsk_rotation_finish(dnssec_event_ctx_t *ctx)
{
#warning Missing checks.
	dnssec_kasp_key_t *active = last_matching_key(ctx->zone, active_zsk_key, ctx);
	dnssec_kasp_key_t *rolling = last_matching_key(ctx->zone, rolling_zsk_key, ctx);

	rolling->timing.active = ctx->now;

	active->timing.retire = ctx->now;
	active->timing.remove = ctx->now;

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
	case DNSSEC_EVENT_ZSK_ROTATION_INIT:
		return zsk_rotation_init(ctx);
	case DNSSEC_EVENT_ZSK_ROTATION_FINISH:
		return zsk_rotation_finish(ctx);
	default:
		return DNSSEC_EINVAL;
	};
}
