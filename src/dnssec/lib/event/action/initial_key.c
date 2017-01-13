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

#include "dnssec/error.h"
#include "dnssec/event.h"
#include "key/internal.h"
#include "shared.h"
#include "event/action.h"
#include "event/utils.h"
#include "dnssec/keyusage.h"

/*!
 * Scan zone keys and check if ZSK and KSK key exists.
 */
static void scan_keys(dnssec_kasp_zone_t *zone, bool *has_ksk, bool *has_zsk)
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

/*!
 * Generate key and start using it immediately.
 */
static int generate_initial_key(dnssec_event_ctx_t *ctx, bool ksk)
{
	dnssec_kasp_key_t *key = NULL;
	int r = generate_key(ctx, ksk, &key);
	if (r != DNSSEC_EOK) {
		return r;
	}

	if (!ksk) {
		char *path = dnssec_keyusage_path(ctx->kasp);
		if (path == NULL) {
			return DNSSEC_ENOMEM;
		}
		dnssec_keyusage_t *keyusage = dnssec_keyusage_new();
		dnssec_keyusage_load(keyusage, path);
		dnssec_keyusage_add(keyusage, key->id, ctx->zone->name);
		dnssec_keyusage_save(keyusage, path);
		dnssec_keyusage_free(keyusage);
		free(path);
	}

	key->timing.active  = ctx->now;
	key->timing.publish = ctx->now;

	return DNSSEC_EOK;
}

static bool responds_to(dnssec_event_type_t type)
{
	return type == DNSSEC_EVENT_GENERATE_INITIAL_KEY;
}

static int plan(dnssec_event_ctx_t *ctx, dnssec_event_t *event)
{
	assert(ctx);
	assert(event);

	bool has_ksk, has_zsk;
	scan_keys(ctx->zone, &has_ksk, &has_zsk);

	if (!has_zsk || (!ctx->policy->singe_type_signing && !has_ksk)) {
		event->type = DNSSEC_EVENT_GENERATE_INITIAL_KEY;
		event->time = ctx->now;
	} else {
		clear_struct(event);
	}

	return DNSSEC_EOK;
}

static int exec(dnssec_event_ctx_t *ctx, const dnssec_event_t *event)
{
	assert(ctx);
	assert(event);

	bool has_ksk, has_zsk;
	scan_keys(ctx->zone, &has_ksk, &has_zsk);
	if (has_ksk && has_zsk) {
		return DNSSEC_EINVAL;
	}

	int r = DNSSEC_EOK;

	if (!ctx->policy->singe_type_signing && !has_ksk) {
		r = generate_initial_key(ctx, true);
	}

	if (r == DNSSEC_EOK && !has_zsk) {
		r = generate_initial_key(ctx, false);
	}

	if (r == DNSSEC_EOK) {
		r = dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
	}

	return r;
}

const event_action_functions_t event_action_initial_key = {
	.responds_to = responds_to,
	.plan        = plan,
	.exec        = exec
};
