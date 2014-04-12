/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <dirent.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>

#include "common/debug.h"
#include "common/errcode.h"
#include "common/mempattern.h"

#include "dnssec/error.h"
#include "dnssec/kasp.h"
#include "dnssec/keystore.h"
#include "dnssec/sign.h"

#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/consts.h"
#include "libknot/rdata/dnskey.h"
#include "knot/dnssec/zone-keys.h"

/*!
 * \brief Get zone key by a keytag.
 */
zone_key_t *get_zone_key(const zone_keyset_t *keyset, uint16_t search)
{
	if (!keyset) {
		return NULL;
	}

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		uint16_t keytag = dnssec_key_get_keytag(key->key);
		if (keytag == search) {
			return key;
		}
	}

	return NULL;
}

/*!
 * \brief Get key feature flags from key parameters.
 */
static int set_key(dnssec_kasp_key_t *kasp_key, zone_key_t *zone_key)
{
	assert(kasp_key);
	assert(zone_key);

	time_t now = time(NULL);
	dnssec_kasp_key_timing_t *timing = &kasp_key->timing;

	// cryptographic context

	dnssec_sign_ctx_t *ctx = NULL;
	int r = dnssec_sign_new(&ctx, kasp_key->key);
	if (r != DNSSEC_EOK) {
		return KNOT_ERROR;
	}

	zone_key->key = kasp_key->key;
	zone_key->ctx = ctx;

	// next event computation

	time_t next = LONG_MAX;
	time_t timestamps[4] = {
	        timing->active,
		timing->publish,
	        timing->remove,
	        timing->retire,
	};

	for (int i = 0; i < 4; i++) {
		time_t ts = timestamps[i];
		if (ts != 0 && now <= ts && ts < next) {
			next = ts;
		}
	}

	zone_key->next_event = next;

	// build flags

	uint16_t flags = dnssec_key_get_flags(kasp_key->key);
	zone_key->is_ksk = flags & KNOT_RDATA_DNSKEY_FLAG_KSK;
	zone_key->is_zsk = !zone_key->is_ksk; // in future, (is_ksk && is_zsk) is possible

	zone_key->is_active = timing->active <= now &&
	                      (timing->retire == 0 || now <= timing->retire);
	zone_key->is_public = timing->publish <= now &&
	                      (timing->remove == 0 || now <= timing->remove);

	return KNOT_EOK;
}

static int load_private_keys(const char *kasp_dir, zone_keyset_t *keyset)
{
	assert(kasp_dir);
	assert(keyset);

	int result = KNOT_EOK;
	char *keystore_dir = NULL;
	dnssec_keystore_t *keystore = NULL;

	int length = asprintf(&keystore_dir, "%s/keys", kasp_dir);
	if (length < 0) {
		result = KNOT_ENOMEM;
		goto fail;
	}

	result = dnssec_keystore_create_pkcs8_dir(&keystore, keystore_dir);
	if (result != DNSSEC_EOK) {
		goto fail;
	}

	for (size_t i = 0; i < keyset->count; i++) {
		if (!keyset->keys[i].is_active) {
			continue;
		}
		#warning "Missing private key loading here."
	}

	result = KNOT_EOK;
fail:
	dnssec_keystore_close(keystore);
	free(keystore_dir);

	return result;
}

/*!
 * \brief Load zone keys from a key directory.
 *
 * \todo Maybe use dynamic list instead of fixed size array.
 */
int load_zone_keys(const char *keydir_name, const char *zone_name,
                   zone_keyset_t *keyset_ptr)
{
	if (!keydir_name || !zone_name || !keyset_ptr) {
		return KNOT_EINVAL;
	}

	zone_keyset_t keyset = {0};

	int r = dnssec_kasp_open_dir(keydir_name, &keyset.kasp);
	if (r != DNSSEC_EOK) {
		log_zone_error("Zone %s: failed to open KASP - %s.\n",
		               zone_name, dnssec_strerror(r));
		return KNOT_ERROR;
	}

	r = dnssec_kasp_get_zone(keyset.kasp, zone_name, &keyset.kasp_zone);
	if (r != DNSSEC_EOK) {
		log_zone_error("Zone %s: failed to get zone from KASP - %s.\n",
		               zone_name, dnssec_strerror(r));
		free_zone_keys(&keyset);
		return KNOT_ERROR;
	}

	dnssec_kasp_key_t *kasp_keys = NULL;
	size_t keys_count = 0;
	dnssec_kasp_zone_get_keys(keyset.kasp_zone, &kasp_keys, &keys_count);
	if (keys_count == 0) {
		log_zone_error("Zone %s: no signing keys available.\n",
		               zone_name);
		free_zone_keys(&keyset);
		return KNOT_ERROR;
	}

	keyset.keys = calloc(keys_count, sizeof(zone_key_t));
	if (!keyset.keys) {
		free_zone_keys(&keyset);
		return KNOT_ENOMEM;
	}

	keyset.count = keys_count;
	for (size_t i = 0; i < keys_count; i++) {
		set_key(&kasp_keys[i], &keyset.keys[i]);
	}

	r = load_private_keys(keydir_name, &keyset);
	if (r != KNOT_EOK) {
		free_zone_keys(&keyset);
		return r;
	}

	*keyset_ptr = keyset;
	return KNOT_EOK;
}

/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 */
void free_zone_keys(zone_keyset_t *keyset)
{
	if (!keyset) {
		return;
	}

	for (size_t i = 0; i < keyset->count; i++) {
		dnssec_sign_free(keyset->keys[i].ctx);
	}

	dnssec_kasp_free_zone(keyset->kasp_zone);
	dnssec_kasp_close(keyset->kasp);
	free(keyset->keys);

	memset(keyset, '\0', sizeof(*keyset));
}

/*!
 * \brief Get timestamp of the next key event.
 */
time_t knot_get_next_zone_key_event(const zone_keyset_t *keyset)
{
	time_t result = LONG_MAX;

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		if (key->next_event < result) {
			result = key->next_event;
		}
	}

	return result;
}
