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
#include <limits.h>
#include <stdbool.h>
#include <time.h>

#include "dnssec/error.h"
#include "dnssec/keystore.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/libknot.h"
#include "libknot/rrtype/dnskey.h"

dynarray_define(keyptr, zone_key_t *, DYNARRAY_VISIBILITY_PUBLIC)

const uint16_t DNSKEY_FLAGS_KSK = 257;
const uint16_t DNSKEY_FLAGS_ZSK = 256;

uint16_t dnskey_flags(bool is_ksk)
{
	return is_ksk ? DNSKEY_FLAGS_KSK : DNSKEY_FLAGS_ZSK;
}

int kdnssec_generate_key(kdnssec_ctx_t *ctx, bool ksk, knot_kasp_key_t **key_ptr)
{
	assert(ctx);
	assert(ctx->zone);
	assert(ctx->keystore);
	assert(ctx->policy);

	dnssec_key_algorithm_t algorithm = ctx->policy->algorithm;
	unsigned size = ksk ? ctx->policy->ksk_size : ctx->policy->zsk_size;

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *kasp_key = &ctx->zone->keys[i];
		if (dnssec_key_get_flags(kasp_key->key) == dnskey_flags(ksk) &&
		    dnssec_key_get_algorithm(kasp_key->key) != ctx->policy->algorithm) {
			log_zone_warning(ctx->zone->dname, "DNSSEC, creating key with different"
					 " algorithm than policy");
			break;
		}
	}

	// generate key in the keystore

	char *id = NULL;
	int r = dnssec_keystore_generate_key(ctx->keystore, algorithm, size, &id);
	if (r != KNOT_EOK) {
		return r;
	}

	// create KASP key

	dnssec_key_t *dnskey = NULL;
	r = dnssec_key_new(&dnskey);
	if (r != KNOT_EOK) {
		free(id);
		return r;
	}

	r = dnssec_key_set_dname(dnskey, ctx->zone->dname);
	if (r != KNOT_EOK) {
		dnssec_key_free(dnskey);
		free(id);
		return r;
	}

	dnssec_key_set_flags(dnskey, dnskey_flags(ksk));
	dnssec_key_set_algorithm(dnskey, algorithm);

	r = dnssec_key_import_keystore(dnskey, ctx->keystore, id);
	if (r != KNOT_EOK) {
		dnssec_key_free(dnskey);
		free(id);
		return r;
	}

	knot_kasp_key_t *key = calloc(1, sizeof(*key));
	if (!key) {
		dnssec_key_free(dnskey);
		free(id);
		return KNOT_ENOMEM;
	}

	key->id = id;
	key->key = dnskey;
	key->timing.created = ctx->now;

	r = kasp_zone_append(ctx->zone, key);
	free(key);
	if (r != KNOT_EOK) {
		dnssec_key_free(dnskey);
		free(id);
		return r;
	}

	if (key_ptr) {
		*key_ptr = &ctx->zone->keys[ctx->zone->num_keys - 1];
	}

	return KNOT_EOK;
}

int kdnssec_share_key(kdnssec_ctx_t *ctx, const knot_dname_t *from_zone, const char *key_id)
{
	knot_dname_t *to_zone = knot_dname_copy(ctx->zone->dname, NULL);
	if (to_zone == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = kdnssec_ctx_commit(ctx);
	if (ret != KNOT_EOK) {
		free(to_zone);
		return ret;
	}

	ret = kasp_db_share_key(*ctx->kasp_db, from_zone, ctx->zone->dname, key_id);
	if (ret != KNOT_EOK) {
		free(to_zone);
		return ret;
	}

	kasp_zone_clear(ctx->zone);
	ret = kasp_zone_load(ctx->zone, to_zone, *ctx->kasp_db);
	free(to_zone);
	return ret;
}

int kdnssec_delete_key(kdnssec_ctx_t *ctx, knot_kasp_key_t *key_ptr)
{
	assert(ctx);
	assert(ctx->zone);
	assert(ctx->keystore);
	assert(ctx->policy);

	ssize_t key_index = key_ptr - ctx->zone->keys;

	if (key_index < 0 || key_index >= ctx->zone->num_keys) {
		return KNOT_EINVAL;
	}

	bool key_still_used_in_keystore = false;
	int ret = kasp_db_delete_key(*ctx->kasp_db, ctx->zone->dname, key_ptr->id, &key_still_used_in_keystore);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!key_still_used_in_keystore) {
		ret = dnssec_keystore_remove_key(ctx->keystore, key_ptr->id);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	dnssec_key_free(key_ptr->key);
	free(key_ptr->id);
	memmove(key_ptr, key_ptr + 1, (ctx->zone->num_keys - key_index - 1) * sizeof(*key_ptr));
	ctx->zone->num_keys--;
	return KNOT_EOK;
}

/*!
 * \brief Get key feature flags from key parameters.
 */
static int set_key(knot_kasp_key_t *kasp_key, knot_time_t now, zone_key_t *zone_key)
{
	assert(kasp_key);
	assert(zone_key);

	knot_kasp_key_timing_t *timing = &kasp_key->timing;

	// cryptographic context

	dnssec_sign_ctx_t *ctx = NULL;
	int r = dnssec_sign_new(&ctx, kasp_key->key);
	if (r != DNSSEC_EOK) {
		return r;
	}

	zone_key->id = kasp_key->id;
	zone_key->key = kasp_key->key;
	zone_key->ctx = ctx;

	// next event computation

	knot_time_t next = 0;
	knot_time_t timestamps[5] = {
	        timing->active,
	        timing->publish,
	        timing->remove,
	        timing->retire,
		timing->ready,
	};

	for (int i = 0; i < 5; i++) {
		knot_time_t ts = timestamps[i];
		if (knot_time_cmp(now, ts) < 0 && knot_time_cmp(ts, next) < 0) {
			next = ts;
		}
	}

	zone_key->next_event = next;

	// key use flags

	uint16_t flags = dnssec_key_get_flags(kasp_key->key);
	zone_key->is_ksk = flags & KNOT_RDATA_DNSKEY_FLAG_KSK;
	zone_key->is_zsk = !zone_key->is_ksk;

	zone_key->is_active = (knot_time_cmp(timing->active, now) <= 0 &&
	                      knot_time_cmp(timing->retire, now) > 0);
	zone_key->is_public = (knot_time_cmp(timing->publish, now) <= 0 &&
	                      knot_time_cmp(timing->remove, now) > 0);
	zone_key->is_ready = (knot_time_cmp(timing->ready, now) <= 0 &&
	                     knot_time_cmp(timing->retire, now) > 0);

	return KNOT_EOK;
}

/*!
 * \brief Check if algorithm is allowed with NSEC3.
 */
static bool is_nsec3_allowed(uint8_t algorithm)
{
	switch (algorithm) {
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1:
		return false;
	default:
		return true;
	}
}

/*!
 * \brief Algorithm usage information.
 */
typedef struct algorithm_usage {
	unsigned ksk_count;  //!< Available KSK count.
	unsigned zsk_count;  //!< Available ZSK count.

	bool is_public;      //!< DNSKEY is published.
	bool is_stss;        //!< Used to sign all types of records.
	bool is_ksk_active;  //!< Used to sign DNSKEY records.
	bool is_zsk_active;  //!< Used to sign non-DNSKEY records.
} algorithm_usage_t;

/*!
 * \brief Check correct key usage, enable Single-Type Signing Scheme if needed.
 *
 * Each record in the zone has to be signed at least by one key for each
 * algorithm published in the DNSKEY RR set in the zone apex.
 *
 * Therefore, publishing a DNSKEY creates a requirement on active keys with
 * the same algorithm. At least one KSK key and one ZSK has to be enabled.
 * If one key type is unavailable (not just inactive and not-published), the
 * algorithm is switched to Single-Type Signing Scheme.
 */
static int prepare_and_check_keys(const knot_dname_t *zone_name, bool nsec3_enabled,
                                  zone_keyset_t *keyset)
{
	assert(zone_name);
	assert(keyset);

	const size_t max_algorithms = KNOT_DNSSEC_ALG_ECDSAP384SHA384 + 1;
	algorithm_usage_t usage[max_algorithms];
	memset(usage, 0, max_algorithms * sizeof(algorithm_usage_t));

	// count available keys

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		uint8_t algorithm = dnssec_key_get_algorithm(key->key);

		assert(algorithm < max_algorithms);
		algorithm_usage_t *u = &usage[algorithm];

		if (nsec3_enabled && !is_nsec3_allowed(algorithm)) {
			log_zone_warning(zone_name, "DNSSEC, key '%d' "
			                     "cannot be used with NSEC3",
			                     dnssec_key_get_keytag(key->key));
			key->is_public = false;
			key->is_active = false;
			key->is_ready = false;
			continue;
		}

		if (key->is_ksk) { u->ksk_count += 1; }
		if (key->is_zsk) { u->zsk_count += 1; }
	}

	// enable Single-Type Signing scheme if applicable

	for (int i = 0; i < max_algorithms; i++) {
		algorithm_usage_t *u = &usage[i];

		// either KSK or ZSK keys are available
		if ((u->ksk_count == 0) != (u->zsk_count == 0)) {
			u->is_stss = true;
			log_zone_info(zone_name, "DNSSEC, Single-Type Signing "
			                  "scheme enabled, algorithm '%d'", i);
		}
	}

	// update key flags for STSS, collect information about usage

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		algorithm_usage_t *u = &usage[dnssec_key_get_algorithm(key->key)];

		if (u->is_stss) {
			key->is_ksk = true;
			key->is_zsk = true;
		}

		if (key->is_public) { u->is_public = true; }
		if (key->is_active) { // TODO consider READY state (not for STSS for now)
			if (key->is_ksk) { u->is_ksk_active = true; }
			if (key->is_zsk) { u->is_zsk_active = true; }
		}
	}

	// validate conditions for used algorithms

	unsigned public_count = 0;

	for (int i = 0; i < max_algorithms; i++) {
		algorithm_usage_t *u = &usage[i];
		if (u->is_public) {
			public_count += 1;
			if (!u->is_ksk_active || !u->is_zsk_active) {
				return KNOT_DNSSEC_EMISSINGKEYTYPE;
			}
		}
	}

	if (public_count == 0) {
		return KNOT_DNSSEC_ENOKEY;
	}

	return KNOT_EOK;
}

/*!
 * \brief Load private keys for active keys.
 */
static int load_private_keys(dnssec_keystore_t *keystore, zone_keyset_t *keyset)
{
	assert(keystore);
	assert(keyset);

	for (size_t i = 0; i < keyset->count; i++) {
		if (!keyset->keys[i].is_active && !keyset->keys[i].is_ready) {
			continue;
		}

		zone_key_t *key = &keyset->keys[i];
		int r = dnssec_key_import_keystore(key->key, keystore, key->id);
		if (r != DNSSEC_EOK && r != DNSSEC_KEY_ALREADY_PRESENT) {
			return r;
		}
	}

	return DNSSEC_EOK;
}

/*!
 * \brief Log information about zone keys.
 */
static void log_key_info(const zone_key_t *key, const knot_dname_t *zone_name)
{
	assert(key);
	assert(zone_name);

	log_zone_info(zone_name, "DNSSEC, loaded key, tag %5d, "
			  "algorithm %d, KSK %s, ZSK %s, public %s, ready %s, active %s",
			  dnssec_key_get_keytag(key->key),
			  dnssec_key_get_algorithm(key->key),
			  key->is_ksk ? "yes" : "no",
			  key->is_zsk ? "yes" : "no",
			  key->is_public ? "yes" : "no",
			  key->is_ready ? "yes" : "no",
			  key->is_active ? "yes" : "no");
}

/*!
 * \brief Load zone keys and init cryptographic context.
 */
int load_zone_keys(knot_kasp_zone_t *zone, dnssec_keystore_t *store,
                   bool nsec3_enabled, knot_time_t now, zone_keyset_t *keyset_ptr)
{
	if (!zone || !store || !keyset_ptr) {
		return KNOT_EINVAL;
	}

	zone_keyset_t keyset = { 0 };

	if (zone->num_keys < 1) {
		log_zone_error(zone->dname, "DNSSEC, no keys are available");
		return KNOT_DNSSEC_ENOKEY;
	}

	keyset.count = zone->num_keys;
	keyset.keys = calloc(keyset.count, sizeof(zone_key_t));
	if (!keyset.keys) {
		free_zone_keys(&keyset);
		return KNOT_ENOMEM;
	}

	for (size_t i = 0; i < zone->num_keys; i++) {
		knot_kasp_key_t *kasp_key = &zone->keys[i];
		set_key(kasp_key, now, &keyset.keys[i]);
		log_key_info(&keyset.keys[i], zone->dname);
	}

	int r = prepare_and_check_keys(zone->dname, nsec3_enabled, &keyset);
	if (r != KNOT_EOK) {
		log_zone_error(zone->dname, "DNSSEC, keys validation failed (%s)",
		                   knot_strerror(r));
		free_zone_keys(&keyset);
		return r;
	}

	r = load_private_keys(store, &keyset);
	r = knot_error_from_libdnssec(r);
	if (r != KNOT_EOK) {
		log_zone_error(zone->dname, "DNSSEC, failed to load private "
		                   "keys (%s)", knot_strerror(r));
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
		dnssec_binary_free(&keyset->keys[i].precomputed_ds);
	}

	free(keyset->keys);

	memset(keyset, '\0', sizeof(*keyset));
}

/*!
 * \brief Get zone keys by keytag.
 */
struct keyptr_dynarray get_zone_keys(const zone_keyset_t *keyset, uint16_t search)
{
	struct keyptr_dynarray res = { 0 };

	for (size_t i = 0; keyset && i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		if (key != NULL && dnssec_key_get_keytag(key->key) == search) {
			keyptr_dynarray_add(&res, &key);
		}
	}

	return res;
}

/*!
 * \brief Get timestamp of next key event.
 */
knot_time_t knot_get_next_zone_key_event(const zone_keyset_t *keyset)
{
	assert(keyset);

	knot_time_t result = 0;

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		if (knot_time_cmp(key->next_event, result) < 0) {
			result = key->next_event;
		}
	}

	return result;
}

/*!
 * \brief Compute DS record rdata from key + cache it.
 */
int zone_key_calculate_ds(zone_key_t *for_key, dnssec_binary_t *out_donotfree)
{
	assert(for_key);
	assert(out_donotfree);

	int ret = KNOT_EOK;

	if (for_key->precomputed_ds.data == NULL) {
		dnssec_key_digest_t digesttype = DNSSEC_KEY_DIGEST_SHA256; // TODO !
		ret = dnssec_key_create_ds(for_key->key, digesttype, &for_key->precomputed_ds);
		ret = knot_error_from_libdnssec(ret);
	}

	*out_donotfree = for_key->precomputed_ds;
	return ret;
}
