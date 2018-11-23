/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <limits.h>
#include <stdio.h>

#include "libdnssec/error.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/libknot.h"

#define MAX_KEY_INFO 128

dynarray_define(keyptr, zone_key_t *, DYNARRAY_VISIBILITY_PUBLIC)

void normalize_generate_flags(kdnssec_generate_flags_t *flags)
{
	if (!(*flags & DNSKEY_GENERATE_KSK) && !(*flags & DNSKEY_GENERATE_ZSK)) {
		*flags |= DNSKEY_GENERATE_ZSK;
	}
	if (!(*flags & DNSKEY_GENERATE_SEP_SPEC)) {
		if ((*flags & DNSKEY_GENERATE_KSK)) {
			*flags |= DNSKEY_GENERATE_SEP_ON;
		} else {
			*flags &= ~DNSKEY_GENERATE_SEP_ON;
		}
	}
}

int kdnssec_generate_key(kdnssec_ctx_t *ctx, kdnssec_generate_flags_t flags,
			 knot_kasp_key_t **key_ptr)
{
	assert(ctx);
	assert(ctx->zone);
	assert(ctx->keystore);
	assert(ctx->policy);

	normalize_generate_flags(&flags);

	dnssec_key_algorithm_t algorithm = ctx->policy->algorithm;
	unsigned size = (flags & DNSKEY_GENERATE_KSK) ? ctx->policy->ksk_size : ctx->policy->zsk_size;

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

	dnssec_key_set_flags(dnskey, dnskey_flags(flags & DNSKEY_GENERATE_SEP_ON));
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
	key->is_ksk = (flags & DNSKEY_GENERATE_KSK);
	key->is_zsk = (flags & DNSKEY_GENERATE_ZSK);
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

	if (!key_still_used_in_keystore && !key_ptr->is_pub_only) {
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
	knot_time_t timestamps[] = {
		timing->pre_active,
		timing->publish,
		timing->ready,
		timing->active,
		timing->retire_active,
		timing->retire,
		timing->post_active,
		timing->remove,
	};

	for (int i = 0; i < sizeof(timestamps) / sizeof(knot_time_t); i++) {
		knot_time_t ts = timestamps[i];
		if (knot_time_cmp(now, ts) < 0 && knot_time_cmp(ts, next) < 0) {
			next = ts;
		}
	}

	zone_key->next_event = next;

	zone_key->is_ksk = kasp_key->is_ksk;
	zone_key->is_zsk = kasp_key->is_zsk;

	zone_key->is_public = (knot_time_cmp(timing->publish, now) <= 0 &&
	                       knot_time_cmp(timing->post_active, now) > 0 &&
	                       knot_time_cmp(timing->remove, now) > 0);

	zone_key->is_ready = (zone_key->is_ksk && knot_time_cmp(timing->ready, now) <= 0 &&
	                      knot_time_cmp(timing->active, now) > 0);

	zone_key->is_active = ((knot_time_cmp(timing->ready, now) <= 0 ||
	                        knot_time_cmp(timing->active, now) <= 0) &&
	                       knot_time_cmp(timing->retire, now) > 0 &&
	                       knot_time_cmp(timing->retire_active, now) > 0 &&
	                       knot_time_cmp(timing->remove, now) > 0);

	zone_key->is_post_active = false;
	if (knot_time_cmp(timing->pre_active, now) <= 0 &&
	    knot_time_cmp(timing->ready, now) > 0 &&
	    knot_time_cmp(timing->active, now) > 0) {
		zone_key->is_post_active = (zone_key->is_zsk ||
		                            knot_time_cmp(timing->publish, now) <= 0);
	}
	if (knot_time_cmp(timing->retire_active, now) <= 0 &&
	    knot_time_cmp(timing->retire, now) > 0) {
		zone_key->is_post_active = true;
	} // not "else" !
	if (knot_time_cmp(timing->post_active, now) <= 0 &&
	    knot_time_cmp(timing->remove, now) > 0) {
		zone_key->is_post_active = zone_key->is_zsk;
	}

	return KNOT_EOK;
}

/*!
 * \brief Check if algorithm is allowed with NSEC3.
 */
static bool is_nsec3_allowed(uint8_t algorithm)
{
	switch (algorithm) {
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
		return false;
	default:
		return true;
	}
}

static int walk_algorithms(kdnssec_ctx_t *ctx, zone_keyset_t *keyset)
{
	uint8_t alg_usage[256] = { 0 };
	bool have_active_alg = false;

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		uint8_t alg = dnssec_key_get_algorithm(key->key);

		if (ctx->policy->nsec3_enabled && !is_nsec3_allowed(alg)) {
			log_zone_warning(ctx->zone->dname, "DNSSEC, key %d "
			                 "cannot be used with NSEC3",
			                 dnssec_key_get_keytag(key->key));
			key->is_public = false;
			key->is_active = false;
			key->is_ready = false;
			key->is_post_active = false;
			continue;
		}

		if (key->is_ksk && key->is_public) { alg_usage[alg] |= 1; }
		if (key->is_zsk && key->is_public) { alg_usage[alg] |= 2; }
		if (key->is_ksk && (key->is_active || key->is_post_active)) { alg_usage[alg] |= 4; }
		if (key->is_zsk && (key->is_active || key->is_post_active)) { alg_usage[alg] |= 8; }
	}

	for (size_t i = 0; i < sizeof(alg_usage); i++) {
		if (!(alg_usage[i] & 3)) {
			continue; // no public keys, ignore
		}
		switch (alg_usage[i]) {
		case 15: // all keys ready for signing
			have_active_alg = true;
			break;
		case 5:
		case 10:
			if (ctx->policy->offline_ksk) {
				have_active_alg = true;
				break;
			}
			// else FALLTHROUGH
		default:
			return KNOT_DNSSEC_EMISSINGKEYTYPE;
		}
	}

	if (!have_active_alg) {
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
		zone_key_t *key = &keyset->keys[i];
		if (!key->is_active && !key->is_post_active) {
			continue;
		}
		int r = dnssec_key_import_keystore(key->key, keystore, key->id);
		switch (r) {
		case DNSSEC_EOK:
		case DNSSEC_KEY_ALREADY_PRESENT:
			break;
		default:
			return r;
		}
	}

	return DNSSEC_EOK;
}

/*!
 * \brief Log information about zone keys.
 */
static void log_key_info(const zone_key_t *key, char *out, size_t out_len)
{
	assert(key);
	assert(out);

	uint8_t alg_code = dnssec_key_get_algorithm(key->key);
	const knot_lookup_t *alg = knot_lookup_by_id(knot_dnssec_alg_names, alg_code);

	char alg_code_str[8] = "";
	if (alg == NULL) {
		(void)snprintf(alg_code_str, sizeof(alg_code_str), "%d", alg_code);
	}

	(void)snprintf(out, out_len, "DNSSEC, key, tag %5d, algorithm %s%s%s%s%s%s",
	               dnssec_key_get_keytag(key->key),
	               (alg != NULL                ? alg->name  : alg_code_str),
	               (key->is_ksk ? (key->is_zsk ? ", CSK" : ", KSK") : ""),
	               (key->is_public             ? ", public"  : ""),
	               (key->is_ready              ? ", ready"   : ""),
	               (key->is_active             ? ", active"  : ""),
	               (key->is_post_active        ? ", active+" : ""));
}

int log_key_sort(const void *a, const void *b)
{
	const char *alg_a = strstr(a, "alg");
	const char *alg_b = strstr(b, "alg");
	assert(alg_a != NULL && alg_b != NULL);

	return strcmp(alg_a, alg_b);
}

/*!
 * \brief Load zone keys and init cryptographic context.
 */
int load_zone_keys(kdnssec_ctx_t *ctx, zone_keyset_t *keyset_ptr, bool verbose)
{
	if (!ctx || !keyset_ptr) {
		return KNOT_EINVAL;
	}

	zone_keyset_t keyset = { 0 };

	if (ctx->zone->num_keys < 1) {
		log_zone_error(ctx->zone->dname, "DNSSEC, no keys are available");
		return KNOT_DNSSEC_ENOKEY;
	}

	keyset.count = ctx->zone->num_keys;
	keyset.keys = calloc(keyset.count, sizeof(zone_key_t));
	if (!keyset.keys) {
		free_zone_keys(&keyset);
		return KNOT_ENOMEM;
	}

	char key_info[ctx->zone->num_keys][MAX_KEY_INFO];
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *kasp_key = &ctx->zone->keys[i];
		set_key(kasp_key, ctx->now, &keyset.keys[i]);
		if (verbose) {
			log_key_info(&keyset.keys[i], key_info[i], MAX_KEY_INFO);
		}
	}

	// Sort the keys by algorithm name.
	if (verbose) {
		qsort(key_info, ctx->zone->num_keys, MAX_KEY_INFO, log_key_sort);
		for (size_t i = 0; i < ctx->zone->num_keys; i++) {
			log_zone_info(ctx->zone->dname, "%s", key_info[i]);
		}
	}

	int ret = walk_algorithms(ctx, &keyset);
	if (ret != KNOT_EOK) {
		log_zone_error(ctx->zone->dname, "DNSSEC, keys validation failed (%s)",
		               knot_strerror(ret));
		free_zone_keys(&keyset);
		return ret;
	}

	ret = load_private_keys(ctx->keystore, &keyset);
	ret = knot_error_from_libdnssec(ret);
	if (ret != KNOT_EOK) {
		log_zone_error(ctx->zone->dname, "DNSSEC, failed to load private "
		               "keys (%s)", knot_strerror(ret));
		free_zone_keys(&keyset);
		return ret;
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
