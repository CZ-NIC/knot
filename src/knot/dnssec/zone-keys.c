/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

typedef struct {
	char msg[MAX_KEY_INFO];
	knot_time_t key_time;
} key_info_t;

knot_dynarray_define(keyptr, zone_key_t *, DYNARRAY_VISIBILITY_NORMAL)

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

static int generate_dnssec_key(dnssec_keystore_t *keystore,
                               const knot_dname_t *zone_name,
                               dnssec_key_algorithm_t alg,
                               unsigned size,
                               kdnssec_generate_flags_t flags,
                               char **id,
                               dnssec_key_t **key)
{
	*key = NULL;
	*id = NULL;

	int ret = dnssec_keystore_generate(keystore, alg, size, id);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = dnssec_key_new(key);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	ret = dnssec_key_set_dname(*key, zone_name);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	dnssec_key_set_flags(*key, dnskey_flags(flags & DNSKEY_GENERATE_SEP_ON));
	dnssec_key_set_algorithm(*key, alg);

	ret = dnssec_keystore_get_private(keystore, *id, *key);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	return KNOT_EOK;

fail:
	dnssec_key_free(*key);
	*key = NULL;
	free(*id);
	*id = NULL;
	return ret;
}

static bool keytag_in_use(kdnssec_ctx_t *ctx, uint16_t keytag)
{
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		uint16_t used = dnssec_key_get_keytag(ctx->zone->keys[i].key);
		if (used == keytag) {
			return true;
		}
	}
	return false;
}

#define GENERATE_KEYTAG_ATTEMPTS (20)

static int generate_keytag_unconflict(kdnssec_ctx_t *ctx,
                                      kdnssec_generate_flags_t flags,
                                      char **id,
                                      dnssec_key_t **key)
{
	unsigned size = (flags & DNSKEY_GENERATE_KSK) ? ctx->policy->ksk_size :
	                                                ctx->policy->zsk_size;

	for (size_t i = 0; i < GENERATE_KEYTAG_ATTEMPTS; i++) {
		dnssec_key_free(*key);
		free(*id);

		int ret = generate_dnssec_key(ctx->keystore, ctx->zone->dname,
		                              ctx->policy->algorithm, size, flags,
		                              id, key);
		if (ret != KNOT_EOK) {
			return ret;
		}
		if (!keytag_in_use(ctx, dnssec_key_get_keytag(*key))) {
			return KNOT_EOK;
		}
	}

	log_zone_notice(ctx->zone->dname, "generated key with conflicting keytag %hu",
	                dnssec_key_get_keytag(*key));
	return KNOT_EOK;
}

int kdnssec_generate_key(kdnssec_ctx_t *ctx, kdnssec_generate_flags_t flags,
			 knot_kasp_key_t **key_ptr)
{
	assert(ctx);
	assert(ctx->zone);
	assert(ctx->keystore);
	assert(ctx->policy);

	normalize_generate_flags(&flags);

	// generate key in the keystore

	char *id = NULL;
	dnssec_key_t *dnskey = NULL;

	int r = generate_keytag_unconflict(ctx, flags, &id, &dnskey);
	if (r != KNOT_EOK) {
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

	ret = kasp_db_share_key(ctx->kasp_db, from_zone, ctx->zone->dname, key_id);
	if (ret != KNOT_EOK) {
		free(to_zone);
		return ret;
	}

	kasp_zone_clear(ctx->zone);
	ret = kasp_zone_load(ctx->zone, to_zone, ctx->kasp_db,
	                     &ctx->keytag_conflict);
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
	int ret = kasp_db_delete_key(ctx->kasp_db, ctx->zone->dname, key_ptr->id, &key_still_used_in_keystore);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!key_still_used_in_keystore && !key_ptr->is_pub_only) {
		ret = dnssec_keystore_remove(ctx->keystore, key_ptr->id);
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

static bool is_published(knot_kasp_key_timing_t *timing, knot_time_t now)
{
	return (knot_time_cmp(timing->publish, now) <= 0 &&
	        knot_time_cmp(timing->post_active, now) > 0 &&
	        knot_time_cmp(timing->remove, now) > 0);
}

static bool is_ready(knot_kasp_key_timing_t *timing, knot_time_t now)
{
	return (knot_time_cmp(timing->ready, now) <= 0 &&
	        knot_time_cmp(timing->active, now) > 0);
}

static bool is_active(knot_kasp_key_timing_t *timing, knot_time_t now)
{
	return (knot_time_cmp(timing->active, now) <= 0 &&
	        knot_time_cmp(timing->retire, now) > 0 &&
	        knot_time_cmp(timing->retire_active, now) > 0 &&
	        knot_time_cmp(timing->remove, now) > 0);
}

static bool alg_has_active_zsk(kdnssec_ctx_t *ctx, uint8_t alg)
{
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *k = &ctx->zone->keys[i];
		if (dnssec_key_get_algorithm(k->key) == alg &&
		    k->is_zsk && is_active(&k->timing, ctx->now)) {
			return true;
		}
	}
	return false;
}

static void fix_revoked_flag(knot_kasp_key_t *key)
{
	uint16_t flags = dnssec_key_get_flags(key->key);
	if ((flags & DNSKEY_FLAGS_REVOKED) != DNSKEY_FLAGS_REVOKED) {
		dnssec_key_set_flags(key->key, flags | DNSKEY_FLAGS_REVOKED); // FYI leading to change of keytag
	}
}

/*!
 * \brief Get key feature flags from key parameters.
 */
static void set_key(knot_kasp_key_t *kasp_key, knot_time_t now,
                    zone_key_t *zone_key, bool same_alg_act_zsk)
{
	assert(kasp_key);
	assert(zone_key);

	knot_kasp_key_timing_t *timing = &kasp_key->timing;

	zone_key->id = kasp_key->id;
	zone_key->key = kasp_key->key;

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
		timing->revoke,
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

	zone_key->is_public = is_published(timing, now);
	zone_key->is_ready = (zone_key->is_ksk && is_ready(timing, now));
	zone_key->is_active = is_active(timing, now);

	zone_key->is_ksk_active_plus = zone_key->is_public && zone_key->is_ksk && !zone_key->is_active; // KSK is active+ whenever published
	zone_key->is_zsk_active_plus = zone_key->is_ready && !same_alg_act_zsk;
	if (knot_time_cmp(timing->pre_active, now) <= 0 &&
	    knot_time_cmp(timing->ready, now) > 0 &&
	    knot_time_cmp(timing->active, now) > 0 &&
	    knot_time_cmp(timing->remove, now) > 0) {
		zone_key->is_zsk_active_plus = zone_key->is_zsk;
		// zone_key->is_ksk_active_plus = (knot_time_cmp(timing->publish, now) <= 0 && zone_key->is_ksk); // redundant, but helps understand
	}
	if (knot_time_cmp(timing->retire, now) <= 0 &&
	    knot_time_cmp(timing->remove, now) > 0) {
		zone_key->is_ksk_active_plus = false;
		zone_key->is_public = zone_key->is_zsk;
	}
	if (knot_time_cmp(timing->retire_active, now) <= 0 &&
	    knot_time_cmp(timing->retire, now) > 0 &&
	    knot_time_cmp(timing->remove, now) > 0) {
		zone_key->is_ksk_active_plus = zone_key->is_ksk;
		zone_key->is_zsk_active_plus = !same_alg_act_zsk;
	} // not "else" !
	if (knot_time_cmp(timing->post_active, now) <= 0 &&
	    knot_time_cmp(timing->remove, now) > 0) {
		zone_key->is_ksk_active_plus = false;
		zone_key->is_zsk_active_plus = zone_key->is_zsk;
	}
	if (zone_key->is_ksk &&
	    knot_time_cmp(timing->revoke, now) <= 0 &&
	    knot_time_cmp(timing->remove, now) > 0) {
		zone_key->is_ready = false;
		zone_key->is_active = false;
		zone_key->is_ksk_active_plus = true;
		zone_key->is_public = true;
		zone_key->is_revoked = true;
		fix_revoked_flag(kasp_key);
	}
	if (kasp_key->is_pub_only) {
		zone_key->is_active = false;
		zone_key->is_ksk_active_plus = false;
		zone_key->is_zsk_active_plus = false;
		zone_key->is_pub_only = true;
	}
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
	if (ctx->policy->unsafe & UNSAFE_KEYSET) {
		return KNOT_EOK;
	}

	uint8_t alg_usage[256] = { 0 };
	bool have_active_alg = false;

	for (size_t i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		if (key->is_pub_only) {
			continue;
		}
		uint8_t alg = dnssec_key_get_algorithm(key->key);

		if (ctx->policy->nsec3_enabled && !is_nsec3_allowed(alg)) {
			log_zone_warning(ctx->zone->dname, "DNSSEC, key %d "
			                 "cannot be used with NSEC3",
			                 dnssec_key_get_keytag(key->key));
			key->is_public = false;
			key->is_active = false;
			key->is_ready = false;
			key->is_ksk_active_plus = false;
			key->is_zsk_active_plus = false;
			continue;
		}

		if (key->is_ksk && key->is_public) { alg_usage[alg] |= 1; }
		if (key->is_zsk && key->is_public) { alg_usage[alg] |= 2; }
		if (key->is_ksk && (key->is_active || key->is_ksk_active_plus)) { alg_usage[alg] |= 4; }
		if (key->is_zsk && (key->is_active || key->is_zsk_active_plus)) { alg_usage[alg] |= 8; }
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
		if (!key->is_active && !key->is_ksk_active_plus && !key->is_zsk_active_plus) {
			continue;
		}
		int r = dnssec_keystore_get_private(keystore, key->id, key->key);
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
	               (key->is_ksk_active_plus || key->is_zsk_active_plus ? ", active+" : ""));
}

static int log_key_sort(const void *a, const void *b)
{
	const key_info_t *x = a, *y = b;
	return knot_time_cmp(x->key_time, y->key_time);
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

	key_info_t key_info[ctx->zone->num_keys];
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *kasp_key = &ctx->zone->keys[i];
		uint8_t kk_alg = dnssec_key_get_algorithm(kasp_key->key);
		bool same_alg_zsk = alg_has_active_zsk(ctx, kk_alg);
		set_key(kasp_key, ctx->now, &keyset.keys[i], same_alg_zsk);
		if (verbose) {
			log_key_info(&keyset.keys[i], key_info[i].msg, MAX_KEY_INFO);
			if (knot_time_cmp(kasp_key->timing.pre_active, kasp_key->timing.publish) < 0) {
				key_info[i].key_time = kasp_key->timing.pre_active;
			} else {
				key_info[i].key_time = kasp_key->timing.publish;
			}
		}
	}

	// Sort the keys by publish/pre_active timestamps.
	if (verbose) {
		qsort(key_info, ctx->zone->num_keys, sizeof(key_info[0]), log_key_sort);
		for (size_t i = 0; i < ctx->zone->num_keys; i++) {
			log_zone_info(ctx->zone->dname, "%s", key_info[i].msg);
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
		dnssec_binary_free(&keyset->keys[i].precomputed_ds);
	}

	free(keyset->keys);

	memset(keyset, '\0', sizeof(*keyset));
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
int zone_key_calculate_ds(zone_key_t *for_key, dnssec_key_digest_t digesttype,
                          dnssec_binary_t *out_donotfree)
{
	assert(for_key);
	assert(out_donotfree);

	int ret = KNOT_EOK;

	if (for_key->precomputed_ds.data == NULL || for_key->precomputed_digesttype != digesttype) {
		dnssec_binary_free(&for_key->precomputed_ds);
		ret = dnssec_key_create_ds(for_key->key, digesttype, &for_key->precomputed_ds);
		ret = knot_error_from_libdnssec(ret);
		for_key->precomputed_digesttype = digesttype;
	}

	*out_donotfree = for_key->precomputed_ds;
	return ret;
}

zone_sign_ctx_t *zone_sign_ctx(const zone_keyset_t *keyset, const kdnssec_ctx_t *dnssec_ctx)
{
	zone_sign_ctx_t *ctx = calloc(1, sizeof(*ctx) + keyset->count * sizeof(*ctx->sign_ctxs));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->sign_ctxs = (dnssec_sign_ctx_t **)(ctx + 1);
	ctx->count = keyset->count;
	ctx->keys = keyset->keys;
	ctx->dnssec_ctx = dnssec_ctx;
	for (size_t i = 0; i < ctx->count; i++) {
		int ret = dnssec_sign_new(&ctx->sign_ctxs[i], ctx->keys[i].key);
		if (ret != DNSSEC_EOK) {
			zone_sign_ctx_free(ctx);
			return NULL;
		}
	}

	return ctx;
}

zone_sign_ctx_t *zone_validation_ctx(const kdnssec_ctx_t *dnssec_ctx)
{
	size_t count = dnssec_ctx->zone->num_keys;
	zone_sign_ctx_t *ctx = calloc(1, sizeof(*ctx) + count * sizeof(*ctx->sign_ctxs));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->sign_ctxs = (dnssec_sign_ctx_t **)(ctx + 1);
	ctx->count = count;
	ctx->keys = NULL;
	ctx->dnssec_ctx = dnssec_ctx;
	for (size_t i = 0; i < ctx->count; i++) {
		int ret = dnssec_sign_new(&ctx->sign_ctxs[i], dnssec_ctx->zone->keys[i].key);
		if (ret != DNSSEC_EOK) {
			zone_sign_ctx_free(ctx);
			return NULL;
		}
	}

	return ctx;
}

void zone_sign_ctx_free(zone_sign_ctx_t *ctx)
{
	if (ctx != NULL) {
		for (size_t i = 0; i < ctx->count; i++) {
			dnssec_sign_free(ctx->sign_ctxs[i]);
		}
		free(ctx);
	}
}

int dnssec_key_from_rdata(dnssec_key_t **key, const knot_dname_t *owner,
                          const uint8_t *rdata, size_t rdlen)
{
	if (key == NULL || rdata == NULL || rdlen == 0) {
		return KNOT_EINVAL;
	}

	const dnssec_binary_t binary_key = {
		.size = rdlen,
		.data = (uint8_t *)rdata
	};

	dnssec_key_t *new_key = NULL;
	int ret = dnssec_key_new(&new_key);
	if (ret != DNSSEC_EOK) {
		return knot_error_from_libdnssec(ret);
	}
	ret = dnssec_key_set_rdata(new_key, &binary_key);
	if (ret != DNSSEC_EOK) {
		dnssec_key_free(new_key);
		return knot_error_from_libdnssec(ret);
	}
	if (owner != NULL) {
		ret = dnssec_key_set_dname(new_key, owner);
		if (ret != DNSSEC_EOK) {
			dnssec_key_free(new_key);
			return knot_error_from_libdnssec(ret);
		}
	}

	*key = new_key;
	return KNOT_EOK;
}

static bool soa_signed_by_key(const zone_key_t *key, const knot_rdataset_t *apex_rrsig)
{
	assert(key != NULL);
	if (apex_rrsig == NULL) {
		return false;
	}
	uint16_t keytag = dnssec_key_get_keytag(key->key);

	knot_rdata_t *rr = apex_rrsig->rdata;
	for (int i = 0; i < apex_rrsig->count; i++) {
		if (knot_rrsig_type_covered(rr) == KNOT_RRTYPE_SOA &&
		    knot_rrsig_key_tag(rr) == keytag) {
			return true;
		}
		rr = knot_rdataset_next(rr);
	}

	return false;
}

int is_soa_signed_by_all_zsks(const zone_keyset_t *keyset,
                              const knot_rdataset_t *apex_rrsig)
{
	if (keyset == NULL || keyset->count == 0) {
		return false;
	}

	for (size_t i = 0; i < keyset->count; i++) {
		const zone_key_t *key = &keyset->keys[i];
		if (key->is_zsk && key->is_active &&
		    !soa_signed_by_key(key, apex_rrsig)) {
			return false;
		}
	}

	return true;
}
