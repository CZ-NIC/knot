/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <dnssec/error.h>
#include <dnssec/kasp.h>
#include <dnssec/keystore.h>

#include "libknot/libknot.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/context.h"
#include "contrib/files.h"

static int zone_save(void *ctx, const dnssec_kasp_zone_t *zone)
{
	return dnssec_kasp_dir_api()->zone_save(ctx, zone);
}

static int zone_load(void *ctx, dnssec_kasp_zone_t *zone)
{
	int r = dnssec_kasp_dir_api()->zone_load(ctx, zone);
	if (r != DNSSEC_EOK && r != DNSSEC_NOT_FOUND) {
		return r;
	}

	free(zone->policy);
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_POLICY, zone->dname);
	zone->policy = strdup(conf_str(&val));

	return DNSSEC_EOK;
}

static int policy_load(void *ctx, dnssec_kasp_policy_t *policy)
{
	const uint8_t *id = (const uint8_t *)policy->name;
	const size_t id_len = strlen(policy->name) + 1;

	conf_val_t val = conf_rawid_get(conf(), C_POLICY, C_KEYSTORE, id, id_len);
	policy->keystore = strdup(conf_str(&val));

	val = conf_rawid_get(conf(), C_POLICY, C_MANUAL, id, id_len);
	policy->manual = conf_bool(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_ALG, id, id_len);
	policy->algorithm = conf_opt(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_KSK_SIZE, id, id_len);
	int64_t num = conf_int(&val);
	policy->ksk_size = (num != YP_NIL) ? num :
	                   dnssec_algorithm_key_size_default(policy->algorithm);

	val = conf_rawid_get(conf(), C_POLICY, C_ZSK_SIZE, id, id_len);
	num = conf_int(&val);
	policy->zsk_size = (num != YP_NIL) ? num :
	                   dnssec_algorithm_key_size_default(policy->algorithm);

	val = conf_rawid_get(conf(), C_POLICY, C_DNSKEY_TTL, id, id_len);
	num = conf_int(&val);
	policy->dnskey_ttl = (num != YP_NIL) ? num : 0;

	val = conf_rawid_get(conf(), C_POLICY, C_ZSK_LIFETIME, id, id_len);
	policy->zsk_lifetime = conf_int(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_RRSIG_LIFETIME, id, id_len);
	policy->rrsig_lifetime = conf_int(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_RRSIG_REFRESH, id, id_len);
	policy->rrsig_refresh_before = conf_int(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_NSEC3, id, id_len);
	policy->nsec3_enabled = conf_bool(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_NSEC3_ITER, id, id_len);
	policy->nsec3_iterations = conf_int(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_NSEC3_SALT_LEN, id, id_len);
	policy->nsec3_salt_length = conf_int(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_NSEC3_SALT_LIFETIME, id, id_len);
	policy->nsec3_salt_lifetime = conf_int(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_PROPAG_DELAY, id, id_len);
	policy->propagation_delay = conf_int(&val);

	return DNSSEC_EOK;
}

static int keystore_load(void *ctx, dnssec_kasp_keystore_t *keystore)
{
	const uint8_t *id = (const uint8_t *)keystore->name;
	const size_t id_len = strlen(keystore->name) + 1;

	conf_val_t val = conf_rawid_get(conf(), C_KEYSTORE, C_BACKEND, id, id_len);
	switch (conf_opt(&val)) {
	case KEYSTORE_BACKEND_PEM:
		keystore->backend = strdup(DNSSEC_KASP_KEYSTORE_PKCS8);
		break;
	case KEYSTORE_BACKEND_PKCS11:
		keystore->backend = strdup(DNSSEC_KASP_KEYSTORE_PKCS11);
		break;
	default:
		return DNSSEC_EINVAL;
	}

	val = conf_rawid_get(conf(), C_KEYSTORE, C_CONFIG, id, id_len);
	keystore->config = strdup(conf_str(&val));

	return DNSSEC_EOK;
}

int kdnssec_kasp(dnssec_kasp_t **kasp, bool legacy)
{
	if (legacy) {
		return dnssec_kasp_init_dir(kasp);
	} else {
		static dnssec_kasp_store_functions_t conf_api = {
			.zone_load       = zone_load,
			.zone_save       = zone_save,
			.policy_load     = policy_load,
			.keystore_load   = keystore_load
		};

		conf_api.init      = dnssec_kasp_dir_api()->init;
		conf_api.open      = dnssec_kasp_dir_api()->open;
		conf_api.close     = dnssec_kasp_dir_api()->close;
		conf_api.base_path = dnssec_kasp_dir_api()->base_path;

		return dnssec_kasp_init_custom(kasp, &conf_api);
	}
}

static int get_keystore(dnssec_kasp_t *kasp, const char *name,
                        dnssec_keystore_t **keystore, bool legacy)
{
	dnssec_kasp_keystore_t *info = NULL;
	int r = dnssec_kasp_keystore_load(kasp, name, &info);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// Initialize keystore directory.
	if (!legacy) {
		// TODO: A keystore should be initialized during the zone setup/load.
		r = dnssec_kasp_keystore_init(kasp, info->backend, info->config,
		                              keystore);
		if (r != DNSSEC_EOK) {
			dnssec_kasp_keystore_free(info);
			return r;
		}
		dnssec_keystore_deinit(*keystore);
	}

	r = dnssec_kasp_keystore_open(kasp, info->backend, info->config, keystore);

	dnssec_kasp_keystore_free(info);

	return r;
}

int kdnssec_kasp_init(kdnssec_ctx_t *ctx, const char *kasp_path, const char *zone_name)
{
	if (ctx == NULL || kasp_path == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}

	int r = kdnssec_kasp(&ctx->kasp, ctx->legacy);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = make_dir(kasp_path, S_IRWXU | S_IRGRP | S_IXGRP, true);
	if (r != KNOT_EOK) {
		return r;
	}

	r = dnssec_kasp_open(ctx->kasp, kasp_path);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_kasp_zone_load(ctx->kasp, zone_name, &ctx->zone);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_kasp_policy_load(ctx->kasp, ctx->zone->policy, &ctx->policy);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return get_keystore(ctx->kasp, ctx->policy->keystore, &ctx->keystore,
	                    ctx->legacy);
}

void kdnssec_ctx_deinit(kdnssec_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	dnssec_keystore_deinit(ctx->keystore);
	dnssec_kasp_policy_free(ctx->policy);
	dnssec_kasp_zone_free(ctx->zone);
	dnssec_kasp_deinit(ctx->kasp);

	memset(ctx, 0, sizeof(*ctx));
}

int kdnssec_ctx_init(kdnssec_ctx_t *ctx, const knot_dname_t *zone_name)
{
	if (ctx == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}

	// Check for legacy configuration.
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_POLICY, zone_name);
	bool legacy = val.code != KNOT_EOK;

	kdnssec_ctx_t new_ctx = {
		.legacy = legacy
	};

	char zone_str[KNOT_DNAME_TXT_MAXLEN + 1];
	if (knot_dname_to_str(zone_str, zone_name, sizeof(zone_str)) == NULL) {
		return KNOT_ENOMEM;
	}

	val = conf_zone_get(conf(), C_STORAGE, zone_name);
	char *storage = conf_abs_path(&val, NULL);
	val = conf_zone_get(conf(), C_KASP_DB, zone_name);
	char *kasp_path = conf_abs_path(&val, storage);
	free(storage);

	int r = kdnssec_kasp_init(&new_ctx, kasp_path, zone_str);
	free(kasp_path);
	if (r != KNOT_EOK) {
		kdnssec_ctx_deinit(&new_ctx);
		return r;
	}

	new_ctx.now = time(NULL);

	*ctx = new_ctx;
	return KNOT_EOK;
}
