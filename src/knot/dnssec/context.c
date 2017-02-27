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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <dnssec/error.h>
#include <dnssec/keystore.h>

#include "libknot/libknot.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/kasp/keystore.h"
#include "contrib/files.h"

static int policy_load(knot_kasp_policy_t *policy)
{
	const uint8_t *id = (const uint8_t *)policy->name;
	const size_t id_len = strlen(policy->name) + 1;

	conf_val_t val = conf_rawid_get(conf(), C_POLICY, C_KEYSTORE, id, id_len);
	policy->keystore = strdup(conf_str(&val));

	val = conf_rawid_get(conf(), C_POLICY, C_MANUAL, id, id_len);
	policy->manual = conf_bool(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_SINGLE_TYPE_SIGNING, id, id_len);
	policy->singe_type_signing = conf_bool(&val);

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
	policy->dnskey_ttl = conf_int(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_ZSK_LIFETIME, id, id_len);
	policy->zsk_lifetime = conf_int(&val);

	val = conf_rawid_get(conf(), C_POLICY, C_PROPAG_DELAY, id, id_len);
	policy->propagation_delay = conf_int(&val);

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

	return KNOT_EOK;
}

int kdnssec_kasp_init(kdnssec_ctx_t *ctx, const char *kasp_path, size_t kasp_mapsize,
		      const knot_dname_t *zone_name, const char *policy_name)
{
	if (ctx == NULL || kasp_path == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}

	ctx->zone = calloc(1, sizeof(*ctx->zone));
	if (ctx->zone == NULL) {
		return KNOT_ENOMEM;
	}
	ctx->kasp_db = kaspdb();

	int r = kasp_db_open(*ctx->kasp_db);
	if (r != KNOT_EOK) {
		return r;
	}

	r = kasp_zone_load(ctx->zone, zone_name, *ctx->kasp_db);
	if (r != KNOT_EOK) {
		return r;
	}

	ctx->kasp_zone_path = strdup(kasp_path);

	ctx->policy = knot_kasp_policy_new(policy_name);
	if (ctx->policy == NULL) {
		return KNOT_ENOMEM;
	}

	r = policy_load(ctx->policy);
	if (r != KNOT_EOK) {
		return r;
	}

	const uint8_t *id = (const uint8_t *)policy_name;
	const size_t id_len = strlen(policy_name) + 1;
	conf_val_t val = conf_rawid_get(conf(), C_KEYSTORE, C_BACKEND, id, id_len);
	int backend = conf_opt(&val);
	val = conf_rawid_get(conf(), C_KEYSTORE, C_CONFIG, id, id_len);

	r = keystore_load(conf_str(&val), backend, kasp_path, &ctx->keystore);
	if (r != KNOT_EOK) {
		return r;
	}

	return KNOT_EOK;
}

int kdnssec_ctx_commit(kdnssec_ctx_t *ctx)
{
	if (ctx == NULL || ctx->kasp_zone_path == NULL) {
		return KNOT_EINVAL;
	}

	// do something with keytore? Probably not..

	return kasp_zone_save(ctx->zone, ctx->zone->dname, *ctx->kasp_db);
}

void kdnssec_ctx_deinit(kdnssec_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	dnssec_keystore_deinit(ctx->keystore);
	knot_kasp_policy_free(ctx->policy);
	kasp_zone_free(&ctx->zone);
	free(ctx->kasp_zone_path);

	memset(ctx, 0, sizeof(*ctx));
}

int kdnssec_ctx_init(kdnssec_ctx_t *ctx, const knot_dname_t *zone_name,
                     conf_val_t *policy)
{
	if (ctx == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}

	kdnssec_ctx_t new_ctx = { 0 };

	char *kasp_dir = conf_kaspdir(conf());
	conf_val_t kasp_db_mapsize = conf_default_get(conf(), C_KASP_DB_MAPSIZE);

	int r = kdnssec_kasp_init(&new_ctx, kasp_dir, conf_int(&kasp_db_mapsize), zone_name, conf_str(policy));
	free(kasp_dir);
	if (r != KNOT_EOK) {
		kdnssec_ctx_deinit(&new_ctx);
		return r;
	}

	new_ctx.now = time(NULL);

	*ctx = new_ctx;
	return KNOT_EOK;
}
