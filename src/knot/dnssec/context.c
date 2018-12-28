/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <string.h>

#include "contrib/time.h"
#include "libknot/libknot.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/kasp/keystore.h"

dynarray_define(parent, knot_kasp_parent_t, DYNARRAY_VISIBILITY_PUBLIC)

static void policy_load(knot_kasp_policy_t *policy, conf_val_t *id)
{
	if (conf_str(id) == NULL) {
		policy->string = strdup("default");
	} else {
		policy->string = strdup(conf_str(id));
	}

	conf_val_t val = conf_id_get(conf(), C_POLICY, C_MANUAL, id);
	policy->manual = conf_bool(&val);

	val = conf_id_get(conf(), C_POLICY, C_SINGLE_TYPE_SIGNING, id);
	policy->singe_type_signing = conf_bool(&val);

	val = conf_id_get(conf(), C_POLICY, C_ALG, id);
	policy->algorithm = conf_opt(&val);

	val = conf_id_get(conf(), C_POLICY, C_KSK_SHARED, id);
	policy->ksk_shared = conf_bool(&val);

	val = conf_id_get(conf(), C_POLICY, C_KSK_SIZE, id);
	int64_t num = conf_int(&val);
	policy->ksk_size = (num != YP_NIL) ? num :
	                   dnssec_algorithm_key_size_default(policy->algorithm);

	val = conf_id_get(conf(), C_POLICY, C_ZSK_SIZE, id);
	num = conf_int(&val);
	policy->zsk_size = (num != YP_NIL) ? num :
	                   dnssec_algorithm_key_size_default(policy->algorithm);

	val = conf_id_get(conf(), C_POLICY, C_DNSKEY_TTL, id);
	int64_t ttl = conf_int(&val);
	policy->dnskey_ttl = (ttl != YP_NIL) ? ttl : UINT32_MAX;

	val = conf_id_get(conf(), C_POLICY, C_ZONE_MAX_TLL, id);
	ttl = conf_int(&val);
	policy->zone_maximal_ttl = (ttl != YP_NIL) ? ttl : UINT32_MAX;

	val = conf_id_get(conf(), C_POLICY, C_ZSK_LIFETIME, id);
	policy->zsk_lifetime = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_KSK_LIFETIME, id);
	policy->ksk_lifetime = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_PROPAG_DELAY, id);
	policy->propagation_delay = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_RRSIG_LIFETIME, id);
	policy->rrsig_lifetime = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_RRSIG_REFRESH, id);
	policy->rrsig_refresh_before = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_NSEC3, id);
	policy->nsec3_enabled = conf_bool(&val);

	val = conf_id_get(conf(), C_POLICY, C_NSEC3_OPT_OUT, id);
	policy->nsec3_opt_out = conf_bool(&val);

	val = conf_id_get(conf(), C_POLICY, C_NSEC3_ITER, id);
	policy->nsec3_iterations = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_NSEC3_SALT_LEN, id);
	policy->nsec3_salt_length = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_NSEC3_SALT_LIFETIME, id);
	policy->nsec3_salt_lifetime = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_CHILD_RECORDS, id);
	policy->child_records_publish = conf_opt(&val);

	conf_val_t ksk_sbm = conf_id_get(conf(), C_POLICY, C_KSK_SBM, id);
	if (ksk_sbm.code == KNOT_EOK) {
		val = conf_id_get(conf(), C_SBM, C_CHK_INTERVAL, &ksk_sbm);
		policy->ksk_sbm_check_interval = conf_int(&val);

		val = conf_id_get(conf(), C_SBM, C_TIMEOUT, &ksk_sbm);
		policy->ksk_sbm_timeout = conf_int(&val);

		val = conf_id_get(conf(), C_SBM, C_PARENT, &ksk_sbm);
		while (val.code == KNOT_EOK) {
			conf_val_t addr = conf_id_get(conf(), C_RMT, C_ADDR, &val);
			knot_kasp_parent_t p = { .addrs = conf_val_count(&addr) };
			p.addr = p.addrs ? malloc(p.addrs * sizeof(*p.addr)) : NULL;
			if (p.addr != NULL) {
				for (size_t i = 0; i < p.addrs; i++) {
					p.addr[i] = conf_remote(conf(), &val, i);
				}
				parent_dynarray_add(&policy->parents, &p);
			}
			conf_val_next(&val);
		}
	}

	val = conf_id_get(conf(), C_POLICY, C_SIGNING_THREADS, id);
	policy->signing_threads = conf_int(&val);

	val = conf_id_get(conf(), C_POLICY, C_OFFLINE_KSK, id);
	policy->offline_ksk = conf_bool(&val);
}

int kdnssec_ctx_init(conf_t *conf, kdnssec_ctx_t *ctx, const knot_dname_t *zone_name,
		     knot_lmdb_db_t *kaspdb, const conf_mod_id_t *from_module)
{
	if (ctx == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	memset(ctx, 0, sizeof(*ctx));

	ctx->zone = calloc(1, sizeof(*ctx->zone));
	if (ctx->zone == NULL) {
		ret = KNOT_ENOMEM;
		goto init_error;
	}

	ctx->kasp_db = kaspdb;
	ret = knot_lmdb_open(ctx->kasp_db);
	if (ret != KNOT_EOK) {
		goto init_error;
	}

	ret = kasp_zone_load(ctx->zone, zone_name, ctx->kasp_db);
	if (ret != KNOT_EOK) {
		goto init_error;
	}

	ctx->kasp_zone_path = conf_kaspdir(conf);
	if (ctx->kasp_zone_path == NULL) {
		ret = KNOT_ENOMEM;
		goto init_error;
	}

	ctx->policy = calloc(1, sizeof(*ctx->policy));
	if (ctx->policy == NULL) {
		ret = KNOT_ENOMEM;
		goto init_error;
	}

	conf_val_t policy_id;
	if (from_module == NULL) {
		policy_id = conf_zone_get(conf, C_DNSSEC_POLICY, zone_name);
	} else {
		policy_id = conf_mod_get(conf, C_POLICY, from_module);
	}
	conf_id_fix_default(&policy_id);
	policy_load(ctx->policy, &policy_id);

	conf_val_t keystore_id = conf_id_get(conf, C_POLICY, C_KEYSTORE, &policy_id);
	conf_id_fix_default(&keystore_id);

	conf_val_t val = conf_id_get(conf, C_KEYSTORE, C_BACKEND, &keystore_id);
	unsigned backend = conf_opt(&val);

	val = conf_id_get(conf, C_KEYSTORE, C_CONFIG, &keystore_id);
	const char *config = conf_str(&val);

	ret = keystore_load(config, backend, ctx->kasp_zone_path, &ctx->keystore);
	if (ret != KNOT_EOK) {
		goto init_error;
	}

	ctx->now = knot_time();

	return KNOT_EOK;
init_error:
	kdnssec_ctx_deinit(ctx);
	return ret;
}

int kdnssec_ctx_commit(kdnssec_ctx_t *ctx)
{
	if (ctx == NULL || ctx->kasp_zone_path == NULL) {
		return KNOT_EINVAL;
	}

	// do something with keytore? Probably not..

	return kasp_zone_save(ctx->zone, ctx->zone->dname, ctx->kasp_db);
}

void kdnssec_ctx_deinit(kdnssec_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->policy != NULL) {
		free(ctx->policy->string);
		dynarray_foreach(parent, knot_kasp_parent_t, i, ctx->policy->parents) {
			free(i->addr);
		}
		free(ctx->policy);
	}
	knot_rrset_free(ctx->offline_rrsig, NULL);
	dnssec_keystore_deinit(ctx->keystore);
	kasp_zone_free(&ctx->zone);
	free(ctx->kasp_zone_path);

	memset(ctx, 0, sizeof(*ctx));
}
