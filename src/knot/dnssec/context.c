/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/macros.h"
#include "contrib/time.h"
#include "libknot/libknot.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/kasp/keystore.h"
#include "knot/dnssec/key_records.h"
#include "knot/server/dthreads.h"

knot_dynarray_define(parent, knot_kasp_parent_t, DYNARRAY_VISIBILITY_NORMAL)

static void policy_load(knot_kasp_policy_t *policy, conf_t *conf, conf_val_t *id)
{
	if (conf_str(id) == NULL) {
		policy->string = strdup("default");
	} else {
		policy->string = strdup(conf_str(id));
	}

	conf_val_t val = conf_id_get(conf, C_POLICY, C_MANUAL, id);
	policy->manual = conf_bool(&val);

	val = conf_id_get(conf, C_POLICY, C_SINGLE_TYPE_SIGNING, id);
	policy->single_type_signing = conf_bool(&val);
	policy->sts_default = (val.code != KNOT_EOK);

	val = conf_id_get(conf, C_POLICY, C_ALG, id);
	policy->algorithm = conf_opt(&val);

	val = conf_id_get(conf, C_POLICY, C_KSK_SHARED, id);
	policy->ksk_shared = conf_bool(&val);

	val = conf_id_get(conf, C_POLICY, C_KSK_SIZE, id);
	int64_t num = conf_int(&val);
	policy->ksk_size = (num != YP_NIL) ? num :
	                   dnssec_algorithm_key_size_default(policy->algorithm);

	val = conf_id_get(conf, C_POLICY, C_ZSK_SIZE, id);
	num = conf_int(&val);
	policy->zsk_size = (num != YP_NIL) ? num :
	                   dnssec_algorithm_key_size_default(policy->algorithm);

	val = conf_id_get(conf, C_POLICY, C_DNSKEY_TTL, id);
	int64_t ttl = conf_int(&val);
	policy->dnskey_ttl = (ttl != YP_NIL) ? ttl : UINT32_MAX;

	val = conf_id_get(conf, C_POLICY, C_ZONE_MAX_TTL, id);
	ttl = conf_int(&val);
	policy->zone_maximal_ttl = (ttl != YP_NIL) ? ttl : UINT32_MAX;

	val = conf_id_get(conf, C_POLICY, C_ZSK_LIFETIME, id);
	policy->zsk_lifetime = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_KSK_LIFETIME, id);
	policy->ksk_lifetime = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_DELETE_DELAY, id);
	policy->delete_delay = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_PROPAG_DELAY, id);
	policy->propagation_delay = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_RRSIG_LIFETIME, id);
	policy->rrsig_lifetime = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_RRSIG_REFRESH, id);
	num = conf_int(&val);
	policy->rrsig_refresh_before = (num != YP_NIL) ? num : UINT32_MAX;
	if (policy->rrsig_refresh_before == UINT32_MAX && policy->zone_maximal_ttl != UINT32_MAX) {
		policy->rrsig_refresh_before = policy->propagation_delay + policy->zone_maximal_ttl;
	}

	val = conf_id_get(conf, C_POLICY, C_RRSIG_PREREFRESH, id);
	policy->rrsig_prerefresh = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_REPRO_SIGNING, id);
	policy->reproducible_sign = conf_bool(&val);

	val = conf_id_get(conf, C_POLICY, C_NSEC3, id);
	policy->nsec3_enabled = conf_bool(&val);

	val = conf_id_get(conf, C_POLICY, C_NSEC3_OPT_OUT, id);
	policy->nsec3_opt_out = conf_bool(&val);

	val = conf_id_get(conf, C_POLICY, C_NSEC3_ITER, id);
	policy->nsec3_iterations = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_NSEC3_SALT_LEN, id);
	policy->nsec3_salt_length = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_NSEC3_SALT_LIFETIME, id);
	policy->nsec3_salt_lifetime = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_CDS_CDNSKEY, id);
	policy->cds_cdnskey_publish = conf_opt(&val);

	val = conf_id_get(conf, C_POLICY, C_CDS_DIGESTTYPE, id);
	policy->cds_dt = conf_opt(&val);

	val = conf_id_get(conf, C_POLICY, C_DNSKEY_MGMT, id);
	policy->incremental = (conf_opt(&val) == DNSKEY_MGMT_INCREMENTAL);

	conf_val_t ksk_sbm = conf_id_get(conf, C_POLICY, C_KSK_SBM, id);
	if (ksk_sbm.code == KNOT_EOK) {
		val = conf_id_get(conf, C_SBM, C_CHK_INTERVAL, &ksk_sbm);
		policy->ksk_sbm_check_interval = conf_int(&val);

		val = conf_id_get(conf, C_SBM, C_TIMEOUT, &ksk_sbm);
		policy->ksk_sbm_timeout = conf_int(&val);

		val = conf_id_get(conf, C_SBM, C_PARENT, &ksk_sbm);
		conf_mix_iter_t iter;
		conf_mix_iter_init(conf, &val, &iter);
		while (iter.id->code == KNOT_EOK) {
			conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, iter.id);
			knot_kasp_parent_t p = { .addrs = conf_val_count(&addr) };
			p.addr = p.addrs ? malloc(p.addrs * sizeof(*p.addr)) : NULL;
			if (p.addr != NULL) {
				for (size_t i = 0; i < p.addrs; i++) {
					p.addr[i] = conf_remote(conf, iter.id, i);
				}
				parent_dynarray_add(&policy->parents, &p);
			}
			conf_mix_iter_next(&iter);
		}

		val = conf_id_get(conf, C_SBM, C_PARENT_DELAY, &ksk_sbm);
		policy->ksk_sbm_delay = conf_int(&val);
	}

	val = conf_id_get(conf, C_POLICY, C_SIGNING_THREADS, id);
	policy->signing_threads = conf_int(&val);

	val = conf_id_get(conf, C_POLICY, C_DS_PUSH, id);
	policy->ds_push = conf_val_count(&val) > 0;

	val = conf_id_get(conf, C_POLICY, C_OFFLINE_KSK, id);
	policy->offline_ksk = conf_bool(&val);

	policy->unsafe = 0;
	val = conf_id_get(conf, C_POLICY, C_UNSAFE_OPERATION, id);
	while (val.code == KNOT_EOK) {
		policy->unsafe |= conf_opt(&val);
		conf_val_next(&val);
	}
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

	ret = kasp_zone_load(ctx->zone, zone_name, ctx->kasp_db,
	                     &ctx->keytag_conflict);
	if (ret != KNOT_EOK) {
		goto init_error;
	}

	ctx->kasp_zone_path = conf_db(conf, C_KASP_DB);
	if (ctx->kasp_zone_path == NULL) {
		ret = KNOT_ENOMEM;
		goto init_error;
	}

	ctx->policy = calloc(1, sizeof(*ctx->policy));
	if (ctx->policy == NULL) {
		ret = KNOT_ENOMEM;
		goto init_error;
	}

	ret = kasp_db_get_saved_ttls(ctx->kasp_db, zone_name,
	                             &ctx->policy->saved_max_ttl,
	                             &ctx->policy->saved_key_ttl);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		return ret;
	}

	conf_val_t policy_id;
	if (from_module == NULL) {
		policy_id = conf_zone_get(conf, C_DNSSEC_POLICY, zone_name);
	} else {
		policy_id = conf_mod_get(conf, C_POLICY, from_module);
	}
	conf_id_fix_default(&policy_id);
	policy_load(ctx->policy, conf, &policy_id);

	ret = zone_init_keystore(conf, &policy_id, &ctx->keystore, NULL,
	                         &ctx->policy->key_label);
	if (ret != KNOT_EOK) {
		goto init_error;
	}

	ctx->dbus_event = conf->cache.srv_dbus_event;

	ctx->now = knot_time();

	key_records_init(ctx, &ctx->offline_records);
	if (ctx->policy->offline_ksk) {
		ret = kasp_db_load_offline_records(ctx->kasp_db, ctx->zone->dname,
		                                   &ctx->now, &ctx->offline_next_time,
		                                   &ctx->offline_records);
		if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
			goto init_error;
		}
	}

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

	if (ctx->policy->dnskey_ttl != UINT32_MAX &&
	    ctx->policy->zone_maximal_ttl != UINT32_MAX) {
		int ret = kasp_db_set_saved_ttls(ctx->kasp_db, ctx->zone->dname,
		                                 ctx->policy->zone_maximal_ttl,
		                                 ctx->policy->dnskey_ttl);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return kasp_zone_save(ctx->zone, ctx->zone->dname, ctx->kasp_db);
}

void kdnssec_ctx_deinit(kdnssec_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->policy != NULL) {
		free(ctx->policy->string);
		knot_dynarray_foreach(parent, knot_kasp_parent_t, i, ctx->policy->parents) {
			free(i->addr);
		}
		free(ctx->policy);
	}
	key_records_clear(&ctx->offline_records);
	dnssec_keystore_deinit(ctx->keystore);
	kasp_zone_free(&ctx->zone);
	free(ctx->kasp_zone_path);

	memset(ctx, 0, sizeof(*ctx));
}

// expects policy struct to be zeroed
static void policy_from_zone(knot_kasp_policy_t *policy, const zone_contents_t *zone)
{
	knot_rdataset_t *dnskey = node_rdataset(zone->apex, KNOT_RRTYPE_DNSKEY);
	knot_rdataset_t *n3p = node_rdataset(zone->apex, KNOT_RRTYPE_NSEC3PARAM);

	policy->manual = true;
	policy->single_type_signing = (dnskey != NULL && dnskey->count == 1);

	if (n3p != NULL) {
		policy->nsec3_enabled = true;
		policy->nsec3_iterations = knot_nsec3param_iters(n3p->rdata);
		policy->nsec3_salt_length = knot_nsec3param_salt_len(n3p->rdata);
	}
	policy->signing_threads = 1;
}

int kdnssec_validation_ctx(conf_t *conf, kdnssec_ctx_t *ctx, const zone_contents_t *zone)
{
	if (ctx == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));

	ctx->zone = calloc(1, sizeof(*ctx->zone));
	if (ctx->zone == NULL) {
		return KNOT_ENOMEM;
	}

	ctx->policy = calloc(1, sizeof(*ctx->policy));
	if (ctx->policy == NULL) {
		free(ctx->zone);
		return KNOT_ENOMEM;
	}

	policy_from_zone(ctx->policy, zone);
	if (conf != NULL) {
		conf_val_t policy_id = conf_zone_get(conf, C_DNSSEC_POLICY, zone->apex->owner);
		conf_id_fix_default(&policy_id);
		conf_val_t num_threads = conf_id_get(conf, C_POLICY, C_SIGNING_THREADS, &policy_id);
		ctx->policy->signing_threads = conf_int(&num_threads);
	} else {
		ctx->policy->signing_threads = MAX(dt_optimal_size(), 1);
	}

	int ret = kasp_zone_from_contents(ctx->zone, zone, ctx->policy->single_type_signing,
	                                  ctx->policy->nsec3_enabled, &ctx->policy->nsec3_iterations,
	                                  &ctx->keytag_conflict);
	if (ret != KNOT_EOK) {
		memset(ctx->zone, 0, sizeof(*ctx->zone));
		kdnssec_ctx_deinit(ctx);
		return ret;
	}

	ctx->now = knot_time();
	ctx->validation_mode = true;
	return KNOT_EOK;
}
