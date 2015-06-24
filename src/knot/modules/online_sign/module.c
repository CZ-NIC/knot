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

#include "knot/common/log.h"
#include "knot/conf/base.h"

#include "knot/modules/online_sign/module.h"
#include "knot/modules/online_sign/nsec_next.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/internet.h"

#include "libknot/dnssec/rrset-sign.h"
#include "libknot/internal/mem.h"

#include "dnssec/error.h"
#include "dnssec/kasp.h"
#include "dnssec/sign.h"
#include "dnssec/nsec.h"

#define NSEC_RR_TTL 1200
#define DNSKEY_RR_TTL 1200
#define RRSIG_LIFETIME (25*60*60)

const yp_item_t scheme_mod_online_sign[] = {
	{ C_ID, YP_TSTR, YP_VNONE },
	{ NULL }
};

struct online_sign_ctx {
	dnssec_key_t *key;
	knot_rrset_t *dnskey_rrset;
};

typedef struct online_sign_ctx online_sign_ctx_t;

static bool want_dnssec(struct query_data *qdata)
{
	return knot_pkt_has_dnssec(qdata->query);
}

static dnssec_nsec_bitmap_t *nxdomain_bitmap(void)
{
	dnssec_nsec_bitmap_t *bitmap = dnssec_nsec_bitmap_new();
	dnssec_nsec_bitmap_add(bitmap, KNOT_RRTYPE_NSEC);
	dnssec_nsec_bitmap_add(bitmap, KNOT_RRTYPE_RRSIG);
	return bitmap;
}

static knot_rrset_t *nxdomain_nsec(const knot_dname_t *qname,
                                   const knot_dname_t *apex,
                                   mm_ctx_t *mm)
{
	knot_rrset_t *nsec = knot_rrset_new(qname, KNOT_RRTYPE_NSEC, KNOT_CLASS_IN, mm);
	if (!nsec) {
		return NULL;
	}

	knot_dname_t *next = online_nsec_next(qname, apex);
	if (!next) {
		knot_rrset_free(&nsec, mm);
		return NULL;
	}

	dnssec_nsec_bitmap_t *bitmap = nxdomain_bitmap();
	if (!bitmap) {
		free(next);
		knot_rrset_free(&nsec, mm);
	}

	size_t size = knot_dname_size(next) + dnssec_nsec_bitmap_size(bitmap);
	uint8_t rdata[size];

	int written = knot_dname_to_wire(rdata, next, size);
	dnssec_nsec_bitmap_write(bitmap, rdata + written);

	knot_dname_free(&next, NULL);
	dnssec_nsec_bitmap_free(bitmap);

	if (knot_rrset_add_rdata(nsec, rdata, size, NSEC_RR_TTL, mm) != KNOT_EOK) {
		knot_rrset_free(&nsec, mm);
		return NULL;
	}

	return nsec;
}

static knot_rrset_t *rrset_sign(const knot_rrset_t *cover,
                                online_sign_ctx_t *module_ctx,
                                dnssec_sign_ctx_t *sign_ctx,
                                mm_ctx_t *mm)
{
	knot_rrset_t *rrsig = knot_rrset_new(cover->owner, KNOT_RRTYPE_RRSIG,
	                                     cover->rclass, mm);
	if (!rrsig) {
		return NULL;
	}

	// compatible context

	dnssec_kasp_policy_t policy = {
		.rrsig_lifetime = RRSIG_LIFETIME
	};

	kdnssec_ctx_t ksign_ctx = {
		.now = time(NULL),
		.policy = &policy
	};

	int r = knot_sign_rrset(rrsig, cover, module_ctx->key, sign_ctx, &ksign_ctx, mm);
	if (r != KNOT_EOK) {
		knot_rrset_free(&rrsig, mm);
		return NULL;
	}

	return rrsig;
}

static int section_sign(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
{
	online_sign_ctx_t *module_ctx = _ctx;

	if (!want_dnssec(qdata)) {
		return state;
	}

	dnssec_sign_ctx_t *sign_ctx = NULL;
	int r = dnssec_sign_new(&sign_ctx, module_ctx->key);
	if (r != DNSSEC_EOK) {
		return ERROR;
	}

	const knot_pktsection_t *section = knot_pkt_section(pkt, pkt->current);
	assert(section);

	uint16_t count_unsigned = section->count;
	for (int i = 0; i < count_unsigned; i++) {
		const knot_rrset_t *rr = knot_pkt_rr(section, i);
		knot_rrset_t *rrsig = rrset_sign(rr, module_ctx, sign_ctx, &pkt->mm);
		if (!rrsig) {
			state = ERROR;
			break;
		}

		r = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, rrsig, KNOT_PF_FREE);
		if (r != KNOT_EOK) {
			knot_rrset_free(&rrsig, &pkt->mm);
			state = ERROR;
			break;
		}
	}

	dnssec_sign_free(sign_ctx);

	return state;
}

static int solve_nxdomain(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
{
	log_zone_debug(qdata->zone->name, "current state %d", state);

	//! TODO: is this correct approach?
	const knot_pktsection_t *ans = knot_pkt_section(pkt, KNOT_ANSWER);
	if (ans->count > 0) {
		return state;
	}

	// synthesise NSEC

	if (want_dnssec(qdata)) {
		knot_rrset_t *nsec = nxdomain_nsec(qdata->name, qdata->zone->name, &pkt->mm);
		int r = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, nsec, KNOT_PF_FREE);
		if (r != DNSSEC_EOK) {
			knot_rrset_free(&nsec, &pkt->mm);
			return ERROR;
		}
	}

	// promote NXDOMAIN to NODATA

	return NODATA;
}

static bool is_apex_query(struct query_data *qdata)
{
	return knot_dname_is_equal(qdata->name, qdata->zone->name);
}

static int synth_answer(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
{
	online_sign_ctx_t *ctx = _ctx;

	// disallow ANY for now
	if (knot_pkt_qtype(pkt) == KNOT_RRTYPE_ANY) {
		qdata->rcode = KNOT_RCODE_REFUSED;
		return ERROR;
	}

	if (knot_pkt_qtype(pkt) == KNOT_RRTYPE_DNSKEY && is_apex_query(qdata)) {
		int r = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, ctx->dnskey_rrset, 0);
		if (r != DNSSEC_EOK) {
			return ERROR;
		}
		return HIT;
	}

	if (knot_pkt_qtype(pkt) == KNOT_RRTYPE_NSEC) {
		return ERROR;
	}

	if (knot_pkt_qtype(pkt) == KNOT_RRTYPE_RRSIG) {
		qdata->rcode = KNOT_RCODE_REFUSED;
		return ERROR;
	}

	return solve_nxdomain(state, pkt, qdata, NULL);
}

static int get_dnssec_key(dnssec_key_t **key_ptr,
                          const knot_dname_t *zone_name,
                          const char *kasp_path)
{
	// KASP database

	dnssec_kasp_t *kasp = NULL;
	int r = dnssec_kasp_init_dir(&kasp);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_kasp_open(kasp, kasp_path);
	if (r != DNSSEC_EOK) {
		dnssec_kasp_deinit(kasp);
		return r;
	}

	// KASP zone

	char *zone_str = knot_dname_to_str_alloc(zone_name);
	if (!zone_str) {
		dnssec_kasp_deinit(kasp);
		return KNOT_ENOMEM;
	}

	dnssec_kasp_zone_t *zone = NULL;
	r = dnssec_kasp_zone_load(kasp, zone_str, &zone);
	free(zone_str);
	if (r != DNSSEC_EOK) {
		dnssec_kasp_deinit(kasp);
		return r;
	}

	// DNSSEC key

	dnssec_list_t *list = dnssec_kasp_zone_get_keys(zone);
	assert(list);
	dnssec_item_t *item = dnssec_list_nth(list, 0);
	if (!item) {
		dnssec_kasp_zone_free(zone);
		dnssec_kasp_deinit(kasp);
		return DNSSEC_NOT_FOUND;
	}

	dnssec_kasp_key_t *kasp_key = dnssec_item_get(item);
	assert(kasp_key);
	dnssec_key_t *key = dnssec_key_dup(kasp_key->key);

	dnssec_kasp_zone_free(zone);
	dnssec_kasp_deinit(kasp);

	if (!key) {
		return KNOT_ENOMEM;
	}

	*key_ptr = key;
	return KNOT_EOK;
}

static int load_private_key(dnssec_key_t *key, const char *kasp_path)
{
	char *keystore_path = sprintf_alloc("%s/keys", kasp_path);
	if (!keystore_path) {
		return KNOT_ENOMEM;
	}

	dnssec_keystore_t *store = NULL;
	dnssec_keystore_init_pkcs8_dir(&store);
	int r = dnssec_keystore_open(store, keystore_path);
	free(keystore_path);
	if (r != DNSSEC_EOK) {
		dnssec_keystore_deinit(store);
		return r;
	}

	r = dnssec_key_import_private_keystore(key, store);
	dnssec_keystore_deinit(store);

	return r;
}

static int get_online_key(dnssec_key_t **key_ptr, const knot_dname_t *zone_name,
                          const char *kasp_path)
{
	dnssec_key_t *key = NULL;

	int r = get_dnssec_key(&key, zone_name, kasp_path);
	if (r != KNOT_EOK) {
		return r;
	}

	r = load_private_key(key, kasp_path);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(key);
		return r;
	}

	*key_ptr = key;

	return KNOT_EOK;
}

static knot_rrset_t *create_dnskey_rrset(const dnssec_key_t *key,
                                         const knot_dname_t *zone)
{
	knot_rrset_t *dnskey = knot_rrset_new(zone, KNOT_RRTYPE_DNSKEY,
	                                      KNOT_CLASS_IN, NULL);
	if (!dnskey) {
		return NULL;
	}

	dnssec_binary_t rdata = { 0 };
	dnssec_key_get_rdata(key, &rdata);
	assert(rdata.size > 0 && rdata.data);

	int r = knot_rrset_add_rdata(dnskey, rdata.data, rdata.size,
	                             DNSKEY_RR_TTL, NULL);
	if (r != DNSSEC_EOK) {
		knot_rrset_free(&dnskey, NULL);
		return NULL;
	}

	return dnskey;
}

static void online_sign_ctx_free(online_sign_ctx_t *ctx)
{
	dnssec_key_free(ctx->key);
	knot_rrset_free(&ctx->dnskey_rrset, NULL);

	free(ctx);
}

static int online_sign_ctx_new(online_sign_ctx_t **ctx_ptr,
                               const knot_dname_t *zone, const char *kasp_path)
{
	online_sign_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return KNOT_ENOMEM;
	}

	int r = get_online_key(&ctx->key, zone, kasp_path);
	if (r != KNOT_EOK) {
		online_sign_ctx_free(ctx);
		return r;
	}

	ctx->dnskey_rrset = create_dnskey_rrset(ctx->key, zone);
	if (!ctx->dnskey_rrset) {
		online_sign_ctx_free(ctx);
		return KNOT_ENOMEM;
	}

	*ctx_ptr = ctx;

	return KNOT_EOK;
}

static char *conf_kasp_path(const knot_dname_t *zone)
{
	conf_val_t val = { 0 };

	val = conf_zone_get(conf(), C_STORAGE, zone);
	char *storage = conf_abs_path(&val, NULL);
	val = conf_zone_get(conf(), C_KASP_DB, zone);
	char *kasp_db = conf_abs_path(&val, storage);
	free(storage);

	return kasp_db;
}

int online_sign_load(struct query_plan *plan, struct query_module *module,
                     const knot_dname_t *zone)
{
	assert(plan);
	assert(module);

	if (!zone) {
		log_error("online signing, global module instance is not supported");
		return KNOT_ENOTSUP;
	}

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone);
	if (conf_bool(&val)) {
		log_zone_error(zone, "online signing, incompatible with automatic signing");
		return KNOT_ENOTSUP;
	}

	char *kasp_path = conf_kasp_path(zone);
	if (!kasp_path) {
		log_zone_error(zone, "online signing, KASP database is not configured");
		return KNOT_ERROR;
	}

	online_sign_ctx_t *ctx = NULL;
	int r = online_sign_ctx_new(&ctx, zone, kasp_path);
	free(kasp_path);
	if (r != KNOT_EOK) {
		log_zone_error(zone, "online signing, failed to initialize signing key (%s)",
		               dnssec_strerror(r));
		return KNOT_ERROR;
	}

	query_plan_step(plan, QPLAN_ANSWER, synth_answer, ctx);

	query_plan_step(plan, QPLAN_ANSWER,     section_sign, ctx);
	query_plan_step(plan, QPLAN_AUTHORITY,  section_sign, ctx);
	query_plan_step(plan, QPLAN_ADDITIONAL, section_sign, ctx);

	module->ctx = ctx;

	return KNOT_EOK;
}

int online_sign_unload(struct query_module *module)
{
	assert(module);

	online_sign_ctx_free(module->ctx);
	module->ctx = NULL;

	return KNOT_EOK;
}
