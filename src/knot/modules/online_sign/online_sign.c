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
#include <stddef.h>

#include "dnssec/error.h"

#include "contrib/string.h"
#include "knot/modules/online_sign/online_sign.h"
#include "knot/modules/online_sign/nsec_next.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-events.h"

#define MOD_POLICY	C_POLICY

const yp_item_t scheme_mod_online_sign[] = {
	{ C_ID,       YP_TSTR, YP_VNONE },
	{ MOD_POLICY, YP_TREF, YP_VREF = { C_POLICY }, YP_FNONE, { check_ref_dflt } },
	{ C_COMMENT,  YP_TSTR, YP_VNONE },
	{ NULL }
};

#define module_zone_error(zone, msg...) \
	MODULE_ZONE_ERR(C_MOD_ONLINE_SIGN, zone, msg)

#define RRSIG_LIFETIME (25*60*60)

/*
 * TODO:
 *
 * - Fix delegation signing:
 *   + The NSEC proof can decsend into the child zone.
 *   + Out-of-zone glue records can be signed.
 *
 * - Fix CNAME handling:
 *   + Owner name of synthesized records can be incorrect.
 *   + Combination with wildcards results in invalid signatures.
 *
 * - Add support for CDS/CDSKEY synthesis.
 *
 */

/*!
 * \brief RR types to force in synthesised NSEC maps.
 *
 * We cannot determine the true NSEC bitmap because of dynamic modules which
 * can synthesize some types on-the-fly. The base NSEC map will be determined
 * from zone content and this list of types.
 *
 * The types in the NSEC bitmap really don't have to exist. Only the QTYPE
 * must not be present. This will make the validation work with resolvers
 * performing negative caching.
 *
 * This list should contain all RR types, which can be potentionally
 * synthesized by other modules.
 */
static const uint16_t NSEC_FORCE_TYPES[] = {
	KNOT_RRTYPE_A,
	KNOT_RRTYPE_AAAA,
	0
};

typedef struct {
	dnssec_key_t *key;
	uint32_t rrsig_lifetime;
} online_sign_ctx_t;

static bool want_dnssec(struct query_data *qdata)
{
	return knot_pkt_has_dnssec(qdata->query);
}

static uint32_t dnskey_ttl(const zone_t *zone)
{
	knot_rrset_t soa = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	return knot_rrset_ttl(&soa);
}

static uint32_t nsec_ttl(const zone_t *zone)
{
	knot_rrset_t soa = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	return knot_soa_minimum(&soa.rrs);
}

/*!
 * \brief Add bitmap records synthesized by online-signing.
 */
static void bitmap_add_synth(dnssec_nsec_bitmap_t *map, bool is_apex)
{
	dnssec_nsec_bitmap_add(map, KNOT_RRTYPE_NSEC);
	dnssec_nsec_bitmap_add(map, KNOT_RRTYPE_RRSIG);
	if (is_apex) {
		dnssec_nsec_bitmap_add(map, KNOT_RRTYPE_DNSKEY);
		//dnssec_nsec_bitmap_add(map, KNOT_RRTYPE_CDS);
	}
}

/*!
 * \brief Add bitmap records present in the zone.
 */
static void bitmap_add_zone(dnssec_nsec_bitmap_t *map, const zone_node_t *node)
{
	if (!node) {
		return;
	}

	for (int i = 0; i < node->rrset_count; i++) {
		dnssec_nsec_bitmap_add(map, node->rrs[i].type);
	}
}

/*!
 * \brief Add bitmap records which can be synthesized by other modules.
 *
 * \param qtype  Current QTYPE, will never be added into the map.
 */
static void bitmap_add_forced(dnssec_nsec_bitmap_t *map, uint16_t qtype)
{
	for (const uint16_t *type = NSEC_FORCE_TYPES; *type; type += 1) {
		if (*type != qtype) {
			dnssec_nsec_bitmap_add(map, *type);
		}
	}
}

/*!
 * \brief Add bitmap records from the actual response.
 */
static void bitmap_add_section(dnssec_nsec_bitmap_t *map, const knot_pktsection_t *answer)
{
	for (int i = 0; i < answer->count; i++) {
		const knot_rrset_t *rr = knot_pkt_rr(answer, i);
		dnssec_nsec_bitmap_add(map, rr->type);
	}
}

/*!
 * \brief Synthesize NSEC type bitmap.
 *
 * - The bitmap will contain types synthesized by this module.
 * - For ANY query, the bitmap will contain types from the actual response.
 * - For non-ANY query, the bitmap will contain types from zone and forced
 *   types which can be potentionally synthesized by other query modules.
 */
static dnssec_nsec_bitmap_t *synth_bitmap(knot_pkt_t *pkt, const struct query_data *qdata)
{
	dnssec_nsec_bitmap_t *map = dnssec_nsec_bitmap_new();
	if (!map) {
		return NULL;
	}

	uint16_t qtype = knot_pkt_qtype(qdata->query);
	bool is_apex = qdata->zone
	               && qdata->zone->contents
	               && qdata->node == qdata->zone->contents->apex;

	bitmap_add_synth(map, is_apex);

	if (qtype == KNOT_RRTYPE_ANY) {
		const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
		bitmap_add_section(map, answer);
	} else {
		bitmap_add_zone(map, qdata->node);
		if (!node_rrtype_exists(qdata->node, KNOT_RRTYPE_CNAME)) {
			bitmap_add_forced(map, qtype);
		}
	}

	return map;
}

static knot_rrset_t *synth_nsec(knot_pkt_t *pkt, struct query_data *qdata, knot_mm_t *mm)
{
	knot_rrset_t *nsec = knot_rrset_new(qdata->name, KNOT_RRTYPE_NSEC, KNOT_CLASS_IN, mm);
	if (!nsec) {
		return NULL;
	}

	knot_dname_t *next = online_nsec_next(qdata->name, qdata->zone->name);
	if (!next) {
		knot_rrset_free(&nsec, mm);
		return NULL;
	}

	dnssec_nsec_bitmap_t *bitmap = synth_bitmap(pkt, qdata);
	if (!bitmap) {
		free(next);
		knot_rrset_free(&nsec, mm);
		return NULL;
	}

	size_t size = knot_dname_size(next) + dnssec_nsec_bitmap_size(bitmap);
	uint8_t rdata[size];

	int written = knot_dname_to_wire(rdata, next, size);
	dnssec_nsec_bitmap_write(bitmap, rdata + written);

	knot_dname_free(&next, NULL);
	dnssec_nsec_bitmap_free(bitmap);

	uint32_t ttl = nsec_ttl(qdata->zone);

	if (knot_rrset_add_rdata(nsec, rdata, size, ttl, mm) != KNOT_EOK) {
		knot_rrset_free(&nsec, mm);
		return NULL;
	}

	return nsec;
}

static knot_rrset_t *sign_rrset(const knot_dname_t *owner,
                                const knot_rrset_t *cover,
                                online_sign_ctx_t *module_ctx,
                                dnssec_sign_ctx_t *sign_ctx,
                                knot_mm_t *mm)
{
	// copy of RR set with replaced owner name

	knot_rrset_t *copy = knot_rrset_new(owner, cover->type, cover->rclass, NULL);
	if (!copy) {
		return NULL;
	}

	if (knot_rdataset_copy(&copy->rrs, &cover->rrs, NULL) != KNOT_EOK) {
		knot_rrset_free(&copy, NULL);
		return NULL;
	}

	// resulting RRSIG

	knot_rrset_t *rrsig = knot_rrset_new(owner, KNOT_RRTYPE_RRSIG, copy->rclass, mm);
	if (!rrsig) {
		knot_rrset_free(&copy, NULL);
		return NULL;
	}

	// compatible context

	knot_kasp_policy_t policy = {
		.rrsig_lifetime = module_ctx->rrsig_lifetime
	};

	kdnssec_ctx_t ksign_ctx = {
		.now = time(NULL),
		.policy = &policy
	};

	int r = knot_sign_rrset(rrsig, copy, module_ctx->key, sign_ctx, &ksign_ctx, mm);

	knot_rrset_free(&copy, NULL);

	if (r != KNOT_EOK) {
		knot_rrset_free(&rrsig, mm);
		return NULL;
	}

	return rrsig;
}

static int sign_section(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
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
		uint16_t rr_pos = knot_pkt_rr_offset(section, i);

		uint8_t owner[KNOT_DNAME_MAXLEN] = { 0 };
		knot_dname_unpack(owner, pkt->wire + rr_pos, sizeof(owner), pkt->wire);
		knot_dname_to_lower(owner);

		knot_rrset_t *rrsig = sign_rrset(owner, rr, module_ctx, sign_ctx, &pkt->mm);
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

static int synth_authority(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
{
	if (state == HIT) {
		return state;
	}

	// synthesise NSEC

	if (want_dnssec(qdata)) {
		knot_rrset_t *nsec = synth_nsec(pkt, qdata, &pkt->mm);
		int r = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, nsec, KNOT_PF_FREE);
		if (r != DNSSEC_EOK) {
			knot_rrset_free(&nsec, &pkt->mm);
			return ERROR;
		}
	}

	// promote NXDOMAIN to NODATA

	if (state == MISS) {
		//! \todo Override RCODE set in solver_authority. Review.
		qdata->rcode = KNOT_RCODE_NOERROR;
		return NODATA;
	}

	return state;
}

static knot_rrset_t *synth_dnskey(const zone_t *zone, const dnssec_key_t *key,
                                  knot_mm_t *mm)
{
	knot_rrset_t *dnskey = knot_rrset_new(zone->name, KNOT_RRTYPE_DNSKEY,
	                                      KNOT_CLASS_IN, mm);
	if (!dnskey) {
		return 0;
	}

	dnssec_binary_t rdata = { 0 };
	dnssec_key_get_rdata(key, &rdata);
	assert(rdata.size > 0 && rdata.data);

	uint32_t ttl = dnskey_ttl(zone);

	int r = knot_rrset_add_rdata(dnskey, rdata.data, rdata.size, ttl, mm);
	if (r != KNOT_EOK) {
		knot_rrset_free(&dnskey, mm);
		return NULL;
	}

	return dnskey;
}

static bool qtype_match(struct query_data *qdata, uint16_t type)
{
	uint16_t qtype = knot_pkt_qtype(qdata->query);
	return (qtype == KNOT_RRTYPE_ANY || qtype == type);
}

static bool is_apex_query(struct query_data *qdata)
{
	return knot_dname_is_equal(qdata->name, qdata->zone->name);
}

static int synth_answer(int state, knot_pkt_t *pkt, struct query_data *qdata, void *_ctx)
{
	online_sign_ctx_t *ctx = _ctx;

	// disallowed queries

	if (knot_pkt_qtype(pkt) == KNOT_RRTYPE_RRSIG) {
		qdata->rcode = KNOT_RCODE_REFUSED;
		return ERROR;
	}

	// synthesized DNSSEC answers

	if (qtype_match(qdata, KNOT_RRTYPE_DNSKEY) && is_apex_query(qdata)) {
		knot_rrset_t *dnskey = synth_dnskey(qdata->zone, ctx->key, &pkt->mm);
		if (!dnskey) {
			return ERROR;
		}

		int r = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, dnskey, KNOT_PF_FREE);
		if (r != DNSSEC_EOK) {
			knot_rrset_free(&dnskey, &pkt->mm);
			return ERROR;
		}

		state = HIT;
	}

	if (qtype_match(qdata, KNOT_RRTYPE_NSEC)) {
		knot_rrset_t *nsec = synth_nsec(pkt, qdata, &pkt->mm);
		if (!nsec) {
			return ERROR;
		}

		int r = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, nsec, KNOT_PF_FREE);
		if (r != DNSSEC_EOK) {
			knot_rrset_free(&nsec, &pkt->mm);
			return ERROR;
		}

		state = HIT;
	}

	return state;
}

static int get_online_key(dnssec_key_t **key_ptr, struct query_module *module)
{
	kdnssec_ctx_t kctx = { 0 };

	int r = kdnssec_ctx_init(module->config, &kctx, module->zone, module->id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// Force Singe-Type signing scheme.
	kctx.policy->singe_type_signing = true;

	bool ignore1 = false;
	time_t ignore2 = 0;
	r = knot_dnssec_zsk_rollover(&kctx, &ignore1, &ignore2);
	if (r != DNSSEC_EOK) {
		goto fail;
	}

	assert(kctx.zone->num_keys > 0);
	knot_kasp_key_t *kasp_key = &kctx.zone->keys[0];
	assert(kasp_key);

	dnssec_key_t *key = dnssec_key_dup(kasp_key->key);
	if (!key) {
		r = KNOT_ENOMEM;
		goto fail;
	}

	r = dnssec_key_import_keystore(key, kctx.keystore, kasp_key->id);
	if (r != DNSSEC_EOK) {
		dnssec_key_free(key);
		goto fail;
	}

	*key_ptr = key;

fail:
	kdnssec_ctx_deinit(&kctx);

	return r;
}

static void online_sign_ctx_free(online_sign_ctx_t *ctx)
{
	dnssec_key_free(ctx->key);

	free(ctx);
}

static int online_sign_ctx_new(online_sign_ctx_t **ctx_ptr, struct query_module *module)
{
	online_sign_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return KNOT_ENOMEM;
	}

	int r = get_online_key(&ctx->key, module);
	if (r != KNOT_EOK) {
		online_sign_ctx_free(ctx);
		return r;
	}

	ctx->rrsig_lifetime = RRSIG_LIFETIME;
	conf_val_t policy = conf_mod_get(module->config, MOD_POLICY, module->id);
	if (policy.code == KNOT_EOK) {
		conf_val_t val = conf_id_get(module->config, C_POLICY, C_RRSIG_LIFETIME, &policy);
		if (val.code == KNOT_EOK) {
			ctx->rrsig_lifetime = conf_int(&val);
		}
	}

	*ctx_ptr = ctx;

	return KNOT_EOK;
}

int online_sign_load(struct query_module *module)
{
	assert(module);
	assert(module->zone);

	conf_val_t val = conf_zone_get(module->config, C_DNSSEC_SIGNING, module->zone);
	if (conf_bool(&val)) {
		module_zone_error(module->zone, "incompatible with automatic signing");
		return KNOT_ENOTSUP;
	}

	online_sign_ctx_t *ctx = NULL;
	int r = online_sign_ctx_new(&ctx, module);
	if (r != KNOT_EOK) {
		module_zone_error(module->zone, "failed to initialize signing key (%s)",
		                  dnssec_strerror(r));
		return KNOT_ERROR;
	}

	module->ctx = ctx;

	query_module_step(module, QPLAN_ANSWER, synth_answer);
	query_module_step(module, QPLAN_ANSWER, sign_section);

	query_module_step(module, QPLAN_AUTHORITY, synth_authority);
	query_module_step(module, QPLAN_AUTHORITY, sign_section);

	query_module_step(module, QPLAN_ADDITIONAL, sign_section);

	return KNOT_EOK;
}

void online_sign_unload(struct query_module *module)
{
	assert(module);

	online_sign_ctx_t *ctx = module->ctx;

	online_sign_ctx_free(ctx);
}
