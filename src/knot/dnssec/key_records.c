/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/dnssec/key_records.h"

#include "libdnssec/error.h"
#include "libdnssec/sign.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/journal/serialization.h"

void key_records_init(const kdnssec_ctx_t *ctx, key_records_t *r)
{
	knot_rrset_init(&r->dnskey, knot_dname_copy(ctx->zone->dname, NULL),
	                KNOT_RRTYPE_DNSKEY, KNOT_CLASS_IN, ctx->policy->dnskey_ttl);
	knot_rrset_init(&r->cdnskey, knot_dname_copy(ctx->zone->dname, NULL),
	                KNOT_RRTYPE_CDNSKEY, KNOT_CLASS_IN, 0);
	knot_rrset_init(&r->cds, knot_dname_copy(ctx->zone->dname, NULL),
	                KNOT_RRTYPE_CDS, KNOT_CLASS_IN, 0);
	knot_rrset_init(&r->rrsig, knot_dname_copy(ctx->zone->dname, NULL),
	                KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, ctx->policy->dnskey_ttl);
}

int key_records_add_rdata(key_records_t *r, uint16_t rrtype, uint8_t *rdata, uint16_t rdlen, uint32_t ttl)
{
	knot_rrset_t *to_add;
	switch(rrtype) {
	case KNOT_RRTYPE_DNSKEY:
		to_add = &r->dnskey;
		break;
	case KNOT_RRTYPE_CDNSKEY:
		to_add = &r->cdnskey;
		break;
	case KNOT_RRTYPE_CDS:
		to_add = &r->cds;
		break;
	case KNOT_RRTYPE_RRSIG:
		to_add = &r->rrsig;
		break;
	default:
		return KNOT_EINVAL;
	}

	int ret = knot_rrset_add_rdata(to_add, rdata, rdlen, NULL);
	if (ret == KNOT_EOK) {
		to_add->ttl = ttl;
	}
	return ret;
}

void key_records_clear(key_records_t *r)
{
	knot_rrset_clear(&r->dnskey, NULL);
	knot_rrset_clear(&r->cdnskey, NULL);
	knot_rrset_clear(&r->cds, NULL);
	knot_rrset_clear(&r->rrsig, NULL);
}

void key_records_clear_rdatasets(key_records_t *r)
{
	knot_rdataset_clear(&r->dnskey.rrs, NULL);
	knot_rdataset_clear(&r->cdnskey.rrs, NULL);
	knot_rdataset_clear(&r->cds.rrs, NULL);
	knot_rdataset_clear(&r->rrsig.rrs, NULL);
}

int key_records_dump(char **buf, size_t *buf_size, const key_records_t *r, bool verbose)
{
	if (*buf == NULL) {
		if (*buf_size == 0) {
			*buf_size = 512;
		}
		*buf = malloc(*buf_size);
		if (*buf == NULL) {
			return KNOT_ENOMEM;
		}
	}

	const knot_dump_style_t verb_style = {
		.wrap = true,
		.show_ttl = true,
		.verbose = true,
		.original_ttl = true,
		.human_tmstamp = true
	};
	const knot_dump_style_t *style = verbose ? &verb_style : &KNOT_DUMP_STYLE_DEFAULT;

	int ret = 0;
	size_t total = 1;
	const knot_rrset_t *all_rr[4] = { &r->dnskey, &r->cdnskey, &r->cds, &r->rrsig };
	// first go: just detect the size
	for (int i = 0; i < 4; i++) {
		if (ret >= 0 && !knot_rrset_empty(all_rr[i])) {
			ret = knot_rrset_txt_dump(all_rr[i], buf, buf_size, style);
			(void)buf;
			total += ret;
		}
	}
	if (ret >= 0 && total > *buf_size) {
		free(*buf);
		*buf_size = total;
		*buf = malloc(*buf_size);
		if (*buf == NULL) {
			return KNOT_ENOMEM;
		}
	}
	char *fake_buf = *buf;
	size_t fake_size = *buf_size;
	//second go: do it
	for (int i = 0; i < 4; i++) {
		if (ret >= 0 && !knot_rrset_empty(all_rr[i])) {
			ret = knot_rrset_txt_dump(all_rr[i], &fake_buf, &fake_size, style);
			fake_buf += ret, fake_size -= ret;
		}
	}
	assert(fake_buf - *buf == total - 1);
	return ret >= 0 ? KNOT_EOK : ret;
}

int key_records_sign(const zone_key_t *key, key_records_t *r, const kdnssec_ctx_t *kctx, knot_time_t *expires)
{
	dnssec_sign_ctx_t *sign_ctx;
	int ret = dnssec_sign_new(&sign_ctx, key->key);
	if (ret != DNSSEC_EOK) {
		ret = knot_error_from_libdnssec(ret);
	}

	if (!knot_rrset_empty(&r->dnskey) && knot_zone_sign_use_key(key, &r->dnskey)) {
		ret = knot_sign_rrset(&r->rrsig, &r->dnskey, key->key, sign_ctx, kctx, NULL, expires);
	}
	if (ret == KNOT_EOK && !knot_rrset_empty(&r->cdnskey) && knot_zone_sign_use_key(key, &r->cdnskey)) {
		ret = knot_sign_rrset(&r->rrsig, &r->cdnskey, key->key, sign_ctx, kctx, NULL, expires);
	}
	if (ret == KNOT_EOK && !knot_rrset_empty(&r->cds) && knot_zone_sign_use_key(key, &r->cds)) {
		ret = knot_sign_rrset(&r->rrsig, &r->cds, key->key, sign_ctx, kctx, NULL, expires);
	}

	dnssec_sign_free(sign_ctx);
	return ret;
}

int key_records_verify(key_records_t *r, kdnssec_ctx_t *kctx, knot_time_t timestamp)
{
	kctx->now = timestamp;
	int ret = kasp_zone_keys_from_rr(kctx->zone, &r->dnskey.rrs, false, &kctx->keytag_conflict);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_sign_ctx_t *sign_ctx = zone_validation_ctx(kctx);
	if (sign_ctx == NULL) {
		return KNOT_ENOMEM;
	}

	ret = knot_validate_rrsigs(&r->dnskey, &r->rrsig, sign_ctx, false);
	if (ret == KNOT_EOK && !knot_rrset_empty(&r->cdnskey)) {
		ret = knot_validate_rrsigs(&r->cdnskey, &r->rrsig, sign_ctx, false);
	}
	if (ret == KNOT_EOK && !knot_rrset_empty(&r->cds)) {
		ret = knot_validate_rrsigs(&r->cds, &r->rrsig, sign_ctx, false);
	}

	zone_sign_ctx_free(sign_ctx);
	return ret;
}

size_t key_records_serialized_size(const key_records_t *r)
{
	return rrset_serialized_size(&r->dnskey) + rrset_serialized_size(&r->cdnskey) +
	       rrset_serialized_size(&r->cds) + rrset_serialized_size(&r->rrsig);
}

int key_records_serialize(wire_ctx_t *wire, const key_records_t *r)
{
	int ret = serialize_rrset(wire, &r->dnskey);
	if (ret == KNOT_EOK) {
		ret = serialize_rrset(wire, &r->cdnskey);
	}
	if (ret == KNOT_EOK) {
		ret = serialize_rrset(wire, &r->cds);
	}
	if (ret == KNOT_EOK) {
		ret = serialize_rrset(wire, &r->rrsig);
	}
	return ret;
}

int key_records_deserialize(wire_ctx_t *wire, key_records_t *r)
{
	int ret = deserialize_rrset(wire, &r->dnskey);
	if (ret == KNOT_EOK) {
		ret = deserialize_rrset(wire, &r->cdnskey);
	}
	if (ret == KNOT_EOK) {
		ret = deserialize_rrset(wire, &r->cds);
	}
	if (ret == KNOT_EOK) {
		ret = deserialize_rrset(wire, &r->rrsig);
	}
	return ret;
}
