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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "knot/dnssec/key_records.h"

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

int key_records_dump(char **buf, size_t *buf_size, const key_records_t *r)
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
	int ret = KNOT_EOK;
	size_t total = 1;
	// first go: just detect the size
	if (!knot_rrset_empty(&r->dnskey)) {
		ret = knot_rrset_txt_dump(&r->dnskey, buf, buf_size, &KNOT_DUMP_STYLE_DEFAULT);
		total += ret;
	}
	if (ret >= 0 && !knot_rrset_empty(&r->cdnskey)) {
		ret = knot_rrset_txt_dump(&r->cdnskey, buf, buf_size, &KNOT_DUMP_STYLE_DEFAULT);
		total += ret;
	}
	if (ret >= 0 && !knot_rrset_empty(&r->cds)) {
		ret = knot_rrset_txt_dump(&r->cds, buf, buf_size, &KNOT_DUMP_STYLE_DEFAULT);
		total += ret;
	}
	if (ret >= 0 && !knot_rrset_empty(&r->rrsig)) {
		ret = knot_rrset_txt_dump(&r->rrsig, buf, buf_size, &KNOT_DUMP_STYLE_DEFAULT);
		total += ret;
	}
	if (ret >= 0 && total < *buf_size) {
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
	if (ret >= 0 && !knot_rrset_empty(&r->dnskey)) {
		ret = knot_rrset_txt_dump(&r->dnskey, &fake_buf, &fake_size, &KNOT_DUMP_STYLE_DEFAULT);
		fake_buf += ret, fake_size -= ret;
	}
	if (ret >= 0 && !knot_rrset_empty(&r->cdnskey)) {
		ret = knot_rrset_txt_dump(&r->cdnskey, &fake_buf, &fake_size, &KNOT_DUMP_STYLE_DEFAULT);
		fake_buf += ret, fake_size -= ret;
	}
	if (ret >= 0 && !knot_rrset_empty(&r->cds)) {
		ret = knot_rrset_txt_dump(&r->cds, &fake_buf, &fake_size, &KNOT_DUMP_STYLE_DEFAULT);
		fake_buf += ret, fake_size -= ret;
	}
	if (ret >= 0 && !knot_rrset_empty(&r->rrsig)) {
		ret = knot_rrset_txt_dump(&r->rrsig, &fake_buf, &fake_size, &KNOT_DUMP_STYLE_DEFAULT);
	}
	return ret >= 0 ? KNOT_EOK : ret;
}

int key_records_sign(const zone_key_t *key, key_records_t *r, const kdnssec_ctx_t *kctx)
{
	if (!key->is_active && !key->is_post_active) {
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	if (!knot_rrset_empty(&r->dnskey) && knot_zone_sign_use_key(key, &r->dnskey)) {
		ret = knot_sign_rrset(&r->rrsig, &r->dnskey, key->key, key->ctx, kctx, NULL, NULL);
	}
	if (ret == KNOT_EOK && !knot_rrset_empty(&r->cdnskey) && knot_zone_sign_use_key(key, &r->cdnskey)) {
		ret = knot_sign_rrset(&r->rrsig, &r->cdnskey, key->key, key->ctx, kctx, NULL, NULL);
	}
	if (ret == KNOT_EOK && !knot_rrset_empty(&r->cds) && knot_zone_sign_use_key(key, &r->cds)) {
		ret = knot_sign_rrset(&r->rrsig, &r->cds, key->key, key->ctx, kctx, NULL, NULL);
	}
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
