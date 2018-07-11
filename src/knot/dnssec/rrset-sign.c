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

#include <assert.h>

#include "contrib/wire_ctx.h"
#include "libdnssec/error.h"
#include "knot/dnssec/rrset-sign.h"
#include "libknot/libknot.h"

#define RRSIG_RDATA_SIGNER_OFFSET 18

#define RRSIG_INCEPT_IN_PAST (90 * 60)

/*- Creating of RRSIGs -------------------------------------------------------*/

/*!
 * \brief Get size of RRSIG RDATA for a given key without signature.
 */
static size_t rrsig_rdata_header_size(const dnssec_key_t *key)
{
	if (!key) {
		return 0;
	}

	size_t size;

	// static part

	size = sizeof(uint16_t)		// type covered
	     + sizeof(uint8_t)		// algorithm
	     + sizeof(uint8_t)		// labels
	     + sizeof(uint32_t)		// original TTL
	     + sizeof(uint32_t)		// signature expiration
	     + sizeof(uint32_t)		// signature inception
	     + sizeof(uint16_t);	// key tag (footprint)

	assert(size == RRSIG_RDATA_SIGNER_OFFSET);

	// variable part

	size += knot_dname_size(dnssec_key_get_dname(key));

	return size;
}

/*!
 * \brief Write RRSIG RDATA except signature.
 *
 * \note This can be also used for SIG(0) if proper parameters are supplied.
 *
 * \param rdata_len     Length of RDATA.
 * \param rdata         Pointer to RDATA.
 * \param key           Key used for signing.
 * \param covered_type  Type of the covered RR.
 * \param owner_labels  Number of labels covered by the signature.
 * \param sig_incepted  Timestamp of signature inception.
 * \param sig_expires   Timestamp of signature expiration.
 */
static int rrsig_write_rdata(uint8_t *rdata, size_t rdata_len,
                             const dnssec_key_t *key,
                             uint16_t covered_type, uint8_t owner_labels,
                             uint32_t owner_ttl,  uint32_t sig_incepted,
                             uint32_t sig_expires)
{
	if (!rdata || !key || sig_incepted >= sig_expires) {
		return KNOT_EINVAL;
	}

	uint8_t algorithm = dnssec_key_get_algorithm(key);
	uint16_t keytag = dnssec_key_get_keytag(key);
	const uint8_t *signer = dnssec_key_get_dname(key);
	assert(signer);

	wire_ctx_t wire = wire_ctx_init(rdata, rdata_len);

	wire_ctx_write_u16(&wire, covered_type);	// type covered
	wire_ctx_write_u8(&wire, algorithm);		// algorithm
	wire_ctx_write_u8(&wire, owner_labels);	// labels
	wire_ctx_write_u32(&wire, owner_ttl);		// original TTL
	wire_ctx_write_u32(&wire, sig_expires);	// signature expiration
	wire_ctx_write_u32(&wire, sig_incepted);	// signature inception
	wire_ctx_write_u16(&wire, keytag);		// key fingerprint
	assert(wire_ctx_offset(&wire) == RRSIG_RDATA_SIGNER_OFFSET);
	wire_ctx_write(&wire, signer, knot_dname_size(signer));	// signer

	return wire.error;
}

/*- Computation of signatures ------------------------------------------------*/

/*!
 * \brief Add RRSIG RDATA without signature to signing context.
 *
 * Requires signer name in RDATA in canonical form.
 *
 * \param ctx   Signing context.
 * \param rdata Pointer to RRSIG RDATA.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_self(dnssec_sign_ctx_t *ctx, const uint8_t *rdata)
{
	assert(ctx);
	assert(rdata);

	int result;

	// static header

	dnssec_binary_t header = { 0 };
	header.data = (uint8_t *)rdata;
	header.size = RRSIG_RDATA_SIGNER_OFFSET;

	result = dnssec_sign_add(ctx, &header);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// signer name

	const uint8_t *rdata_signer = rdata + RRSIG_RDATA_SIGNER_OFFSET;
	dnssec_binary_t signer = { 0 };
	signer.data = knot_dname_copy(rdata_signer, NULL);
	signer.size = knot_dname_size(signer.data);

	result = dnssec_sign_add(ctx, &signer);
	free(signer.data);

	return result;
}

/*!
 * \brief Add covered RRs to signing context.
 *
 * Requires all DNAMEs in canonical form and all RRs ordered canonically.
 *
 * \param ctx      Signing context.
 * \param covered  Covered RRs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_records(dnssec_sign_ctx_t *ctx, const knot_rrset_t *covered)
{
	// huge block of rrsets can be optionally created
	uint8_t *rrwf = malloc(KNOT_WIRE_MAX_PKTSIZE);
	if (!rrwf) {
		return KNOT_ENOMEM;
	}

	int written = knot_rrset_to_wire(covered, rrwf, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (written < 0) {
		free(rrwf);
		return written;
	}

	dnssec_binary_t rrset_wire = { 0 };
	rrset_wire.size = written;
	rrset_wire.data = rrwf;
	int result = dnssec_sign_add(ctx, &rrset_wire);
	free(rrwf);

	return result;
}

int knot_sign_ctx_add_data(dnssec_sign_ctx_t *ctx,
                           const uint8_t *rrsig_rdata,
                           const knot_rrset_t *covered)
{
	if (!ctx || !rrsig_rdata || knot_rrset_empty(covered)) {
		return KNOT_EINVAL;
	}

	int result = sign_ctx_add_self(ctx, rrsig_rdata);
	if (result != KNOT_EOK) {
		return result;
	}

	return sign_ctx_add_records(ctx, covered);
}

/*!
 * \brief Create RRSIG RDATA.
 *
 * \param[in]  rrsigs        RR set with RRSIGS.
 * \param[in]  ctx           DNSSEC signing context.
 * \param[in]  covered       RR covered by the signature.
 * \param[in]  key           Key used for signing.
 * \param[in]  sig_incepted  Timestamp of signature inception.
 * \param[in]  sig_expires   Timestamp of signature expiration.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int rrsigs_create_rdata(knot_rrset_t *rrsigs, dnssec_sign_ctx_t *ctx,
                               const knot_rrset_t *covered,
                               const dnssec_key_t *key,
                               uint32_t sig_incepted, uint32_t sig_expires,
                               knot_mm_t *mm)
{
	assert(rrsigs);
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(covered));
	assert(key);

	size_t header_size = rrsig_rdata_header_size(key);
	assert(header_size != 0);

	uint8_t owner_labels = knot_dname_labels(covered->owner, NULL);
	if (knot_dname_is_wildcard(covered->owner)) {
		owner_labels -= 1;
	}

	uint8_t header[header_size];
	int res = rrsig_write_rdata(header, header_size,
	                            key, covered->type, owner_labels,
	                            covered->ttl, sig_incepted, sig_expires);
	assert(res == KNOT_EOK);

	res = dnssec_sign_init(ctx);
	if (res != KNOT_EOK) {
		return res;
	}

	res = knot_sign_ctx_add_data(ctx, header, covered);
	if (res != KNOT_EOK) {
		return res;
	}

	dnssec_binary_t signature = { 0 };
	res = dnssec_sign_write(ctx, &signature);
	if (res != DNSSEC_EOK) {
		return res;
	}
	assert(signature.size > 0);

	size_t rrsig_size = header_size + signature.size;
	uint8_t rrsig[rrsig_size];
	memcpy(rrsig, header, header_size);
	memcpy(rrsig + header_size, signature.data, signature.size);

	dnssec_binary_free(&signature);

	return knot_rrset_add_rdata(rrsigs, rrsig, rrsig_size, mm);
}

int knot_sign_rrset(knot_rrset_t *rrsigs, const knot_rrset_t *covered,
                    const dnssec_key_t *key, dnssec_sign_ctx_t *sign_ctx,
                    const kdnssec_ctx_t *dnssec_ctx, knot_mm_t *mm)
{
	if (knot_rrset_empty(covered) || !key || !sign_ctx || !dnssec_ctx ||
	    rrsigs->type != KNOT_RRTYPE_RRSIG ||
	    !knot_dname_is_equal(rrsigs->owner, covered->owner)
	) {
		return KNOT_EINVAL;
	}

	uint32_t sig_incept = dnssec_ctx->now - RRSIG_INCEPT_IN_PAST;
	uint32_t sig_expire = dnssec_ctx->now + dnssec_ctx->policy->rrsig_lifetime;

	return rrsigs_create_rdata(rrsigs, sign_ctx, covered, key, sig_incept,
	                           sig_expire, mm);
}

int knot_synth_rrsig(uint16_t type, const knot_rdataset_t *rrsig_rrs,
                     knot_rdataset_t *out_sig, knot_mm_t *mm)
{
	if (rrsig_rrs == NULL) {
		return KNOT_ENOENT;
	}

	if (out_sig == NULL || out_sig->count > 0) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *rr_to_copy = rrsig_rrs->rdata;
	for (int i = 0; i < rrsig_rrs->count; ++i) {
		if (type == knot_rrsig_type_covered(rr_to_copy)) {
			int ret = knot_rdataset_add(out_sig, rr_to_copy, mm);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(out_sig, mm);
				return ret;
			}
		}
		rr_to_copy = knot_rdataset_next(rr_to_copy);
	}

	return out_sig->count > 0 ? KNOT_EOK : KNOT_ENOENT;
}

/*- Verification of signatures -----------------------------------------------*/

/*!
 * \brief Check if the signature is expired.
 *
 * \param rrsig   RRSIG rdata.
 * \param policy  DNSSEC policy.
 *
 * \return Signature is expired or should be replaced soon.
 */
static bool is_expired_signature(const knot_rdata_t *rrsig, uint32_t now,
                                 uint32_t refresh_before)
{
	assert(rrsig);

	uint32_t expire_at = knot_rrsig_sig_expiration(rrsig);
	uint32_t expire_in = expire_at > now ? expire_at - now : 0;

	return expire_in <= refresh_before;
}

int knot_check_signature(const knot_rrset_t *covered,
                    const knot_rrset_t *rrsigs, size_t pos,
                    const dnssec_key_t *key,
                    dnssec_sign_ctx_t *sign_ctx,
                    const kdnssec_ctx_t *dnssec_ctx)
{
	if (knot_rrset_empty(covered) || knot_rrset_empty(rrsigs) || !key ||
	    !sign_ctx || !dnssec_ctx) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *rrsig = knot_rdataset_at(&rrsigs->rrs, pos);
	assert(rrsig);

	if (is_expired_signature(rrsig, dnssec_ctx->now,
	                         dnssec_ctx->policy->rrsig_refresh_before)) {
		return DNSSEC_INVALID_SIGNATURE;
	}

	// identify fields in the signature being validated

	dnssec_binary_t signature = {
		.size = knot_rrsig_signature_len(rrsig),
		.data = (uint8_t *)knot_rrsig_signature(rrsig)
	};
	if (signature.data == NULL) {
		return KNOT_EINVAL;
	}

	// perform the validation

	int result = dnssec_sign_init(sign_ctx);
	if (result != KNOT_EOK) {
		return result;
	}

	result = knot_sign_ctx_add_data(sign_ctx, rrsig->data, covered);
	if (result != KNOT_EOK) {
		return result;
	}

	return dnssec_sign_verify(sign_ctx, &signature);
}
