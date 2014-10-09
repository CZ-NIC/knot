/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "libknot/common.h"
#include "libknot/descriptor.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/rrset-sign.h"
#include "libknot/dnssec/sign.h"
#include "libknot/errcode.h"
#include "libknot/packet/wire.h"
#include "libknot/rrset.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/packet/rrset-wire.h"

#define RRSIG_RDATA_SIGNER_OFFSET 18

/*- Creating of RRSIGs -------------------------------------------------------*/

/*!
 * \brief Get size of RRSIG RDATA for a given key.
 */
size_t knot_rrsig_rdata_size(const knot_dnssec_key_t *key)
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

	assert(key->name);
	size += knot_dname_size(key->name);
	size += knot_dnssec_sign_size(key);

	return size;
}

/*!
 * \brief Write RRSIG RDATA except signature.
 */
int knot_rrsig_write_rdata(uint8_t *rdata, const knot_dnssec_key_t *key,
                           uint16_t covered_type, uint8_t owner_labels,
                           uint32_t owner_ttl,  uint32_t sig_incepted,
                           uint32_t sig_expires)
{
	if (!rdata || !key || sig_incepted >= sig_expires) {
		return KNOT_EINVAL;
	}

	uint8_t *w = rdata;

	knot_wire_write_u16(w, covered_type);	// type covered
	w += sizeof(uint16_t);
	*w = key->algorithm;			// algorithm
	w += sizeof(uint8_t);
	*w = owner_labels;			// labels
	w += sizeof(uint8_t);
	knot_wire_write_u32(w, owner_ttl);	// original TTL
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, sig_expires);	// signature expiration
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, sig_incepted);	// signature inception
	w += sizeof(uint32_t);
	knot_wire_write_u16(w, key->keytag);	// key fingerprint
	w += sizeof(uint16_t);

	assert(w == rdata + RRSIG_RDATA_SIGNER_OFFSET);
	assert(key->name);
	memcpy(w, key->name, knot_dname_size(key->name)); // signer

	return KNOT_EOK;
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
static int sign_ctx_add_self(knot_dnssec_sign_context_t *ctx,
                             const uint8_t *rdata)
{
	assert(ctx);
	assert(rdata);

	int result;

	// add static header
	result = knot_dnssec_sign_add(ctx, rdata, RRSIG_RDATA_SIGNER_OFFSET);
	if (result != KNOT_EOK) {
		return result;
	}

	// add signer name
	const uint8_t *signer_ptr = rdata + RRSIG_RDATA_SIGNER_OFFSET;
	knot_dname_t *signer = knot_dname_copy(signer_ptr, NULL);
	knot_dname_to_lower(signer);
	result = knot_dnssec_sign_add(ctx, signer, knot_dname_size(signer));
	knot_dname_free(&signer, NULL);

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
static int sign_ctx_add_records(knot_dnssec_sign_context_t *ctx,
                                const knot_rrset_t *covered)
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

	int result = knot_dnssec_sign_add(ctx, rrwf, written);
	free(rrwf);

	return result;
}

/*!
 * \brief Add all data covered by signature into signing context.
 *
 * RFC 4034: The signature covers RRSIG RDATA field (excluding the signature)
 * and all matching RR records, which are ordered canonically.
 *
 * Requires all DNAMEs in canonical form and all RRs ordered canonically.
 *
 * \param ctx          Signing context.
 * \param rrsig_rdata  RRSIG RDATA with populated fields except signature.
 * \param covered      Covered RRs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_ctx_add_data(knot_dnssec_sign_context_t *ctx,
                             const uint8_t *rrsig_rdata,
                             const knot_rrset_t *covered)
{
	int result = sign_ctx_add_self(ctx, rrsig_rdata);
	if (result != KNOT_EOK) {
		return result;
	}

	return sign_ctx_add_records(ctx, covered);
}

/*!
 * \brief Create RRSIG RDATA (all fields except signature are filled).
 *
 * \param[in]  rrsigs        RR set with RRSIGS.
 * \param[in]  rrsigs        DNSSEC signing context.
 * \param[in]  covered       RR covered by the signature.
 * \param[in]  key           Key used for signing.
 * \param[in]  sig_incepted  Timestamp of signature inception.
 * \param[in]  sig_expires   Timestamp of signature expiration.
 *
 * \return Error code, KNOT_EOK if succesful.
 */
static int rrsigs_create_rdata(knot_rrset_t *rrsigs,
                               knot_dnssec_sign_context_t *context,
                               const knot_rrset_t *covered,
                               const knot_dnssec_key_t *key,
                               uint32_t sig_incepted, uint32_t sig_expires)
{
	assert(rrsigs);
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(covered));
	assert(key);

	size_t size = knot_rrsig_rdata_size(key);
	assert(size != 0);

	uint8_t owner_labels = knot_dname_labels(covered->owner, NULL);
	if (knot_dname_is_wildcard(covered->owner)) {
		owner_labels -= 1;
	}

	uint8_t result[size];
	const knot_rdata_t *covered_data = knot_rdataset_at(&covered->rrs, 0);
	int res = knot_rrsig_write_rdata(result, key, covered->type, owner_labels,
	                                 knot_rdata_ttl(covered_data),
	                                 sig_incepted, sig_expires);
	assert(res == KNOT_EOK);

	res = knot_dnssec_sign_new(context);
	if (res != KNOT_EOK) {
		return res;
	}

	res = sign_ctx_add_data(context, result, covered);
	if (res != KNOT_EOK) {
		return res;
	}

	const size_t signature_offset = RRSIG_RDATA_SIGNER_OFFSET + knot_dname_size(key->name);
	uint8_t *signature = result + signature_offset;
	const size_t signature_size = size - signature_offset;

	res = knot_dnssec_sign_write(context, signature, signature_size);
	if (res != KNOT_EOK) {
		return res;
	}

	return knot_rrset_add_rdata(rrsigs, result, size,
	                            knot_rdata_ttl(covered_data), NULL);
}

/*!
 * \brief Create RRSIG RR for given RR set.
 */
int knot_sign_rrset(knot_rrset_t *rrsigs, const knot_rrset_t *covered,
                    const knot_dnssec_key_t *key,
                    knot_dnssec_sign_context_t *sign_ctx,
                    const knot_dnssec_policy_t *policy)
{
	if (knot_rrset_empty(covered) || !key || !sign_ctx || !policy ||
	    rrsigs->type != KNOT_RRTYPE_RRSIG ||
	    !knot_dname_is_equal(rrsigs->owner, covered->owner)
	) {
		return KNOT_EINVAL;
	}

	uint32_t sig_incept = policy->now;
	uint32_t sig_expire = sig_incept + policy->sign_lifetime;

	return rrsigs_create_rdata(rrsigs, sign_ctx, covered, key, sig_incept,
	                           sig_expire);
}

int knot_synth_rrsig(uint16_t type, const knot_rdataset_t *rrsig_rrs,
                     knot_rdataset_t *out_sig, mm_ctx_t *mm)
{
	if (rrsig_rrs == NULL) {
		return KNOT_ENOENT;
	}

	if (out_sig == NULL || out_sig->rr_count > 0) {
		return KNOT_EINVAL;
	}

	for (int i = 0; i < rrsig_rrs->rr_count; ++i) {
		if (type == knot_rrsig_type_covered(rrsig_rrs, i)) {
			const knot_rdata_t *rr_to_copy = knot_rdataset_at(rrsig_rrs, i);
			int ret = knot_rdataset_add(out_sig, rr_to_copy, mm);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(out_sig, mm);
				return ret;
			}
		}
	}

	return out_sig->rr_count > 0 ? KNOT_EOK : KNOT_ENOENT;
}

/*- Verification of signatures -----------------------------------------------*/

/*!
 * \brief Check if the signature is expired.
 *
 * \param rrsigs  RR set with RRSIGs.
 * \param pos     Number of RR in the RR set.
 * \param policy  DNSSEC policy.
 *
 * \return Signature is expired or should be replaced soon.
 */
static bool is_expired_signature(const knot_rrset_t *rrsigs, size_t pos,
                                 const knot_dnssec_policy_t *policy)
{
	assert(!knot_rrset_empty(rrsigs));
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(policy);

	uint32_t expiration = knot_rrsig_sig_expiration(&rrsigs->rrs, pos);

	return (expiration <= policy->refresh_before);
}

/*!
 * \brief Check if RRSIG signature is valid.
 */
int knot_is_valid_signature(const knot_rrset_t *covered,
                            const knot_rrset_t *rrsigs, size_t pos,
                            const knot_dnssec_key_t *key,
                            knot_dnssec_sign_context_t *ctx,
                            const knot_dnssec_policy_t *policy)
{
	if (knot_rrset_empty(covered) ||
	    knot_rrset_empty(rrsigs) || !key || !ctx || !policy) {
		return KNOT_EINVAL;
	}

	if (is_expired_signature(rrsigs, pos, policy)) {
		return KNOT_DNSSEC_EINVALID_SIGNATURE;
	}

	// identify fields in the signature being validated

	const knot_rdata_t *rr_data = knot_rdataset_at(&rrsigs->rrs, pos);
	uint8_t *rdata = knot_rdata_data(rr_data);
	if (!rdata) {
		return KNOT_EINVAL;
	}

	uint8_t *signature = NULL;
	size_t signature_size = 0;
	knot_rrsig_signature(&rrsigs->rrs, pos, &signature, &signature_size);
	if (!signature) {
		return KNOT_EINVAL;
	}

	// perform the validation

	int result = knot_dnssec_sign_new(ctx);
	if (result != KNOT_EOK) {
		return result;
	}

	result = sign_ctx_add_data(ctx, rdata, covered);
	if (result != KNOT_EOK) {
		return result;
	}

	return knot_dnssec_sign_verify(ctx, signature, signature_size);
}

