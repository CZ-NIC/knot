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

#include <config.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "common/errcode.h"
#include "libknot/common.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/rrset-sign.h"
#include "libknot/dnssec/sign.h"
#include "libknot/rdata.h"
#include "libknot/rrset.h"

#define MAX_RR_WIREFORMAT_SIZE (64 * 1024)
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

/*- Creating of RRSIGs from covered RRs -------------------------------------*/

/*!
 * \brief Create RRSIG RDATA (all fields except signature are filled).
 *
 * \param[in]  rrsigs        RR set with RRSIGS.
 * \param[in]  covered       RR covered by the signature.
 * \param[in]  key           Key used for signing.
 * \param[in]  sig_incepted  Timestamp of signature inception.
 * \param[in]  sig_expires   Timestamp of signature expiration.
 * \param[out] rdata         Created RDATA.
 * \param[out] rdata_size    Size of created RDATA.
 *
 * \return Error code, KNOT_EOK if succesful.
 */
static int rrsigs_create_rdata(knot_rrset_t *rrsigs,
                               const knot_rrset_t *covered,
                               const knot_dnssec_key_t *key,
			       uint32_t sig_incepted, uint32_t sig_expires,
                               uint8_t **rdata, size_t *rdata_size)
{
	assert(rrsigs);
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(covered);
	assert(key);
	assert(rdata);
	assert(rdata_size);

	size_t size = knot_rrsig_rdata_size(key);
	assert(size != 0);

	uint8_t *result = knot_rrset_create_rdata(rrsigs, size);
	if (!result) {
		return KNOT_ENOMEM;
	}

	uint8_t owner_labels = knot_dname_labels(covered->owner, NULL);
	if (knot_dname_is_wildcard(covered->owner)) {
		owner_labels -= 1;
	}

	int res = knot_rrsig_write_rdata(result, key, covered->type, owner_labels,
	                                 covered->ttl, sig_incepted, sig_expires);

	assert(res == KNOT_EOK);
	UNUSED(res);

	*rdata = result;
	*rdata_size = size;

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

	const uint8_t *signer = rdata + RRSIG_RDATA_SIGNER_OFFSET;
	size_t data_size = RRSIG_RDATA_SIGNER_OFFSET + knot_dname_size(signer);

	return knot_dnssec_sign_add(ctx, rdata, data_size);
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
	uint8_t *rrwf = malloc(MAX_RR_WIREFORMAT_SIZE);
	if (!rrwf) {
		return KNOT_ENOMEM;
	}

#ifndef NDEBUG
	// cannonical ordering of RRs is cheked in debug mode
	uint8_t *prev_rrwf = malloc(MAX_RR_WIREFORMAT_SIZE);
	size_t prev_rr_size = 0;
	size_t rdata_offset = 0;
#endif

	int result = KNOT_EOK;

	uint16_t rr_count = covered->rdata_count;
	for (uint16_t i = 0; i < rr_count; i++) {
		size_t rr_size;
		result = knot_rrset_to_wire_one(covered, i, rrwf,
		                                MAX_RR_WIREFORMAT_SIZE,
		                                &rr_size, NULL);
		if (result != KNOT_EOK) {
			break;
		}

#ifndef NDEBUG
		if (i == 0) {
			rdata_offset = knot_dname_size(covered->owner);
			rdata_offset += 10; // type, class, ttl, rdlength
		} else {
			size_t cmp_size = MIN(prev_rr_size, rr_size);
			int cmp = memcmp(prev_rrwf + rdata_offset,
			                 rrwf + rdata_offset,
			                 cmp_size - rdata_offset);
			assert(cmp < 0 || (cmp == 0 && prev_rr_size <= rr_size));
		}

		memcpy(prev_rrwf, rrwf, rr_size);
		prev_rr_size = rr_size;
#endif

		result = knot_dnssec_sign_add(ctx, rrwf, rr_size);
		if (result != KNOT_EOK) {
			break;
		}
	}

#ifndef NDEBUG
	free(prev_rrwf);
#endif
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
 * \brief Create RRSIG RR for given RR set.
 */
int knot_sign_rrset(knot_rrset_t *rrsigs, const knot_rrset_t *covered,
                    const knot_dnssec_key_t *key,
                    knot_dnssec_sign_context_t *sign_ctx,
                    const knot_dnssec_policy_t *policy)
{
	if (!rrsigs || !covered || !key || !sign_ctx || !policy ||
	    rrsigs->type != KNOT_RRTYPE_RRSIG ||
	    (knot_dname_cmp(rrsigs->owner, covered->owner) != 0)
	) {
		return KNOT_EINVAL;
	}

	uint32_t sig_incept = policy->now;
	uint32_t sig_expire = sig_incept + policy->sign_lifetime;

	uint8_t *rdata = NULL;
	size_t rdata_size = 0;

	int result = rrsigs_create_rdata(rrsigs, covered, key, sig_incept,
	                                 sig_expire, &rdata, &rdata_size);
	if (result != KNOT_EOK) {
		return result;
	}

	result = knot_dnssec_sign_new(sign_ctx);
	if (result != KNOT_EOK) {
		return result;
	}

	result = sign_ctx_add_data(sign_ctx, rdata, covered);
	if (result != KNOT_EOK) {
		return result;
	}

	size_t signature_offset = RRSIG_RDATA_SIGNER_OFFSET + knot_dname_size(key->name);
	uint8_t *signature = rdata + signature_offset;
	size_t signature_size = rdata_size - signature_offset;

	return knot_dnssec_sign_write(sign_ctx, signature, signature_size);
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
	assert(rrsigs);
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(policy);

	uint32_t expiration = knot_rdata_rrsig_sig_expiration(rrsigs, pos);

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
	if (!covered || !rrsigs || !key || !ctx || !policy) {
		return KNOT_EINVAL;
	}

	if (is_expired_signature(rrsigs, pos, policy)) {
		return KNOT_DNSSEC_EINVALID_SIGNATURE;
	}

	// identify fields in the signature being validated

	uint8_t *rdata = knot_rrset_get_rdata(rrsigs, pos);
	if (!rdata) {
		return KNOT_EINVAL;
	}

	uint8_t *signature = NULL;
	size_t signature_size = 0;
	knot_rdata_rrsig_signature(rrsigs, pos, &signature, &signature_size);
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
