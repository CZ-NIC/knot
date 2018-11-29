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

#pragma once

#include "libdnssec/key.h"
#include "libdnssec/sign.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/rrset.h"

/*!
 * \brief Create RRSIG RR for given RR set.
 *
 * \param rrsigs      RR set with RRSIGs into which the result will be added.
 * \param covered     RR set to create a new signature for.
 * \param key         Signing key.
 * \param sign_ctx    Signing context.
 * \param dnssec_ctx  DNSSEC context.
 * \param mm          Memory context.
 * \param expires     Out: When will the new RRSIG expire.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_sign_rrset(knot_rrset_t *rrsigs,
                    const knot_rrset_t *covered,
                    const dnssec_key_t *key,
                    dnssec_sign_ctx_t *sign_ctx,
                    const kdnssec_ctx_t *dnssec_ctx,
                    knot_mm_t *mm,
                    knot_time_t *expires);

/*!
 * \brief Create RRSIG RR for given RR set, choose which key to use.
 *
 * \param rrsigs      RR set with RRSIGs into which the result will be added.
 * \param rrset       RR set to create a new signature for.
 * \param sign_ctx    Zone signing context-
 * \param mm          Memory context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_sign_rrset2(knot_rrset_t *rrsigs,
                     const knot_rrset_t *rrset,
                     zone_sign_ctx_t *sign_ctx,
                     knot_mm_t *mm);

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
int knot_sign_ctx_add_data(dnssec_sign_ctx_t *ctx,
                           const uint8_t *rrsig_rdata,
                           const knot_rrset_t *covered);

/*!
 * \brief Creates new RRS using \a rrsig_rrs as a source. Only those RRs that
 *        cover given \a type are copied into \a out_sig
 *
 * \param type       Covered type.
 * \param rrsig_rrs  Source RRS.
 * \param out_sig    Output RRS.
 * \param mm         Memory context.
 *
 * \retval KNOT_EOK if some RRSIG was found.
 * \retval KNOT_EINVAL if no RRSIGs were found.
 * \retval Error code other than EINVAL on error.
 */
int knot_synth_rrsig(uint16_t type, const knot_rdataset_t *rrsig_rrs,
                     knot_rdataset_t *out_sig, knot_mm_t *mm);

/*!
 * \brief Check if RRSIG signature is valid.
 *
 * \param covered     RRs covered by the signature.
 * \param rrsigs      RR set with RRSIGs.
 * \param pos         Number of RRSIG RR in 'rrsigs' to be validated.
 * \param key         Signing key.
 * \param sign_ctx    Signing context.
 * \param dnssec_ctx  DNSSEC context.
 *
 * \return Error code, KNOT_EOK if successful and the signature is valid.
 * \retval KNOT_DNSSEC_EINVALID_SIGNATURE  The signature is invalid.
 */
int knot_check_signature(const knot_rrset_t *covered,
                         const knot_rrset_t *rrsigs, size_t pos,
                         const dnssec_key_t *key,
                         dnssec_sign_ctx_t *sign_ctx,
                         const kdnssec_ctx_t *dnssec_ctx);
