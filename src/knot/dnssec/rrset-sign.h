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
/*!
 * \file rrset-sign.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Interface for DNSSEC signing of RR sets.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "dnssec/key.h"
#include "dnssec/sign.h"
#include "knot/dnssec/context.h"
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
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_sign_rrset(knot_rrset_t *rrsigs,
                    const knot_rrset_t *covered,
                    const dnssec_key_t *key,
                    dnssec_sign_ctx_t *sign_ctx,
                    const kdnssec_ctx_t *dnssec_ctx,
                    knot_mm_t *mm);

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

/*! @} */
