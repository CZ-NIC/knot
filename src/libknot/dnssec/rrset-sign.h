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
 * \file rrsig-sign.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Interface for DNSSEC signing of RR sets.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_RRSET_SIGN_H_
#define _KNOT_DNSSEC_RRSET_SIGN_H_

#include <stdbool.h>
#include <stdlib.h>
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/sign.h"
#include "libknot/rrset.h"

/*!
 * \brief Create RRSIG RR for given RR set.
 *
 * \param rrsigs    RR set with RRSIGs into which the result will be added.
 * \param covered   RR set to create a new signature for.
 * \param key       Signing key.
 * \param sign_ctx  Signing context.
 * \param policy    DNSSEC policy.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_sign_rrset(knot_rrset_t *rrsigs,
                    const knot_rrset_t *covered,
                    const knot_dnssec_key_t *key,
                    knot_dnssec_sign_context_t *sign_ctx,
                    const knot_dnssec_policy_t *policy);

/*!
 * \brief Check if RRSIG signature is valid.
 *
 * \param covered  RRs covered by the signature.
 * \param rrsigs   RR set with RRSIGs.
 * \param pos      Number of RRSIG RR in 'rrsigs' to be validated.
 * \param key      Signing key.
 * \param ctx      Signing context.
 * \param policy   DNSSEC policy.
 *
 * \return Error code, KNOT_EOK if successful and the signature is valid.
 * \retval KNOT_DNSSEC_EINVALID_SIGNATURE  The signature is invalid.
 */
int knot_is_valid_signature(const knot_rrset_t *covered,
                            const knot_rrset_t *rrsigs, size_t pos,
                            const knot_dnssec_key_t *key,
                            knot_dnssec_sign_context_t *ctx,
                            const knot_dnssec_policy_t *policy);

#endif // _KNOT_DNSSEC_RRSET_SIGN_H_

/*! @} */
