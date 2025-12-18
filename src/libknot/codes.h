/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Some DNS-related code names.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include "libknot/lookup.h"

/*!
 * \brief DNS operation code names.
 */
extern const knot_lookup_t knot_opcode_names[];

/*!
 * \brief DNS reply code names.
 */
extern const knot_lookup_t knot_rcode_names[];

/*!
 * \brief TSIG exceptions to reply code names.
 */
extern const knot_lookup_t knot_tsig_rcode_names[];

/*!
 * \brief EDNS EDE names.
 */
extern const knot_lookup_t knot_edns_ede_names[];

/*!
 * \brief DNSSEC algorithm names.
 */
extern const knot_lookup_t knot_dnssec_alg_names[];

/*!
 * \brief Service binding (SVCB) param types.
 */
extern const knot_lookup_t knot_svcb_param_names[];

/*!
 * \brief DELEG DelegInfo types.
 */
extern const knot_lookup_t knot_deleg_info_names[];

/*!
 * \brief EDNS option names.
 */
extern const knot_lookup_t knot_edns_opt_names[];

/*! @} */
