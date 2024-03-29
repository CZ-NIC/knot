/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief EDNS option names.
 */
extern const knot_lookup_t knot_edns_opt_names[];

/*! @} */
