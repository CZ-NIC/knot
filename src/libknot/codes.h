/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief TSIG error names.
 */
extern const knot_lookup_t knot_tsig_err_names[];

/*!
 * \brief TKEY error names.
 */
extern const knot_lookup_t knot_tkey_err_names[];

/*!
 * \brief DNSSEC algorithm names.
 */
extern const knot_lookup_t knot_dnssec_alg_names[];

/*! @} */
