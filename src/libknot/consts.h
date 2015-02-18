/*!
 * \file consts.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Contains some DNS-related constants.
 *
 * \addtogroup libknot
 * @{
 */
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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "libknot/internal/utils.h"
#include "libknot/internal/consts.h"

/*!
 * \brief DNS operation code names.
 */
extern lookup_table_t knot_opcode_names[];

/*!
 * \brief DNS reply code names.
 */
extern lookup_table_t knot_rcode_names[];

/*!
 * \brief TSIG error names.
 */
extern lookup_table_t knot_tsig_err_names[];

/*!
 * \brief TKEY error names.
 */
extern lookup_table_t knot_tkey_err_names[];

/*!
 * \brief DNSSEC algorithm names.
 */
extern lookup_table_t knot_dnssec_alg_names[];

/*! @} */
