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
 * \file algorithm.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief DNSSEC key algorithm utilities.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_ALGORITHM_H_
#define _KNOT_DNSSEC_ALGORITHM_H_

#include <stdbool.h>
#include <stdint.h>

/*!
 * \brief DNSSEC algorithm numbers.
 *
 * http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
 */
typedef enum {
	KNOT_DNSSEC_ALG_RSAMD5             =  1,
	KNOT_DNSSEC_ALG_DH                 =  2,
	KNOT_DNSSEC_ALG_DSA                =  3,

	KNOT_DNSSEC_ALG_RSASHA1            =  5,
	KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1     =  6,
	KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1 =  7,
	KNOT_DNSSEC_ALG_RSASHA256          =  8,

	KNOT_DNSSEC_ALG_RSASHA512          = 10,

	KNOT_DNSSEC_ALG_ECC_GOST           = 12,
	KNOT_DNSSEC_ALG_ECDSAP256SHA256    = 13,
	KNOT_DNSSEC_ALG_ECDSAP384SHA384    = 14
} knot_dnssec_algorithm_t;

/*!
 * \brief NSEC3 hash algorithm numbers.
 */
typedef enum {
	KNOT_NSEC3_ALGORITHM_SHA1 = 1
} knot_nsec3_hash_algorithm_t;

/*!
 * \brief Check if algorithm is supported for zone signing.
 *
 * \param algorithm      Algorithm identification.
 * \param nsec3_enabled  NSEC3 enabled for signed zone.
 *
 * \return Given algorithm is allowed for zone signing.
 */
bool knot_dnssec_algorithm_is_zonesign(uint8_t algorithm, bool nsec3_enabled);

#endif // _KNOT_DNSSEC_ALGORITHM_H_

/*! @} */
