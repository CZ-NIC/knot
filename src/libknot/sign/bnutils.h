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
 * \file bnutils.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Conversion between Base64 and OpenSSL BIGNUM formats.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_SIGN_BNUTILS_H_
#define _KNOT_SIGN_BNUTILS_H_

#include <openssl/bn.h>

/*!
 * \brief Convert Base64 encoded number into OpenSSL BIGNUM format.
 *
 * \param input  Base64 encoded input number
 * \return Input number represented in OpenSSL BIGNUM format.
 */
BIGNUM *knot_b64_to_bignum(const char *input);

#endif // _KNOT_SIGN_BNUTILS_H_

/*! @} */
