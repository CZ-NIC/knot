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
 * \file random.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Interface for pseudo-random generator from OpenSSL.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_RANDOM_H
#define _KNOT_DNSSEC_RANDOM_H

#include <assert.h>
#include <openssl/rand.h>
#include <stdint.h>
#include "common/errcode.h"

/*!
 * \brief Fill a buffer with random data.
 *
 * \note Always succeeds, but might not provide cryptographically strong random.
 *
 * \param dest  Pointer to output buffer.
 * \param size  Size of output buffer.
 *
 * \retval 1  Cryptographically strong random data were written.
 * \retval 0  Cryptographically weak random data were written.
 */
static inline int knot_random_buffer(void *dest, size_t size)
{
	assert(dest);

	int result = RAND_pseudo_bytes(dest, (int)size);
	assert(result != -1);

	return result;
}

/*!
 * \brief Declare function knot_random_<type>().
 */
#define _knot_register_random_type(type) \
	static inline type knot_random_##type(void) { \
		type buffer; \
		knot_random_buffer(&buffer, sizeof(buffer)); \
		return buffer; \
	}

_knot_register_random_type(int);
_knot_register_random_type(uint16_t);
_knot_register_random_type(uint32_t);

#endif // _KNOT_DNSSEC_RANDOM_H

/*! @} */
