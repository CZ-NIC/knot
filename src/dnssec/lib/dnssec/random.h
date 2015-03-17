/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * Pseudo-random number generating API.
 *
 * \defgroup random Random
 *
 * Pseudo-random number generating API.
 *
 * The module provides generating of pseudo-random numbers and buffers.
 *
 * Example:
 *
 * ~~~
 *
 * uint16_t transaction_id = dnssec_random_uint16_t();
 *
 * ~~~
 *
 * @{
 */

#pragma once

#include <stdint.h>
#include <dnssec/binary.h>

/*!
 * Fill a buffer with pseudo-random data.
 *
 * \param data  Pointer to the output buffer.
 * \param size  Size of the output buffer.
 *
 * \return Error code, DNSEC_EOK if successful.
 */
int dnssec_random_buffer(uint8_t *data, size_t size);

/*!
 * Fill a binary structure with random data.
 *
 * \param data  Preallocated binary structure to be filled.
 *
 * \return Error code, DNSEC_EOK if successful.
 */
int dnssec_random_binary(dnssec_binary_t *data);

/*!
 * Declare function dnssec_random_<type>().
 */
#define dnssec_register_random_type(type) \
	static inline type dnssec_random_##type(void) { \
		type value; \
		dnssec_random_buffer((uint8_t *)&value, sizeof(value)); \
		return value; \
	}

/*!
 * Generate pseudo-random 16-bit number.
 */
static inline uint16_t dnssec_random_uint16_t(void);

/*!
 * Generate pseudo-random 32-bit number.
 */
static inline uint32_t dnssec_random_uint32_t(void);

/*! \cond */
dnssec_register_random_type(uint16_t);
dnssec_register_random_type(uint32_t);
/*! \endcond */

/*! @} */
