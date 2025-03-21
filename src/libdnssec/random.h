/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup random
 *
 * \brief Pseudo-random number generating API.
 *
 * The module provides generating of pseudo-random numbers and buffers.
 *
 * @{
 */

#pragma once

#include <stdint.h>
#include <libdnssec/binary.h>

/*!
 * Fill a buffer with pseudo-random data.
 *
 * \param data  Pointer to the output buffer.
 * \param size  Size of the output buffer.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_random_buffer(uint8_t *data, size_t size);

/*!
 * Fill a binary structure with random data.
 *
 * \param data  Preallocated binary structure to be filled.
 *
 * \return Error code, DNSSEC_EOK if successful.
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
dnssec_register_random_type(uint64_t);
/*! \endcond */

/*! @} */
