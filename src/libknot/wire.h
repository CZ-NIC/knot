/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Wire integer operations.
 *
 * \addtogroup wire
 * @{
 */

#pragma once

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "libknot/endian.h"

/*!
 * \brief Reads 2 bytes from the wireformat data.
 *
 * \param pos Data to read the 2 bytes from.
 *
 * \return The 2 bytes read, in host byte order.
 */
inline static uint16_t knot_wire_read_u16(const uint8_t *pos)
{
	assert(pos);
	uint16_t result;
	memcpy(&result, pos, sizeof(result));
	return be16toh(result);
}

/*!
 * \brief Reads 4 bytes from the wireformat data.
 *
 * \param pos Data to read the 4 bytes from.
 *
 * \return The 4 bytes read, in host byte order.
 */
inline static uint32_t knot_wire_read_u32(const uint8_t *pos)
{
	assert(pos);
	uint32_t result;
	memcpy(&result, pos, sizeof(result));
	return be32toh(result);
}

/*!
 * \brief Reads 6 bytes from the wireformat data.
 *
 * \param pos Data to read the 6 bytes from.
 *
 * \return The 6 bytes read, in host byte order.
 */
inline static uint64_t knot_wire_read_u48(const uint8_t *pos)
{
	assert(pos);
	uint64_t input = 0;
	memcpy((uint8_t *)&input + 1, pos, 6);
	return be64toh(input) >> 8;
}

/*!
 * \brief Read 8 bytes from the wireformat data.
 *
 * \param pos Data to read the 8 bytes from.
 *
 * \return The 8 bytes read, in host byte order.
 */
inline static uint64_t knot_wire_read_u64(const uint8_t *pos)
{
	assert(pos);
	uint64_t result;
	memcpy(&result, pos, sizeof(result));
	return be64toh(result);
}

/*!
 * \brief Writes 2 bytes in wireformat.
 *
 * The data are stored in network byte order (big endian).
 *
 * \param pos Position where to put the 2 bytes.
 * \param data Data to put.
 */
inline static void knot_wire_write_u16(uint8_t *pos, uint16_t data)
{
	assert(pos);
	uint16_t beval = htobe16(data);
	memcpy(pos, &beval, sizeof(beval));
}

/*!
 * \brief Writes 4 bytes in wireformat.
 *
 * The data are stored in network byte order (big endian).
 *
 * \param pos Position where to put the 4 bytes.
 * \param data Data to put.
 */
inline static void knot_wire_write_u32(uint8_t *pos, uint32_t data)
{
	assert(pos);
	uint32_t beval = htobe32(data);
	memcpy(pos, &beval, sizeof(beval));
}

/*!
 * \brief Writes 6 bytes in wireformat.
 *
 * The data are stored in network byte order (big endian).
 *
 * \param pos Position where to put the 4 bytes.
 * \param data Data to put.
 */
inline static void knot_wire_write_u48(uint8_t *pos, uint64_t data)
{
	assert(pos);
	uint64_t swapped = htobe64(data << 8);
	memcpy(pos, (uint8_t *)&swapped + 1, 6);
}

/*!
 * \brief Writes 8 bytes in wireformat.
 *
 * The data are stored in network byte order (big endian).
 *
 * \param pos Position where to put the 8 bytes.
 * \param data Data to put.
 */
inline static void knot_wire_write_u64(uint8_t *pos, uint64_t data)
{
	assert(pos);
	uint64_t beval = htobe64(data);
	memcpy(pos, &beval, sizeof(beval));
}

/*! @} */
