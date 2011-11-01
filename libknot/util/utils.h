/*!
 * \file utils.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Various utilities.
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

#ifndef _KNOT_UTILS_H_
#define _KNOT_UTILS_H_

#include <string.h>
#include <stdint.h>
#include <stdio.h>

/*!
 * \brief A general purpose lookup table.
 *
 * \note Taken from NSD.
 */
struct knot_lookup_table {
	int id;
	const char *name;
};

typedef struct knot_lookup_table knot_lookup_table_t;

/*!
 * \brief Looks up the given name in the lookup table.
 *
 * \param table Lookup table.
 * \param name Name to look up.
 *
 * \return Item in the lookup table with the given name or NULL if no such is
 *         present.
 */
knot_lookup_table_t *knot_lookup_by_name(knot_lookup_table_t *table,
                                             const char *name);

/*!
 * \brief Looks up the given id in the lookup table.
 *
 * \param table Lookup table.
 * \param id ID to look up.
 *
 * \return Item in the lookup table with the given id or NULL if no such is
 *         present.
 */
knot_lookup_table_t *knot_lookup_by_id(knot_lookup_table_t *table,
                                           int id);

/*!
 * \brief Strlcpy - safe string copy function, based on FreeBSD implementation.
 *
 * http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/string/
 *
 * \param dst Destination string.
 * \param src Source string.
 * \param size How many characters to copy - 1.
 *
 * \return strlen(src), if retval >= siz, truncation occurred.
 */
size_t knot_strlcpy(char *dst, const char *src, size_t size);

/*
 * Writing / reading arbitrary data to / from wireformat.
 */

/*!
 * \brief Reads 2 bytes from the wireformat data.
 *
 * \param pos Data to read the 2 bytes from.
 *
 * \return The 2 bytes read, in inverse endian.
 */
static inline uint16_t knot_wire_read_u16(const uint8_t *pos)
{
	return (pos[0] << 8) | pos[1];
}

/*!
 * \brief Reads 4 bytes from the wireformat data.
 *
 * \param pos Data to read the 4 bytes from.
 *
 * \return The 4 bytes read, in inverse endian.
 */
static inline uint32_t knot_wire_read_u32(const uint8_t *pos)
{
	return (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
}

/*!
 * \brief Reads 6 bytes from the wireformat data.
 *
 * \param pos Data to read the 6 bytes from.
 *
 * \return The 6 bytes read, in inverse endian.
 */
static inline uint64_t knot_wire_read_u48(const uint8_t *pos)
{
	return ((uint64_t)(pos[0]) << 40) | ((uint64_t)(pos[1]) << 32) | (pos[2] << 24) |
	        (pos[3] << 16) | (pos[4] << 8) | pos[5];
}

/*!
 * \brief Writes 2 bytes in wireformat.
 *
 * The endian of the data is inverted.
 *
 * \param pos Position where to put the 2 bytes.
 * \param data Data to put.
 */
static inline void knot_wire_write_u16(uint8_t *pos, uint16_t data)
{
	pos[0] = (uint8_t)((data >> 8) & 0xff);
	pos[1] = (uint8_t)(data & 0xff);
}

/*!
 * \brief Writes 4 bytes in wireformat.
 *
 * The endian of the data is inverted.
 *
 * \param pos Position where to put the 4 bytes.
 * \param data Data to put.
 */
static inline void knot_wire_write_u32(uint8_t *pos, uint32_t data)
{
	pos[0] = (uint8_t)((data >> 24) & 0xff);
	pos[1] = (uint8_t)((data >> 16) & 0xff);
	pos[2] = (uint8_t)((data >> 8) & 0xff);
	pos[3] = (uint8_t)(data & 0xff);
}

/*!
 * \brief Writes 6 bytes in wireformat.
 *
 * The endian of the data is inverted.
 *
 * \param pos Position where to put the 4 bytes.
 * \param data Data to put.
 */
static inline void knot_wire_write_u48(uint8_t *pos, uint64_t data)
{
	pos[0] = (uint8_t)((data >> 40) & 0xff);
	pos[1] = (uint8_t)((data >> 32) & 0xff);
	pos[2] = (uint8_t)((data >> 24) & 0xff);
	pos[3] = (uint8_t)((data >> 16) & 0xff);
	pos[4] = (uint8_t)((data >> 8) & 0xff);
	pos[5] = (uint8_t)(data & 0xff);
}

/*!
 * \brief Linear congruential generator.
 *
 * Simple pseudorandom generator for general purpose.
 * \warning Do not use for cryptography.
 * \return Random number <0, (size_t)~0>
 */
size_t knot_quick_rand();

uint16_t knot_random_id();

/*!
 * \brief Helper function for simple locking.
 *
 * \param type Type of lock.
 * \param type Starting position of lock.
 *
 * \return Locking structure.
 */
struct flock* knot_file_lock(short type, short whence);

#endif /* _KNOT_UTILS_H_ */

/*! @} */

