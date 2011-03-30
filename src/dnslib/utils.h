/*!
 * \file utils.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Various utilities.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_UTILS_H_
#define _KNOT_DNSLIB_UTILS_H_

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "common/print.h"

/*
 * Printing functions
 */

inline void dnslib_hex_print(const char *data, int length)
{
	hex_print(data, length);
}

/*!
 * \brief A general purpose lookup table.
 *
 * \note Taken from NSD.
 */
struct dnslib_lookup_table {
	int id;
	const char *name;
};

typedef struct dnslib_lookup_table dnslib_lookup_table_t;

/*!
 * \brief Looks up the given name in the lookup table.
 *
 * \param table Lookup table.
 * \param name Name to look up.
 *
 * \return Item in the lookup table with the given name or NULL if no such is
 *         present.
 */
dnslib_lookup_table_t *dnslib_lookup_by_name(dnslib_lookup_table_t *table,
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
dnslib_lookup_table_t *dnslib_lookup_by_id(dnslib_lookup_table_t *table,
                                           int id);

/*!
 * \brief Strlcpy - safe string copy function, based on FreeBSD implementation.
 *
 * http://www.openbsd.org/cgi-bin/cvsweb/src/lib/libc/string/
 *
 * \param dst Destination string.
 * \param src Source string.
 * \param siz How many characters to copy - 1.
 *
 * \return strlen(src), if retval >= siz, truncation occurred.
 */
size_t dnslib_strlcpy(char *dst, const char *src, size_t size);

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
static inline uint16_t dnslib_wire_read_u16(const uint8_t *pos)
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
static inline uint16_t dnslib_wire_read_u32(const uint8_t *pos)
{
	return (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
}

/*!
 * \brief Writes 2 bytes in wireformat.
 *
 * The endian of the data is inverted.
 *
 * \param pos Position where to put the 2 bytes.
 * \param data Data to put.
 */
static inline void dnslib_wire_write_u16(uint8_t *pos, uint16_t data)
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
static inline void dnslib_wire_write_u32(uint8_t *pos, uint32_t data)
{
	pos[0] = (uint8_t)((data >> 24) & 0xff);
	pos[1] = (uint8_t)((data >> 16) & 0xff);
	pos[2] = (uint8_t)((data >> 8) & 0xff);
	pos[3] = (uint8_t)(data & 0xff);
}

#endif /* _KNOT_DNSLIB_UTILS_H_ */

/*! @} */

