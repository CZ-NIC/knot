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

/*
 * Printing functions
 */

typedef int (*printf_t)(const char *fmt, ...);

void dnslib_hex_printf(const char *data, int length, printf_t print_handler);

inline void dnslib_hex_print(const char *data, int length)
{
	dnslib_hex_printf(data, length, &printf);
}

/*!
 * \brief A general purpose lookup table.
 */
struct dnslib_lookup_table {
	int id;
	const char *name;
};

typedef struct dnslib_lookup_table dnslib_lookup_table_t;

dnslib_lookup_table_t *dnslib_lookup_by_name(dnslib_lookup_table_t *table,
                                             const char *name);

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

static inline uint16_t dnslib_wire_read_u16(const uint8_t *pos)
{
	return (pos[0] << 8) | pos[1];
}

static inline uint16_t dnslib_wire_read_u32(const uint8_t *pos)
{
	return (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
}

static inline void dnslib_wire_write_u16(uint8_t *pos, uint16_t data)
{
	pos[0] = (uint8_t)((data >> 8) & 0xff);
	pos[1] = (uint8_t)(data & 0xff);
}

static inline void dnslib_wire_write_u32(uint8_t *pos, uint32_t data)
{
	pos[0] = (uint8_t)((data >> 24) & 0xff);
	pos[1] = (uint8_t)((data >> 16) & 0xff);
	pos[2] = (uint8_t)((data >> 8) & 0xff);
	pos[3] = (uint8_t)(data & 0xff);
}

#endif /* _KNOT_DNSLIB_UTILS_H_ */

/*! @} */

