/*!
 * \file tolower.h
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Table for converting ASCII characters to lowercase.
 *
 * \addtogroup dnslib
 * @{
 */

#include <stdint.h>

#ifndef _KNOT_DNSLIB_TOLOWER_H_
#define _KNOT_DNSLIB_TOLOWER_H_

#define KNOT_CHAR_TABLE_SIZE 256

enum {
	CHAR_TABLE_SIZE = KNOT_CHAR_TABLE_SIZE
};

const uint8_t char_table[CHAR_TABLE_SIZE];

static inline uint8_t dnslib_tolower(uint8_t c) {
#if KNOT_CHAR_TABLE_SIZE < 256
	assert(c < CHAR_TABLE_SIZE);
#endif
	return char_table[c];
}

#endif /* _KNOT_DNSLIB_TOLOWER_H_ */
