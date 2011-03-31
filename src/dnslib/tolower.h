/*!
 * \file tolower.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Table for converting ASCII characters to lowercase.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_TOLOWER_H_
#define _KNOT_DNSLIB_TOLOWER_H_

#include <stdint.h>

/*! \brief Size of the character conversion table. */
#define KNOT_CHAR_TABLE_SIZE 256

enum {
	/*! \brief Size of the character conversion table. */
	CHAR_TABLE_SIZE = KNOT_CHAR_TABLE_SIZE
};

/*! \brief Character table mapping uppercase letters to lowercase. */
const uint8_t char_table[CHAR_TABLE_SIZE];

/*!
 * \brief Converts ASCII character to lowercase.
 * 
 * \param c ASCII character code.
 *
 * \return \a c converted to lowercase (or \a c if not applicable).
 */
static inline uint8_t dnslib_tolower(uint8_t c) {
#if KNOT_CHAR_TABLE_SIZE < 256
	assert(c < CHAR_TABLE_SIZE);
#endif
	return char_table[c];
}

#endif /* _KNOT_DNSLIB_TOLOWER_H_ */
