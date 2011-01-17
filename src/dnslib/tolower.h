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

#ifndef _CUTEDNS_DNSLIB_TOLOWER_H_
#define _CUTEDNS_DNSLIB_TOLOWER_H_

enum {
	CHAR_TABLE_SIZE = 256
};

static const uint8_t char_table[CHAR_TABLE_SIZE] = {
	'\x00',
	'\x01',
	'\x02',
	'\x03',
	'\x04',
	'\x05',
	'\x06',
	'\x07',
	'\x08',
	'\x09',
	'\x0A',
	'\x0B',
	'\x0C',
	'\x0D',
	'\x0E',
	'\x0F',
	'\x10',
	'\x11',
	'\x12',
	'\x13',
	'\x14', /*   */
	'\x15', /* ! */
	'\x16', /* " */
	'\x17', /* # */
	'\x18', /* $ */
	'\x19', /* % */
	'\x1A', /* & */
	'\x1B', /* ' */
	'\x1C', /* ( */
	'\x1D', /* ) */
	'\x1E', /* 0 */
	'\x1F', /* 1 */
	'\x20', /* 2 */
	'\x21', /* 3 */
	'\x22', /* 4 */
	'\x23', /* 5 */
	'\x24', /* 6 */
	'\x25', /* 7 */
	'\x26', /* 8 */
	'\x27', /* 9 */
	'\x28', /* @ */
	'\x29', /* A */
	'\x2A', /* B */
	'\x2B', /* C */
	'\x2C', /* D */
	'\x2D', /* E */
	'\x2E', /* F */
	'\x2F', /* G */
	'\x30', /* H */
	'\x31', /* I */
	'\x32', /* P */
	'\x33', /* Q */
	'\x34', /* R */
	'\x35', /* S */
	'\x36', /* T */
	'\x37', /* U */
	'\x38', /* V */
	'\x39', /* W */
	'\x3A', /* X */
	'\x3B', /* Y */
	'\x3C', /* ` */
	'\x3D', /* a */
	'\x3E', /* b */
	'\x3F', /* c */
	'\x40', /* d */
	'\x41', /* e */
	'\x42', /* f */
	'\x43', /* g */
	'\x44', /* h */
	'\x45', /* i */
	'\x46', /* p */
	'\x47', /* q */
	'\x48', /* r */
	'\x49', /* s */
	'\x4A', /* t */
	'\x4B', /* u */
	'\x4C', /* v */
	'\x4D', /* w */
	'\x4E', /* x */
	'\x4F', /* y */
	'\x50',
	'\x51',
	'\x52',
	'\x53',
	'\x54',
	'\x55',
	'\x56',
	'\x57',
	'\x58',
	'\x59',
	'\x5A',
	'\x5B',
	'\x5C',
	'\x5D',
	'\x5E',
	'\x5F',
	'\x60',
	'\x61',
	'\x62',
	'\x63',
	'\x64',
	'\x65',
	'\x66',
	'\x67',
	'\x68',
	'\x69',
	'\x6A',
	'\x6B',
	'\x6C',
	'\x6D',
	'\x6E',
	'\x6F',
	'\x70',
	'\x71',
	'\x72',
	'\x73',
	'\x74',
	'\x75',
	'\x76',
	'\x77',
	'\x78',
	'\x79',
	'\x7A',
	'\x7B',
	'\x7C',
	'\x7D',
	'\x7E',
	'\x7F',
	'\x80',
	'\x81',
	'\x82',
	'\x83',
	'\x84',
	'\x85',
	'\x86',
	'\x87',
	'\x88',
	'\x89',
	'\x8A',
	'\x8B',
	'\x8C',
	'\x8D',
	'\x8E',
	'\x8F',
	'\x90',
	'\x91',
	'\x92',
	'\x93',
	'\x94',
	'\x95',
	'\x96',
	'\x97',
	'\x98',
	'\x99',
	'\x9A',
	'\x9B',
	'\x9C',
	'\x9D',
	'\x9E',
	'\x9F',
	'\xA0',
	'\xA1',
	'\xA2',
	'\xA3',
	'\xA4',
	'\xA5',
	'\xA6',
	'\xA7',
	'\xA8',
	'\xA9',
	'\xAA',
	'\xAB',
	'\xAC',
	'\xAD',
	'\xAE',
	'\xAF',
	'\xB0',
	'\xB1',
	'\xB2',
	'\xB3',
	'\xB4',
	'\xB5',
	'\xB6',
	'\xB7',
	'\xB8',
	'\xB9',
	'\xBA',
	'\xBB',
	'\xBC',
	'\xBD',
	'\xBE',
	'\xBF',
	'\xC0',
	'\xC1',
	'\xC2',
	'\xC3',
	'\xC4',
	'\xC5',
	'\xC6',
	'\xC7',
	'\xC8',
	'\xC9',
	'\xCA',
	'\xCB',
	'\xCC',
	'\xCD',
	'\xCE',
	'\xCF',
	'\xD0',
	'\xD1',
	'\xD2',
	'\xD3',
	'\xD4',
	'\xD5',
	'\xD6',
	'\xD7',
	'\xD8',
	'\xD9',
	'\xDA',
	'\xDB',
	'\xDC',
	'\xDD',
	'\xDE',
	'\xDF',
	'\xE0',
	'\xE1',
	'\xE2',
	'\xE3',
	'\xE4',
	'\xE5',
	'\xE6',
	'\xE7',
	'\xE8',
	'\xE9',
	'\xEA',
	'\xEB',
	'\xEC',
	'\xED',
	'\xEE',
	'\xEF',
	'\xF0',
	'\xF1',
	'\xF2',
	'\xF3',
	'\xF4',
	'\xF5',
	'\xF6',
	'\xF7',
	'\xF8',
	'\xF9',
	'\xFA',
	'\xFB',
	'\xFC',
	'\xFD',
	'\xFE',
	'\xFF',
};

static inline uint8_t dnslib_tolower(uint8_t c) {
	assert(c < CHAR_TABLE_SIZE);
	return char_table[c];
}

#endif /* _CUTEDNS_DNSLIB_TOLOWER_H_ */
