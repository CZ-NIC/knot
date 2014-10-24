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

#include "libknot/util/tolower.h"
#include "common/macros.h"

_public_
const uint8_t knot_char_table[KNOT_CHAR_TABLE_SIZE] = {
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
	'\x14',
	'\x15',
	'\x16',
	'\x17',
	'\x18',
	'\x19',
	'\x1A',
	'\x1B',
	'\x1C',
	'\x1D',
	'\x1E',
	'\x1F',
	'\x20',
	'\x21', /* ! */
	'\x22', /* " */
	'\x23', /* # */
	'\x24', /* $ */
	'\x25', /* % */
	'\x26', /* & */
	'\x27', /* ' */
	'\x28', /* ( */
	'\x29', /* ) */
	'\x2A', /* * */
	'\x2B', /* + */
	'\x2C', /* , */
	'\x2D', /* - */
	'\x2E', /* . */
	'\x2F', /* / */
	'\x30', /* 0 */
	'\x31', /* 1 */
	'\x32', /* 2 */
	'\x33', /* 3 */
	'\x34', /* 4 */
	'\x35', /* 5 */
	'\x36', /* 6 */
	'\x37', /* 7 */
	'\x38', /* 8 */
	'\x39', /* 9 */
	'\x3A', /* : */
	'\x3B', /* ; */
	'\x3C', /* < */
	'\x3D', /* = */
	'\x3E', /* > */
	'\x3F', /* ? */
	'\x40', /* @ */
	'\x61', /* A */
	'\x62', /* B */
	'\x63', /* C */
	'\x64', /* D */
	'\x65', /* E */
	'\x66', /* F */
	'\x67', /* G */
	'\x68', /* H */
	'\x69', /* I */
	'\x6A', /* J */
	'\x6B', /* K */
	'\x6C', /* L */
	'\x6D', /* M */
	'\x6E', /* N */
	'\x6F', /* O */
	'\x70', /* P */
	'\x71', /* Q */
	'\x72', /* R */
	'\x73', /* S */
	'\x74', /* T */
	'\x75', /* U */
	'\x76', /* V */
	'\x77', /* W */
	'\x78', /* X */
	'\x79', /* Y */
	'\x7A', /* Z */
	'\x5B', /* [ */
	'\x5C', /* \ */
	'\x5D', /* ] */
	'\x5E', /* ^ */
	'\x5F', /* _ */
	'\x60', /* ` */
	'\x61', /* a */
	'\x62', /* b */
	'\x63', /* c */
	'\x64', /* d */
	'\x65', /* e */
	'\x66', /* f */
	'\x67', /* g */
	'\x68', /* h */
	'\x69', /* i */
	'\x6A', /* j */
	'\x6B', /* k */
	'\x6C', /* l */
	'\x6D', /* m */
	'\x6E', /* n */
	'\x6F', /* o */
	'\x70', /* p */
	'\x71', /* q */
	'\x72', /* r */
	'\x73', /* s */
	'\x74', /* t */
	'\x75', /* u */
	'\x76', /* v */
	'\x77', /* w */
	'\x78', /* x */
	'\x79', /* y */
	'\x7A', /* z */
	'\x7B', /* { */
	'\x7C', /* | */
	'\x7D', /* } */
	'\x7E', /* ~ */
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
