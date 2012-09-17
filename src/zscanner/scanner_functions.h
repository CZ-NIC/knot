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
/*!
 * \file scanner_functions.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Zone scanner auxiliary functions.
 *
 * \addtogroup zone_scanner
 * @{
 */

#ifndef _ZSCANNER__SCANNER_FUNCTIONS_H_
#define _ZSCANNER__SCANNER_FUNCTIONS_H_

#include <stdint.h>

#include "zscanner/scanner.h"


extern const uint8_t ascii_to_lower[];

extern const uint8_t digit_to_num[];

extern const uint8_t first_hex_to_num[];
extern const uint8_t second_hex_to_num[];

// Transformation arrays for Base64 encoding.
extern const uint8_t first_base64_to_num[];
extern const uint8_t second_left_base64_to_num[];
extern const uint8_t second_right_base64_to_num[];
extern const uint8_t third_left_base64_to_num[];
extern const uint8_t third_right_base64_to_num[];
extern const uint8_t fourth_base64_to_num[];

// Transformation arrays for Base32hex encoding.
extern const uint8_t first_base32hex_to_num[];
extern const uint8_t second_left_base32hex_to_num[];
extern const uint8_t second_right_base32hex_to_num[];
extern const uint8_t third_base32hex_to_num[];
extern const uint8_t fourth_left_base32hex_to_num[];
extern const uint8_t fourth_right_base32hex_to_num[];
extern const uint8_t fifth_left_base32hex_to_num[];
extern const uint8_t fifth_right_base32hex_to_num[];
extern const uint8_t sixth_base32hex_to_num[];
extern const uint8_t seventh_left_base32hex_to_num[];
extern const uint8_t seventh_right_base32hex_to_num[];
extern const uint8_t eighth_base32hex_to_num[];

int date_to_timestamp(uint8_t *buff, uint32_t *timestamp);

void wire_dname_to_text(const uint8_t *dname,
			const uint32_t dname_length,
			char *text_dname);

uint8_t loc64to8(uint64_t number);


#endif // _ZSCANNER__SCANNER_FUNCTIONS_H_

/*! @} */
