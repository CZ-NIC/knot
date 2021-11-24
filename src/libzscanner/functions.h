/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \file
 *
 * \brief Zone scanner auxiliary functions.
 *
 * \addtogroup zone_scanner
 * @{
 */

#pragma once

#include <stdint.h>

#include "libzscanner/scanner.h"

/*! \brief Transforms digit char to number. */
extern const uint8_t digit_to_num[];

/*! \brief Transforms first hex char to the part of the total number. */
extern const uint8_t first_hex_to_num[];
/*! \brief Transforms second hex char to the part of the total number. */
extern const uint8_t second_hex_to_num[];

/*! \brief Transforms first Base64 char. */
extern const uint8_t first_base64_to_num[];
/*! \brief Transforms left part of the second Base64 char. */
extern const uint8_t second_left_base64_to_num[];
/*! \brief Transforms left part of the second Base64 char. */
extern const uint8_t second_right_base64_to_num[];
/*! \brief Transforms left part of the third Base64 char. */
extern const uint8_t third_left_base64_to_num[];
/*! \brief Transforms left part of the third Base64 char. */
extern const uint8_t third_right_base64_to_num[];
/*! \brief Transforms fourth Base64 char. */
extern const uint8_t fourth_base64_to_num[];

/*! \brief Transforms first Base32hex char. */
extern const uint8_t first_base32hex_to_num[];
/*! \brief Transforms left part of the second Base32hex char. */
extern const uint8_t second_left_base32hex_to_num[];
/*! \brief Transforms right part of the second Base32hex char. */
extern const uint8_t second_right_base32hex_to_num[];
/*! \brief Transforms third Base32hex char. */
extern const uint8_t third_base32hex_to_num[];
/*! \brief Transforms left part of the fourth Base32hex char. */
extern const uint8_t fourth_left_base32hex_to_num[];
/*! \brief Transforms right part of the fourth Base32hex char. */
extern const uint8_t fourth_right_base32hex_to_num[];
/*! \brief Transforms left part of the fifth Base32hex char. */
extern const uint8_t fifth_left_base32hex_to_num[];
/*! \brief Transforms right part of the fifth Base32hex char. */
extern const uint8_t fifth_right_base32hex_to_num[];
/*! \brief Transforms sixth Base32hex char. */
extern const uint8_t sixth_base32hex_to_num[];
/*! \brief Transforms left part of the seventh Base32hex char. */
extern const uint8_t seventh_left_base32hex_to_num[];
/*! \brief Transforms right part of the seventh Base32hex char. */
extern const uint8_t seventh_right_base32hex_to_num[];
/*! \brief Transforms eighth Base32hex char. */
extern const uint8_t eighth_base32hex_to_num[];

/*!
 * \brief Converts YYYYMMDDHHMMSS time string to unsigned 32-bit timestamp.
 *
 * \param buff		Buffer containing time string.
 * \param timestamp	Computed timestamp.
 *
 * \retval KNOT_EOK	if success.
 * \retval error_code	if error.
 */
int date_to_timestamp(uint8_t *buff, uint32_t *timestamp);

/*!
 * \brief Converts wire-format dname to text dname.
 *
 * \param data		Buffer containing wire-format dname.
 * \param data_len	Length of the buffer.
 * \param text		Text output.
 */
void wire_dname_to_str(const uint8_t  *data,
                       const uint32_t data_len,
                       char *text);

/*!
 * \brief Converts unsigned integer to mantissa*10^(exponent).
 *
 * Given number is encoded as two 4-bit numbers. First part is mantissa [0-9],
 * second part is decimal exponent [0-15]. Result is concatenation of these
 * two blocks.
 *
 * \param number	Number to convert.
 *
 * \retval number	encoded number.
 */
uint8_t loc64to8(uint64_t number);

/*!
 * \brief Sorts mandatory parameter values of the SVCB record.
 *
 * \param list_begin	Start of the parameter list.
 * \param list_end	End of the parameter list.
 */
void svcb_mandatory_sort(uint8_t *list_begin, uint8_t *list_end);

/*!
 * \brief Sorts parameters of the SVCB record.
 *
 * \param scanner	Scanner context.
 * \param rdata_end	Current end of the output data.
 *
 * \return ZS_*.
 */
int svcb_sort(zs_scanner_t *scanner, uint8_t *rdata_end);

/*!
 * \brief Final check of a sorted SVCB record.
 *
 * \param scanner	Scanner context.
 * \param rdata_end	Current end of the output data.
 *
 * \return ZS_*.
 */
int svcb_check(zs_scanner_t *scanner, uint8_t *rdata_end);

/*! @} */
