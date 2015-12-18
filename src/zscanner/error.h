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
 * \file error.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Error codes and handling.
 * @{
 */

#pragma once

enum err_codes {
	ZS_OK = 0,
	ZS_EINVAL = -1000,
	ZS_ENOMEM,
	ZS_FILE_OPEN,
	ZS_FILE_INVALID,
	ZS_FILE_PATH,
	ZS_FILE_MMAP,
	ZS_DOS_NEWLINE,
	ZS_UNCOVERED_STATE,
	ZS_UNCLOSED_MULTILINE,
	ZS_LEFT_PARENTHESIS,
	ZS_RIGHT_PARENTHESIS,
	ZS_UNSUPPORTED_TYPE,
	ZS_BAD_PREVIOUS_OWNER,
	ZS_BAD_DNAME_CHAR,
	ZS_BAD_OWNER,
	ZS_LABEL_OVERFLOW,
	ZS_DNAME_OVERFLOW,
	ZS_BAD_NUMBER,
	ZS_NUMBER64_OVERFLOW,
	ZS_NUMBER32_OVERFLOW,
	ZS_NUMBER16_OVERFLOW,
	ZS_NUMBER8_OVERFLOW,
	ZS_FLOAT_OVERFLOW,
	ZS_RDATA_OVERFLOW,
	ZS_ITEM_OVERFLOW,
	ZS_BAD_ADDRESS_CHAR,
	ZS_BAD_IPV4,
	ZS_BAD_IPV6,
	ZS_BAD_GATEWAY,
	ZS_BAD_GATEWAY_KEY,
	ZS_BAD_APL,
	ZS_BAD_RDATA,
	ZS_BAD_HEX_RDATA,
	ZS_BAD_HEX_CHAR,
	ZS_BAD_BASE64_CHAR,
	ZS_BAD_BASE32HEX_CHAR,
	ZS_BAD_REST,
	ZS_BAD_TIMESTAMP_CHAR,
	ZS_BAD_TIMESTAMP_LENGTH,
	ZS_BAD_TIMESTAMP,
	ZS_BAD_DATE,
	ZS_BAD_TIME,
	ZS_BAD_TIME_UNIT,
	ZS_BAD_BITMAP,
	ZS_TEXT_OVERFLOW,
	ZS_BAD_TEXT_CHAR,
	ZS_BAD_TEXT,
	ZS_BAD_DIRECTIVE,
	ZS_BAD_TTL,
	ZS_BAD_ORIGIN,
	ZS_BAD_INCLUDE_FILENAME,
	ZS_BAD_INCLUDE_ORIGIN,
	ZS_UNPROCESSED_INCLUDE,
	ZS_UNOPENED_INCLUDE,
	ZS_BAD_RDATA_LENGTH,
	ZS_CANNOT_TEXT_DATA,
	ZS_BAD_LOC_DATA,
	ZS_UNKNOWN_BLOCK,
	ZS_BAD_ALGORITHM,
	ZS_BAD_CERT_TYPE,
	ZS_BAD_EUI_LENGTH,
	ZS_BAD_L64_LENGTH,
	ZS_BAD_CHAR_COLON,
	ZS_BAD_CHAR_DASH
};

/*!
 * \brief Returns error message for the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error message.
 */
const char* zs_strerror(const int code);

/*!
 * \brief Returns error code name of the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error code name.
 */
const char* zs_errorname(const int code);

/*! @} */
