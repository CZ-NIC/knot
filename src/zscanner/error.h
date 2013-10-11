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

#ifndef _ZSCANNER__ERROR_H_
#define _ZSCANNER__ERROR_H_

enum err_codes {
	ZSCANNER_OK = 0,

	FLOADER_EFSTAT = -1000,
	FLOADER_EDIRECTORY,
	FLOADER_EEMPTY,
	FLOADER_EMMAP,
	FLOADER_EMUNMAP,
	FLOADER_ESCANNER,

	ZSCANNER_UNCOVERED_STATE,
	ZSCANNER_UNCLOSED_MULTILINE,
	ZSCANNER_ELEFT_PARENTHESIS,
	ZSCANNER_ERIGHT_PARENTHESIS,
	ZSCANNER_EUNSUPPORTED_TYPE,
	ZSCANNER_EBAD_PREVIOUS_OWNER,
	ZSCANNER_EBAD_DNAME_CHAR,
	ZSCANNER_EBAD_OWNER,
	ZSCANNER_ELABEL_OVERFLOW,
	ZSCANNER_EDNAME_OVERFLOW,
	ZSCANNER_EBAD_NUMBER,
	ZSCANNER_ENUMBER64_OVERFLOW,
	ZSCANNER_ENUMBER32_OVERFLOW,
	ZSCANNER_ENUMBER16_OVERFLOW,
	ZSCANNER_ENUMBER8_OVERFLOW,
	ZSCANNER_EFLOAT_OVERFLOW,
	ZSCANNER_ERDATA_OVERFLOW,
	ZSCANNER_EITEM_OVERFLOW,
	ZSCANNER_EBAD_ADDRESS_CHAR,
	ZSCANNER_EBAD_IPV4,
	ZSCANNER_EBAD_IPV6,
	ZSCANNER_EBAD_GATEWAY,
	ZSCANNER_EBAD_GATEWAY_KEY,
	ZSCANNER_EBAD_APL,
	ZSCANNER_EBAD_RDATA,
	ZSCANNER_EBAD_HEX_RDATA,
	ZSCANNER_EBAD_HEX_CHAR,
	ZSCANNER_EBAD_BASE64_CHAR,
	ZSCANNER_EBAD_BASE32HEX_CHAR,
	ZSCANNER_EBAD_REST,
	ZSCANNER_EBAD_TIMESTAMP_CHAR,
	ZSCANNER_EBAD_TIMESTAMP_LENGTH,
	ZSCANNER_EBAD_TIMESTAMP,
	ZSCANNER_EBAD_DATE,
	ZSCANNER_EBAD_TIME,
	ZSCANNER_EBAD_TIME_UNIT,
	ZSCANNER_EBAD_BITMAP,
	ZSCANNER_ETEXT_OVERFLOW,
	ZSCANNER_EBAD_TEXT_CHAR,
	ZSCANNER_EBAD_TEXT,
	ZSCANNER_EBAD_DIRECTIVE,
	ZSCANNER_EBAD_TTL,
	ZSCANNER_EBAD_ORIGIN,
	ZSCANNER_EBAD_INCLUDE_FILENAME,
	ZSCANNER_EBAD_INCLUDE_ORIGIN,
	ZSCANNER_EUNPROCESSED_INCLUDE,
	ZSCANNER_EUNOPENED_INCLUDE,
	ZSCANNER_EBAD_RDATA_LENGTH,
	ZSCANNER_ECANNOT_TEXT_DATA,
	ZSCANNER_EBAD_LOC_DATA,
	ZSCANNER_EUNKNOWN_BLOCK,
	ZSCANNER_EBAD_ALGORITHM,
	ZSCANNER_EBAD_CERT_TYPE,
	ZSCANNER_EBAD_EUI_LENGTH,
	ZSCANNER_EBAD_L64_LENGTH,
	ZSCANNER_EBAD_CHAR_COLON,
	ZSCANNER_EBAD_CHAR_DASH
};

/*!
 * \brief Returns error message for the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error message.
 */
const char* zscanner_strerror(const int code);

/*!
 * \brief Returns error code name of the given error code.
 *
 * \param code Error code.
 *
 * \return String containing the error code name.
 */
const char* zscanner_errorname(const int code);

#endif // _ZSCANNER__ERROR_H_

/*! @} */
