/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Error codes and handling.
 *
 * \addtogroup zone_scanner
 * @{
 */

#pragma once

enum err_codes {
	ZS_OK = 0,
	ZS_EINVAL = -1000,
	ZS_ENOMEM,
	ZS_FILE_OPEN,
	ZS_FILE_INVALID,
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
	ZS_BAD_CHAR_DASH,
	ZS_DUPLICATE_SVCB_KEY,
	ZS_BAD_SVCB_PARAM,
	ZS_BAD_SVCB_MANDATORY,
	ZS_DUPLICATE_SVCB_MANDATORY,
	ZS_MISSING_SVCB_MANDATORY,
	ZS_EMPTY_LIST_ITEM,
	ZS_FILE_ACCESS,
	ZS_BAD_ALPN_BACKSLASH,
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
