/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>

#include "libzscanner/error.h"

typedef struct {
	int        code;
	const char *text;
	const char *code_name;
} err_table_t;

#define ERR_ITEM(code, text) { code, text, #code }

static const err_table_t err_msgs[] = {
	ERR_ITEM( ZS_OK,
	          "ok" ),
	ERR_ITEM( ZS_EINVAL,
	          "invalid parameter" ),
	ERR_ITEM( ZS_ENOMEM,
	          "not enough memory" ),
	ERR_ITEM( ZS_FILE_OPEN,
	          "file open error" ),
	ERR_ITEM( ZS_FILE_INVALID,
	          "invalid file" ),
	ERR_ITEM( ZS_DOS_NEWLINE,
	          "unsupported CRLF newline, remove CR bytes" ),
	ERR_ITEM( ZS_UNCOVERED_STATE,
	          "general scanner error" ),
	ERR_ITEM( ZS_UNCLOSED_MULTILINE,
	          "unclosed last multiline block" ),
	ERR_ITEM( ZS_LEFT_PARENTHESIS,
	          "too many left parentheses" ),
	ERR_ITEM( ZS_RIGHT_PARENTHESIS,
	          "too many right parentheses" ),
	ERR_ITEM( ZS_UNSUPPORTED_TYPE,
	          "unsupported record type" ),
	ERR_ITEM( ZS_BAD_PREVIOUS_OWNER,
	          "previous owner is invalid" ),
	ERR_ITEM( ZS_BAD_DNAME_CHAR,
	          "invalid domain name character" ),
	ERR_ITEM( ZS_BAD_OWNER,
	          "owner is invalid" ),
	ERR_ITEM( ZS_LABEL_OVERFLOW,
	          "maximal domain name label length has exceeded" ),
	ERR_ITEM( ZS_DNAME_OVERFLOW,
	          "maximal domain name length has exceeded" ),
	ERR_ITEM( ZS_BAD_NUMBER,
	          "invalid number" ),
	ERR_ITEM( ZS_NUMBER64_OVERFLOW,
	          "number is too big" ),
	ERR_ITEM( ZS_NUMBER32_OVERFLOW,
	          "number is bigger than 32 bits" ),
	ERR_ITEM( ZS_NUMBER16_OVERFLOW,
	          "number is bigger than 16 bits" ),
	ERR_ITEM( ZS_NUMBER8_OVERFLOW,
	          "number is bigger than 8 bits" ),
	ERR_ITEM( ZS_FLOAT_OVERFLOW,
	          "float number overflow" ),
	ERR_ITEM( ZS_RDATA_OVERFLOW,
	          "maximal record data length has exceeded" ),
	ERR_ITEM( ZS_ITEM_OVERFLOW,
	          "maximal item length has exceeded" ),
	ERR_ITEM( ZS_BAD_ADDRESS_CHAR,
	          "invalid address character" ),
	ERR_ITEM( ZS_BAD_IPV4,
	          "invalid IPv4 address" ),
	ERR_ITEM( ZS_BAD_IPV6,
	          "invalid IPv6 address" ),
	ERR_ITEM( ZS_BAD_GATEWAY,
	          "invalid gateway" ),
	ERR_ITEM( ZS_BAD_GATEWAY_KEY,
	          "invalid gateway key" ),
	ERR_ITEM( ZS_BAD_APL,
	          "invalid address prefix list" ),
	ERR_ITEM( ZS_BAD_RDATA,
	          "invalid record data" ),
	ERR_ITEM( ZS_BAD_HEX_RDATA,
	          "invalid record data in hex format" ),
	ERR_ITEM( ZS_BAD_HEX_CHAR,
	          "invalid hexadecimal character" ),
	ERR_ITEM( ZS_BAD_BASE64_CHAR,
	          "invalid Base64 character" ),
	ERR_ITEM( ZS_BAD_BASE32HEX_CHAR,
	          "invalid Base32hex character" ),
	ERR_ITEM( ZS_BAD_REST,
	          "unexpected data" ),
	ERR_ITEM( ZS_BAD_TIMESTAMP_CHAR,
	          "invalid timestamp character" ),
	ERR_ITEM( ZS_BAD_TIMESTAMP_LENGTH,
	          "invalid timestamp length" ),
	ERR_ITEM( ZS_BAD_TIMESTAMP,
	          "invalid timestamp" ),
	ERR_ITEM( ZS_BAD_DATE,
	          "invalid date" ),
	ERR_ITEM( ZS_BAD_TIME,
	          "invalid time" ),
	ERR_ITEM( ZS_BAD_TIME_UNIT,
	          "invalid time unit" ),
	ERR_ITEM( ZS_BAD_BITMAP,
	          "invalid bitmap" ),
	ERR_ITEM( ZS_TEXT_OVERFLOW,
	          "text is too long" ),
	ERR_ITEM( ZS_BAD_TEXT_CHAR,
	          "invalid text character" ),
	ERR_ITEM( ZS_BAD_TEXT,
	          "invalid text string" ),
	ERR_ITEM( ZS_BAD_DIRECTIVE,
	          "invalid directive" ),
	ERR_ITEM( ZS_BAD_TTL,
	          "invalid zone TTL" ),
	ERR_ITEM( ZS_BAD_ORIGIN,
	          "invalid FQDN zone origin" ),
	ERR_ITEM( ZS_BAD_INCLUDE_FILENAME,
	          "invalid filename in include directive" ),
	ERR_ITEM( ZS_BAD_INCLUDE_ORIGIN,
	          "invalid origin in include directive" ),
	ERR_ITEM( ZS_UNPROCESSED_INCLUDE,
	          "include file processing error" ),
	ERR_ITEM( ZS_UNOPENED_INCLUDE,
	          "include file opening error" ),
	ERR_ITEM( ZS_BAD_RDATA_LENGTH,
	          "the rdata length statement is incorrect" ),
	ERR_ITEM( ZS_CANNOT_TEXT_DATA,
	          "unable to process text form for this type" ),
	ERR_ITEM( ZS_BAD_LOC_DATA,
	          "invalid zone location data" ),
	ERR_ITEM( ZS_UNKNOWN_BLOCK,
	          "unknown rdata block" ),
	ERR_ITEM( ZS_BAD_ALGORITHM,
	          "invalid algorithm" ),
	ERR_ITEM( ZS_BAD_CERT_TYPE,
	          "invalid certificate type" ),
	ERR_ITEM( ZS_BAD_EUI_LENGTH,
	          "invalid EUI length" ),
	ERR_ITEM( ZS_BAD_L64_LENGTH,
	          "invalid 64-bit locator" ),
	ERR_ITEM( ZS_BAD_CHAR_COLON,
	          "missing colon character" ),
	ERR_ITEM( ZS_BAD_CHAR_DASH,
	          "missing dash character" ),

	ERR_ITEM( 0, NULL ) // Terminator
};

__attribute__((visibility("default")))
const char* zs_strerror(const int code)
{
	const err_table_t *err = err_msgs;

	while (err->text != NULL) {
		if (err->code == code) {
			return err->text;
		}
		err++;
	}

	return NULL;
}

__attribute__((visibility("default")))
const char* zs_errorname(const int code)
{
	const err_table_t *err = err_msgs;

	while (err->text != NULL) {
		if (err->code == code) {
			return err->code_name;
		}
		err++;
	}

	return NULL;
}
