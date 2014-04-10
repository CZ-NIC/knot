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

#include <stdlib.h>	// NULL

#include "zscanner/error.h"

typedef struct {
	int        code;
	const char *text;
	const char *code_name;
} err_table_t;

#define ERR_ITEM(code, text) { code, text, #code }

const err_table_t err_msgs[] = {
	ERR_ITEM( ZS_OK, "OK" ),

	/* Zone file loader errors. */
	ERR_ITEM( ZS_LOADER_FSTAT,
	          "Fstat error." ),
	ERR_ITEM( ZS_LOADER_DIRECTORY,
	          "Zone file is a directory." ),
	ERR_ITEM( ZS_LOADER_EMPTY,
	          "Empty zone file." ),
	ERR_ITEM( ZS_LOADER_MMAP,
	          "Mmap error." ),
	ERR_ITEM( ZS_LOADER_MUNMAP,
	          "Munmap error." ),
	ERR_ITEM( ZS_LOADER_SCANNER,
	          "Zone processing error." ),

	/* Zone scanner errors. */
	ERR_ITEM( ZS_DOS_NEWLINE,
	          "Unsupported CRLF newline. Please, remove CR bytes." ),
	ERR_ITEM( ZS_UNCOVERED_STATE,
	          "General scanner error." ),
	ERR_ITEM( ZS_UNCLOSED_MULTILINE,
	          "Unclosed last multiline block." ),
	ERR_ITEM( ZS_LEFT_PARENTHESIS,
	          "Too many left parentheses." ),
	ERR_ITEM( ZS_RIGHT_PARENTHESIS,
	          "Too many right parentheses." ),
	ERR_ITEM( ZS_UNSUPPORTED_TYPE,
	          "Unsupported record type." ),
	ERR_ITEM( ZS_BAD_PREVIOUS_OWNER,
	          "Previous owner is invalid." ),
	ERR_ITEM( ZS_BAD_DNAME_CHAR,
	          "Invalid domain name character." ),
	ERR_ITEM( ZS_BAD_OWNER,
	          "Owner is invalid." ),
	ERR_ITEM( ZS_LABEL_OVERFLOW,
	          "Maximal domain name label length has exceeded." ),
	ERR_ITEM( ZS_DNAME_OVERFLOW,
	          "Maximal domain name length has exceeded." ),
	ERR_ITEM( ZS_BAD_NUMBER,
	          "Invalid number." ),
	ERR_ITEM( ZS_NUMBER64_OVERFLOW,
	          "Number is too big." ),
	ERR_ITEM( ZS_NUMBER32_OVERFLOW,
	          "Number is bigger than 32 bits." ),
	ERR_ITEM( ZS_NUMBER16_OVERFLOW,
	          "Number is bigger than 16 bits." ),
	ERR_ITEM( ZS_NUMBER8_OVERFLOW,
	          "Number is bigger than 8 bits." ),
	ERR_ITEM( ZS_FLOAT_OVERFLOW,
	          "Float number overflow." ),
	ERR_ITEM( ZS_RDATA_OVERFLOW,
	          "Maximal record data length has exceeded." ),
	ERR_ITEM( ZS_ITEM_OVERFLOW,
	          "Maximal item length has exceeded." ),
	ERR_ITEM( ZS_BAD_ADDRESS_CHAR,
	          "Invalid address character." ),
	ERR_ITEM( ZS_BAD_IPV4,
	          "Invalid IPv4 address." ),
	ERR_ITEM( ZS_BAD_IPV6,
	          "Invalid IPv6 address." ),
	ERR_ITEM( ZS_BAD_GATEWAY,
	          "Invalid gateway." ),
	ERR_ITEM( ZS_BAD_GATEWAY_KEY,
	          "Invalid gateway key." ),
	ERR_ITEM( ZS_BAD_APL,
	          "Invalid address prefix list." ),
	ERR_ITEM( ZS_BAD_RDATA,
	          "Invalid record data." ),
	ERR_ITEM( ZS_BAD_HEX_RDATA,
	          "Invalid record data in hex format." ),
	ERR_ITEM( ZS_BAD_HEX_CHAR,
	          "Invalid hexadecimal character." ),
	ERR_ITEM( ZS_BAD_BASE64_CHAR,
	          "Invalid Base64 character." ),
	ERR_ITEM( ZS_BAD_BASE32HEX_CHAR,
	          "Invalid Base32hex character." ),
	ERR_ITEM( ZS_BAD_REST,
	          "Unexpected data." ),
	ERR_ITEM( ZS_BAD_TIMESTAMP_CHAR,
	          "Invalid timestamp character." ),
	ERR_ITEM( ZS_BAD_TIMESTAMP_LENGTH,
	          "Invalid timestamp length." ),
	ERR_ITEM( ZS_BAD_TIMESTAMP,
	          "Invalid timestamp." ),
	ERR_ITEM( ZS_BAD_DATE,
	          "Invalid date." ),
	ERR_ITEM( ZS_BAD_TIME,
	          "Invalid time." ),
	ERR_ITEM( ZS_BAD_TIME_UNIT,
	          "Invalid time unit." ),
	ERR_ITEM( ZS_BAD_BITMAP,
	          "Invalid bitmap." ),
	ERR_ITEM( ZS_TEXT_OVERFLOW,
	          "Text is too long." ),
	ERR_ITEM( ZS_BAD_TEXT_CHAR,
	          "Invalid text character." ),
	ERR_ITEM( ZS_BAD_TEXT,
	          "Invalid text string." ),
	ERR_ITEM( ZS_BAD_DIRECTIVE,
	          "Invalid directive." ),
	ERR_ITEM( ZS_BAD_TTL,
	          "Invalid zone TTL." ),
	ERR_ITEM( ZS_BAD_ORIGIN,
	          "Invalid FQDN zone origin." ),
	ERR_ITEM( ZS_BAD_INCLUDE_FILENAME,
	          "Invalid filename in include directive." ),
	ERR_ITEM( ZS_BAD_INCLUDE_ORIGIN,
	          "Invalid origin in include directive." ),
	ERR_ITEM( ZS_UNPROCESSED_INCLUDE,
	          "Include file processing error." ),
	ERR_ITEM( ZS_UNOPENED_INCLUDE,
	          "Include file opening error." ),
	ERR_ITEM( ZS_BAD_RDATA_LENGTH,
	          "The rdata length statement is incorrect." ),
	ERR_ITEM( ZS_CANNOT_TEXT_DATA,
	          "Unable to process text form for this type." ),
	ERR_ITEM( ZS_BAD_LOC_DATA,
	          "Invalid zone location data." ),
	ERR_ITEM( ZS_UNKNOWN_BLOCK,
	          "Unknown rdata block." ),
	ERR_ITEM( ZS_BAD_ALGORITHM,
	          "Invalid algorithm." ),
	ERR_ITEM( ZS_BAD_CERT_TYPE,
	          "Invalid certificate type." ),
	ERR_ITEM( ZS_BAD_EUI_LENGTH,
	          "Invalid EUI length." ),
	ERR_ITEM( ZS_BAD_L64_LENGTH,
	          "Invalid 64-bit locator." ),
	ERR_ITEM( ZS_BAD_CHAR_COLON,
	          "Missing colon character." ),
	ERR_ITEM( ZS_BAD_CHAR_DASH,
	          "Missing dash character." ),

	ERR_ITEM( 0, NULL ) // Terminator
};

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
