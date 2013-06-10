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

#include <config.h>
#include "zscanner/error.h"
#include <stdlib.h>	// NULL

typedef struct {
	int        code;
	const char *name;
} err_table_t;

const err_table_t err_msgs[] = {
	{ ZSCANNER_OK, "OK" },

	/* Zone file loader errors. */
	{ FLOADER_EFSTAT, "Fstat error." },
	{ FLOADER_EDIRECTORY, "Zone file is a directory." },
	{ FLOADER_EEMPTY, "Empty zone file." },
	{ FLOADER_EDEFAULTS, "Zone defaults processing error." },
	{ FLOADER_EMMAP, "Mmap error." },
	{ FLOADER_EMUNMAP, "Munmap error." },
	{ FLOADER_ESCANNER, "Zone processing error." },

	/* Zone scanner errors. */
	{ ZSCANNER_UNCOVERED_STATE, "General scanner error." },
	{ ZSCANNER_ELEFT_PARENTHESIS, "Too many left parentheses." },
	{ ZSCANNER_ERIGHT_PARENTHESIS, "Too many right parentheses." },
	{ ZSCANNER_EUNSUPPORTED_TYPE, "Unsupported record type." },
	{ ZSCANNER_EBAD_PREVIOUS_OWNER, "Previous owner is invalid." },
	{ ZSCANNER_EBAD_DNAME_CHAR, "Bad domain name character." },
	{ ZSCANNER_EBAD_OWNER, "Owner is invalid." },
	{ ZSCANNER_ELABEL_OVERFLOW, "Maximal domain name label length has exceeded." },
	{ ZSCANNER_EDNAME_OVERFLOW, "Maximal domain name length has exceeded." },
	{ ZSCANNER_EBAD_NUMBER, "Bad number." },
	{ ZSCANNER_ENUMBER64_OVERFLOW, "Number is too big." },
	{ ZSCANNER_ENUMBER32_OVERFLOW, "Number is bigger than 32 bits." },
	{ ZSCANNER_ENUMBER16_OVERFLOW, "Number is bigger than 16 bits." },
	{ ZSCANNER_ENUMBER8_OVERFLOW, "Number is bigger than 8 bits." },
	{ ZSCANNER_EFLOAT_OVERFLOW, "Float number overflow." },
	{ ZSCANNER_ERDATA_OVERFLOW, "Maximal record data length has exceeded." },
	{ ZSCANNER_EITEM_OVERFLOW, "Maximal item length has exceeded." },
	{ ZSCANNER_EBAD_ADDRESS_CHAR, "Bad address character." },
	{ ZSCANNER_EBAD_IPV4, "Bad IPv4 address." },
	{ ZSCANNER_EBAD_IPV6, "Bad IPv6 address." },
	{ ZSCANNER_EBAD_GATEWAY, "Bad gateway." },
	{ ZSCANNER_EBAD_GATEWAY_KEY, "Bad gateway key." },
	{ ZSCANNER_EBAD_APL, "Bad adress prefix list." },
	{ ZSCANNER_EBAD_RDATA, "Bad record data." },
	{ ZSCANNER_EBAD_HEX_RDATA, "Bad record data in hex format." },
	{ ZSCANNER_EBAD_HEX_CHAR, "Bad hexadecimal character." },
	{ ZSCANNER_EBAD_BASE64_CHAR, "Bad Base64 character." },
	{ ZSCANNER_EBAD_BASE32HEX_CHAR, "Bad Base32hex character." },
	{ ZSCANNER_EBAD_REST, "Unexpected data." },
	{ ZSCANNER_EBAD_TIMESTAMP_CHAR, "Bad timestamp character." },
	{ ZSCANNER_EBAD_TIMESTAMP_LENGTH, "Bad timestamp length." },
	{ ZSCANNER_EBAD_TIMESTAMP, "Bad timestamp." },
	{ ZSCANNER_EBAD_DATE, "Bad date." },
	{ ZSCANNER_EBAD_TIME, "Bad time." },
	{ ZSCANNER_EBAD_TIME_UNIT, "Bad time unit." },
	{ ZSCANNER_EBAD_BITMAP, "Bad bitmap." },
	{ ZSCANNER_ETEXT_OVERFLOW, "Text is too long." },
	{ ZSCANNER_EBAD_TEXT_CHAR, "Bad text character." },
	{ ZSCANNER_EBAD_TEXT, "Bad text string." },
	{ ZSCANNER_EBAD_DIRECTIVE, "Bad directive." },
	{ ZSCANNER_EBAD_TTL, "Bad zone TTL." },
	{ ZSCANNER_EBAD_ORIGIN, "Bad zone origin." },
	{ ZSCANNER_EBAD_INCLUDE_FILENAME, "Bad filename in include directive." },
	{ ZSCANNER_EBAD_INCLUDE_ORIGIN, "Bad origin in include directive." },
	{ ZSCANNER_EUNPROCESSED_INCLUDE, "Include file processing error." },
	{ ZSCANNER_EUNOPENED_INCLUDE, "Include file opening error." },
	{ ZSCANNER_EBAD_RDATA_LENGTH, "The rdata length statement is incorrect." },
	{ ZSCANNER_ECANNOT_TEXT_DATA, "Unable to process text form for this type." },
	{ ZSCANNER_EBAD_LOC_DATA, "Bad zone location data." },
	{ ZSCANNER_EUNKNOWN_BLOCK, "Unknown rdata block." },
	{ ZSCANNER_EBAD_ALGORITHM, "Bad algorithm." },
	{ ZSCANNER_EBAD_CERT_TYPE, "Bad certificate type." },
	{ ZSCANNER_EBAD_EUI_LENGTH, "Bad EUI length." },
	{ ZSCANNER_EBAD_L64_LENGTH, "Bad 64-bit locator." },
	{ ZSCANNER_EBAD_CHAR_COLON, "Missing colon character." },
	{ ZSCANNER_EBAD_CHAR_DASH, "Missing dash character." },

	{ 0, NULL } // Terminator
};

const char* zscanner_strerror(const int code)
{
	const err_table_t *err = err_msgs;

	while (err->name != NULL) {
		if (err->code == code) {
			return err->name;
		}
		err++;
	}

	return NULL;
}
