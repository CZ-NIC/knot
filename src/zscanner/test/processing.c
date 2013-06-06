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
#include "zscanner/scanner_functions.h"

#include <inttypes.h>			// PRIu64
#include <stdio.h>			// printf

#include "common/errcode.h"		// knot_strerror
#include "common/descriptor.h"		// knot_rrtype_to_string
#include "zscanner/scanner.h"		// scanner_t

#define ERROR_CODE_TO_STRING(code) [code - ZSCANNER_UNCOVERED_STATE] = #code
const char *error_names[] = {
	ERROR_CODE_TO_STRING(ZSCANNER_UNCOVERED_STATE),
	ERROR_CODE_TO_STRING(ZSCANNER_ELEFT_PARENTHESIS),
	ERROR_CODE_TO_STRING(ZSCANNER_ERIGHT_PARENTHESIS),
	ERROR_CODE_TO_STRING(ZSCANNER_EUNSUPPORTED_TYPE),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_PREVIOUS_OWNER),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_DNAME_CHAR),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_OWNER),
	ERROR_CODE_TO_STRING(ZSCANNER_ELABEL_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_EDNAME_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_NUMBER),
	ERROR_CODE_TO_STRING(ZSCANNER_ENUMBER64_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_ENUMBER32_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_ENUMBER16_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_ENUMBER8_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_EFLOAT_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_ERDATA_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_EITEM_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_ADDRESS_CHAR),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_IPV4),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_IPV6),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_GATEWAY),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_GATEWAY_KEY),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_APL),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_RDATA),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_HEX_RDATA),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_HEX_CHAR),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_BASE64_CHAR),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_BASE32HEX_CHAR),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_REST),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_TIMESTAMP_CHAR),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_TIMESTAMP_LENGTH),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_TIMESTAMP),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_DATE),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_TIME),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_TIME_UNIT),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_BITMAP),
	ERROR_CODE_TO_STRING(ZSCANNER_ETEXT_OVERFLOW),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_TEXT_CHAR),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_TEXT),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_DIRECTIVE),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_TTL),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_ORIGIN),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_INCLUDE_FILENAME),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_INCLUDE_ORIGIN),
	ERROR_CODE_TO_STRING(ZSCANNER_EUNPROCESSED_INCLUDE),
	ERROR_CODE_TO_STRING(ZSCANNER_EUNOPENED_INCLUDE),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_RDATA_LENGTH),
	ERROR_CODE_TO_STRING(ZSCANNER_ECANNOT_TEXT_DATA),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_LOC_DATA),
	ERROR_CODE_TO_STRING(ZSCANNER_EUNKNOWN_BLOCK),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_ALGORITHM),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_CERT_TYPE),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_EUI_LENGTH),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_L64_LENGTH),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_CHAR_COLON),
	ERROR_CODE_TO_STRING(ZSCANNER_EBAD_CHAR_DASH),
};
#define ERROR_CODE_NAME(code) error_names[code - ZSCANNER_UNCOVERED_STATE]

const char *separator = "------\n";

static void print_wire_dname(const uint8_t *dname, uint32_t dname_length)
{
	uint32_t label_length = 0, i = 0;

	for (i = 0; i < dname_length; i++) {
		if (label_length == 0) {
			label_length = dname[i];
			printf("(%u)", label_length);
			continue;
		}
		printf("%c", (char)dname[i]);
		label_length--;
	}
}

void empty_process(const scanner_t *s)
{
	(void)s;
}

void debug_process_error(const scanner_t *s)
{
	if (s->stop == true) {
		printf("LINE(%03"PRIu64") ERROR(%s) FILE(%s) NEAR(%s)\n",
		       s->line_counter,
		       knot_strerror(s->error_code),
		       s->file_name,
		       s->buffer);
	} else {
		printf("LINE(%03"PRIu64") WARNING(%s) FILE(%s) NEAR(%s)\n",
		       s->line_counter,
		       knot_strerror(s->error_code),
		       s->file_name,
		       s->buffer);
	}
	fflush(stdout);
}

void debug_process_record(const scanner_t *s)
{
	uint32_t block, block_length, i;

	char rclass[32];
	char rtype[32];

	if (knot_rrclass_to_string(s->r_class, rclass, sizeof(rclass)) > 0 &&
	    knot_rrtype_to_string(s->r_type, rtype, sizeof(rtype)) > 0) {
		printf("LINE(%03"PRIu64") %s %u %*s ",
		       s->line_counter, rclass, s->r_ttl, 5, rtype);
	} else {
		printf("LINE(%03"PRIu64") %u %u %*u ",
		       s->line_counter, s->r_class, s->r_ttl, 5, s->r_type);
	}

	print_wire_dname(s->r_owner, s->r_owner_length);

	printf("  #%u/%uB:", s->r_data_blocks_count, s->r_data_length);

	for (block = 1; block <= s->r_data_blocks_count; block++) {
		block_length =
			s->r_data_blocks[block] - s->r_data_blocks[block - 1];
		printf(" (%u)", block_length);

		for (i = s->r_data_blocks[block - 1];
		     i < s->r_data_blocks[block];
		     i++) {
			printf("%02X", (s->r_data)[i]);
		}
	}
	printf("\n");
	fflush(stdout);
}

void test_process_error(const scanner_t *s)
{
	if (s->stop == true) {
		printf("ERROR=%s\n%s", ERROR_CODE_NAME(s->error_code), separator);
	} else {
		printf("WARNG=%s\n%s", ERROR_CODE_NAME(s->error_code), separator);
	}
	fflush(stdout);
}

void test_process_record(const scanner_t *s)
{
	uint32_t block, i;

	printf("OWNER=");
	for (i = 0; i < s->r_owner_length; i++) {
		printf("%02X", s->r_owner[i]);
	}
	printf("\n");
	printf("CLASS=%04X\n", s->r_class);
	printf("RRTTL=%08X\n", s->r_ttl);
	printf("RTYPE=%04X\n", s->r_type);
	printf("RDATA=");
	for (block = 1; block <= s->r_data_blocks_count; block++) {
		if (block > 1) {
			printf(" ");
		}

		for (i = s->r_data_blocks[block - 1];
		     i < s->r_data_blocks[block];
		     i++) {
			printf("%02X", (s->r_data)[i]);
		}
	}
	printf("\n%s", separator);
	fflush(stdout);
}

void dump_rdata(const scanner_t *s)
{
	uint32_t block, i;

	for (block = 1; block <= s->r_data_blocks_count; block++) {
		for (i = s->r_data_blocks[block - 1];
		     i < s->r_data_blocks[block];
		     i++) {
			printf("%c", (s->r_data)[i]);
		}
	}
}
