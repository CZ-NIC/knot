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

#include <inttypes.h>
#include <stdio.h>

#include "tests/processing.h"
#include "scanner.h"
#include "libknot/descriptor.c"

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

void debug_process_error(zs_scanner_t *s)
{
	if (s->error.fatal) {
		printf("LINE(%03"PRIu64") ERROR(%s) FILE(%s) NEAR(%s)\n",
		       s->line_counter,
		       zs_strerror(s->error.code),
		       s->file.name,
		       s->buffer);
	} else {
		printf("LINE(%03"PRIu64") WARNING(%s) FILE(%s) NEAR(%s)\n",
		       s->line_counter,
		       zs_strerror(s->error.code),
		       s->file.name,
		       s->buffer);
	}
	fflush(stdout);
}

void debug_process_record(zs_scanner_t *s)
{
	uint32_t i;

	char rclass[32];
	char rtype[32];

	if (knot_rrclass_to_string(s->r_class, rclass, sizeof(rclass)) > 0 &&
	    knot_rrtype_to_string(s->r_type, rtype, sizeof(rtype)) > 0) {
		printf("LINE(%03"PRIu64") %s %6u %*s ",
		       s->line_counter, rclass, s->r_ttl, 5, rtype);
	} else {
		printf("LINE(%03"PRIu64") %u %6u %*u ",
		       s->line_counter, s->r_class, s->r_ttl, 5, s->r_type);
	}

	print_wire_dname(s->r_owner, s->r_owner_length);

	printf(" \\# %u ", s->r_data_length);

	for (i = 0; i < s->r_data_length; i++) {
		printf("%02X", (s->r_data)[i]);
	}
	printf("\n");
	fflush(stdout);
}

void test_process_error(zs_scanner_t *s)
{
	if (s->error.fatal) {
		printf("ERROR=%s\n%s", zs_errorname(s->error.code), separator);
	} else {
		printf("WARNG=%s\n%s", zs_errorname(s->error.code), separator);
	}
	fflush(stdout);
}

void test_process_record(zs_scanner_t *s)
{
	uint32_t i;

	printf("OWNER=");
	for (i = 0; i < s->r_owner_length; i++) {
		printf("%02X", s->r_owner[i]);
	}
	printf("\n");
	printf("CLASS=%04X\n", s->r_class);
	printf("RRTTL=%08X\n", s->r_ttl);
	printf("RTYPE=%04X\n", s->r_type);
	printf("RDATA=");
	for (i = 0; i < s->r_data_length; i++) {
		printf("%02X", (s->r_data)[i]);
	}
	printf("\n%s", separator);
	fflush(stdout);
}
