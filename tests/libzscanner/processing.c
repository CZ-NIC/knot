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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "libzscanner/scanner.h"
#include "libzscanner/functions.c"
#include "libzscanner/processing.h"
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

int test_date_to_timestamp(void)
{
	time_t    ref_timestamp, max_timestamp;
	uint32_t  test_timestamp;
	uint8_t   buffer[16];
	uint64_t  val1, val2; // For time_t type unification.
	struct tm tm;

	// Set UTC for strftime.
	putenv("TZ=UTC");
	tzset();

	// Get maximal allowed timestamp.
	strptime("21051231235959", "%Y%m%d%H%M%S", &tm);
	max_timestamp = mktime(&tm);

	// Testing loop over whole input interval.
	for (ref_timestamp = 0;
	     ref_timestamp < max_timestamp;
	     ref_timestamp += 1) {
		struct tm result;
		// Get reference (correct) timestamp.
		strftime((char*)buffer, sizeof(buffer), "%Y%m%d%H%M%S",
			 gmtime_r(&ref_timestamp, &result));

		// Get testing timestamp.
		test_timestamp = 0U; // prevents Wunitialized
		date_to_timestamp(buffer, &test_timestamp);

		// Some continuous loging.
		if (ref_timestamp % 10000000 == 0) {
			val1 = ref_timestamp;
			printf("%s = %"PRIu64"\n", buffer, val1);
		}

		// Comparing results.
		if (ref_timestamp != test_timestamp) {
			val1 = ref_timestamp;

			if (ref_timestamp > test_timestamp) {
				val2 = ref_timestamp - test_timestamp;
				printf("%s = %"PRIu64", in - out = %"PRIu64"\n",
				       buffer, val1, val2);
			} else {
				val2 = test_timestamp - ref_timestamp;
				printf("%s = %"PRIu64", out - in = %"PRIu64"\n",
				       buffer, val1, val2);
			}

			return -1;
		}
	}

	return 0;
}
