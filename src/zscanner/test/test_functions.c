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

#include "zscanner/scanner_functions.h"

#include <inttypes.h>  // PRIu64
#include <stdio.h>     // printf
#include <arpa/inet.h> // ntohs

#include "util/descriptor.h" // knot_rrtype_to_string
#include "util/error.h"      // knot_strerror
#include "zscanner/scanner.h"


void print_wire_dname(const uint8_t *dname, uint32_t dname_length)
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

void process_error(const scanner_t *s)
{
    printf("LINE(%03"PRIu64") ERROR(%s) FILE(%s) NEAR(%s)\n",
           s->line_counter,
           knot_strerror(s->error_code),
           s->file_name,
           s->buffer);
    fflush(stdout);
}

void process_record(const scanner_t *s)
{
    uint16_t r_data_length = ntohs(*(s->r_data_length_position));

    printf("LINE(%03"PRIu64") %s %u %*s ",
           s->line_counter,
           knot_rrclass_to_string(s->r_class),
           s->r_ttl,
           5,
           knot_rrtype_to_string(s->r_type));

    print_wire_dname(s->r_owner, s->r_owner_length);

    printf("  #%u#: ", r_data_length);

    for (int i = 0; i < r_data_length; i++) {
        printf("%02x", (s->r_data)[i + 2]);
    }

    printf("\n");
    fflush(stdout);
}

