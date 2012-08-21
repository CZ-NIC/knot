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

#include "zscanner/scanner.h"

#include <stdint.h>                // uint32_t
#include <stdlib.h>                // calloc
#include <stdio.h>                 // sprintf
#include <limits.h>                // PATH_MAX
#include <libgen.h>                // dirname
#include <stdbool.h>               // bool
#include <sys/socket.h>            // AF_INET (BSD)
#include <netinet/in.h>            // in_addr (BSD)

#include "util/error.h"            // error codes
#include "util/descriptor.h"       // KNOT_RRTYPE_A
#include "zscanner/file_loader.h"  // include processing
#include "zscanner/scanner_functions.h"

#define SCANNER_WARNING(code) { s->error_code = code; }
#define SCANNER_ERROR(code)   { s->error_code = code; s->stop = true; }

#define TYPE_NUM(type) {                                              \
    *((uint16_t *)(s->r_data_end)) = htons(type);                     \
}

#define WINDOW_ADD_BIT(type) {                                        \
    win = type / 256; bit_pos = type % 256; byte_pos = bit_pos / 8;   \
                                                                      \
    ((s->windows[win]).bitmap)[byte_pos] |= 128 >> (bit_pos % 8);     \
    if ((s->windows[win]).length < byte_pos + 1) {                    \
        (s->windows[win]).length = byte_pos + 1;                      \
    }                                                                 \
    if (s->last_window < win) {                                       \
        s->last_window = win;                                         \
    }                                                                 \
}

// Include scanner file (in Ragel).
%%{
    machine zone_scanner;

    include "scanner_body.rl";

    write data;
}%%

scanner_t* scanner_create(const char *file_name)
{
    scanner_t *s = calloc(1, sizeof(scanner_t));
    if (s == NULL) {
        return NULL;
    }

    s->file_name = strdup(file_name);
    s->line_counter = 1;

    // Nonzero initial scanner state.
    s->cs = zone_scanner_start;

    s->r_data_length_position = (uint16_t *)(s->r_data);

    return s;
}

void scanner_free(scanner_t *s)
{
    free(s->file_name);
    free(s);
}

int scanner_process(char      *start,
                    char      *end,
                    bool      is_last_block,
                    scanner_t *s)
{
    // Necessary scanner variables.
    int  stack[RAGEL_STACK_SIZE];
    int  ret = 0;
    char *ts = NULL, *eof = NULL;
    char *p = start, *pe = end;

    // Auxiliary variables which are used in scanner body.
    struct in_addr  addr4;
    struct in6_addr addr6;
    uint8_t  win, byte_pos, bit_pos;
    uint32_t timestamp;
    int16_t  window;

    // Restoring scanner states.
    int cs  = s->cs;
    int top = s->top;
    memcpy(stack, s->stack, sizeof(stack));

    // Applying unprocessed token shift.
    if (s->token_shift > 0) {
        ts = start - s->token_shift;
    }

    // End of file check.
    if (is_last_block == true) {
        eof = pe;
    }

    // Writing scanner body (in C).
    %% write exec;

    // Scanner error state check.
    if (cs == zone_scanner_error) {
        printf("Unknown scanner error!\n");
        return -1;
    }

    // Storing scanner states.
    s->cs  = cs;
    s->top = top;
    memcpy(s->stack, stack, sizeof(stack));

    // Storing unprocessed token shift
    if (ts != NULL) {
        s->token_shift = pe - ts;
    }
    else {
        s->token_shift = 0;
    }

    return ret;
}

