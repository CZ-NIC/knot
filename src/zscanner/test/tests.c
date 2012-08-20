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

#include "zscanner/test/tests.h"

#include <inttypes.h>  // PRIu64
#include <stdio.h>     // printf
#include <time.h>
#include <stdlib.h>
#include "../scanner_functions.h"

int test__date_to_timestamp()
{
    time_t    timestamp_in = 0, timestamp_out = 0, max_timestamp = 0;
    char      buffer[16];
    struct tm tm;

    putenv("TZ=UTC");
    tzset();

    strptime("21051231235959", "%Y%m%d%H%M%S", &tm);
    max_timestamp = mktime(&tm);

    for (timestamp_in = 0; timestamp_in < max_timestamp; timestamp_in += 30) {
        strftime(buffer, sizeof(buffer), "%Y%m%d%H%M%S", gmtime(&timestamp_in));

        date_to_timestamp((uint8_t *)buffer, (uint32_t *)(&timestamp_out));

        if (timestamp_in % 10000000 == 0) {
            printf("%s = %"PRIu64"\n", buffer, timestamp_in);
        }

        if (timestamp_in != timestamp_out) {
            if (timestamp_in > timestamp_out) { 
                printf("%s = %"PRIu64", in - out = %"PRIu64"\n",
                buffer, timestamp_in, timestamp_in - timestamp_out);
            }
            else {
                printf("%s = %"PRIu64", out - in = %"PRIu64"\n",
                buffer, timestamp_in, timestamp_out - timestamp_in);
            }

            return -1;
        }
    }

    return 0;
}

