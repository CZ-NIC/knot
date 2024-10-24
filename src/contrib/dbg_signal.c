/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "contrib/dbg_signal.h"

#include "knot/common/log.h"
#include "libknot/libknot.h"

static char dbg_buffer[KNOT_DNAME_MAXLEN] = { 0 };
static char dbg_hex_buffer[3 * sizeof(dbg_buffer)] = { 0 };
static dbg_data_t dbg_data;

/*! \brief Temporary debug helper - signal handler. */
static void dbg_signal_handler(int signum)
{
	printf("%s\n", strsignal(signum));

	char *dname_str = knot_dname_to_str(dbg_buffer, dbg_data.dname,
	                                    sizeof(dbg_buffer));

	char *src, *dst;
	int remain = sizeof(dbg_hex_buffer);
	for (src = (char *)dbg_data.dname, dst = dbg_hex_buffer; *src != '\0'; src++) {
		int n = snprintf(dst, remain, " %02x", *src);

		if (n < remain) {
			dst += n;
			remain -= n;
		} else {    // It didn't fit.
			snprintf(dst + remain - 1, remain, "+");
			break;
		}

	}

	printf("aborting, dname: %s\n"
	       "          (hex): %s\n", dname_str, dbg_hex_buffer);

	abort();
}

/*! \brief Temporary debug helper - signal handler setup. */
void dbg_signal_setup(void)
{
	struct sigaction action = { .sa_handler = dbg_signal_handler };
	sigaction(SIGSEGV, &action, NULL);
}

/*! \brief Temporary debug helper - record the monitored data. */
void dbg_record(const knot_dname_t *dbg_dname)
{
	dbg_data.dname = dbg_dname;
}
