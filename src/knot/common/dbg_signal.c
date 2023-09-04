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

#include "knot/common/dbg_signal.h"

#include "knot/common/log.h"
#include "libknot/libknot.h"

/*! \brief Temporary debug helper - signal handler. */
static void dbg_signal_handler(int signum)
{
	printf("%s\n", strsignal(signum));

	extern dbg_data_t dbg_data;
	if (dbg_data.valid) {
		knot_dname_txt_storage_t name_str;
		(void)knot_dname_to_str(name_str, knot_pkt_qname(dbg_data.qdata->query),
		                        sizeof(name_str));

		char rrtype_str[32];
		int len = knot_rrtype_to_string(knot_pkt_qtype(dbg_data.qdata->query),
		                                rrtype_str, sizeof(rrtype_str));

		log_fatal("corrupted glue: name=%s, type=%s",
		          name_str, (len > 0) ? rrtype_str : "<error>");
	}

	abort();
}

/*! \brief Temporary debug helper - signal handler setup. */
void dbg_signal_setup(void)
{
	struct sigaction action = { .sa_handler = dbg_signal_handler };
	sigaction(SIGSEGV, &action, NULL);
}
