/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#define tcp_master orig_tcp_master
#include "knot/server/tcp-handler.c"
#undef tcp_master

int tcp_master(dthread_t *thread)
{
	log_info("AFL, empty TCP handler");
	return 0;
}
