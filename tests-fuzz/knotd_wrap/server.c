/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#define server_reconfigure orig_server_reconfigure
#include "knot/server/server.c"
#undef server_reconfigure

extern void udp_master_init_stdio(server_t *server);

int server_reconfigure(conf_t *conf, server_t *server)
{
	orig_server_reconfigure(conf, server);
	udp_master_init_stdio(server);

	return KNOT_EOK;
}
