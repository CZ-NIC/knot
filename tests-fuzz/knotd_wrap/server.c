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

#define server_reconfigure orig_server_reconfigure
#include "knot/server/server.c"
#undef server_reconfigure

extern void udp_master_init_stdio(server_t *server);

void server_reconfigure(conf_t *conf, server_t *server)
{
	orig_server_reconfigure(conf, server);
	udp_master_init_stdio(server);
}
