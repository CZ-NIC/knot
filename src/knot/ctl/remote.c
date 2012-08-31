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

#include "remote.h"
#include "common/log.h"
#include "common/fdset.h"
#include "knot/conf/conf.h"
#include "knot/other/error.h"
#include "knot/server/socket.h"
#include "knot/server/tcp-handler.h"

int remote_bind(conf_iface_t *desc)
{
	if (desc == NULL) {
		return -1;
	}
	
	/* Create new socket. */
	int s = socket_create(desc->family, SOCK_STREAM);
	if (s < 0) {
		log_server_error("Couldn't create socket for remote "
				 "control interface - %s",
				 knotd_strerror(s));
		return -1;
	}
	
	/* Bind to interface and start listening. */
	int r = socket_bind(s, desc->family, desc->address, desc->port);
	if (r == KNOTD_EOK) {
		r = socket_listen(s, TCP_BACKLOG_SIZE);
	}
	
	if (r != KNOTD_EOK) {
		socket_close(s);
		log_server_error("Could not bind to "
				 "remote control interface %s port %d.\n",
				 desc->address, desc->port);
		return -1;
	}
	
	return s;
}

int remote_unbind(int r)
{
	if (r < 0) {
		return KNOTD_EINVAL;
	}
	
	return socket_close(r);
}

int remote_poll(int r)
{
	if (r < 0) {
		return -1;
	}
	
	/* Wait for events. */
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(r, &rfds);
	return fdset_pselect(r + 1, &rfds, NULL, NULL, NULL, NULL);
}
