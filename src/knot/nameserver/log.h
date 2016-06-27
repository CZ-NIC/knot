/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "contrib/sockaddr.h"
#include "knot/common/log.h"

/*!
 * \brief Base log message format for network communication.
 *
 * Emits a message in the following format:
 * > [zone] operation, address: custom formatted message
 */
#define NS_PROC_LOG(priority, zone, remote, operation, msg, ...) do { \
	char addr[SOCKADDR_STRLEN] = ""; \
	sockaddr_tostr(addr, sizeof(addr), (struct sockaddr *)remote); \
	log_msg_zone(priority, zone, "%s, %s: " msg, operation, addr, ##__VA_ARGS__); \
	} while (0)
