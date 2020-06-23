/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "libknot/consts.h"
#include "libknot/packet/wire.h"
#include "libknot/rrtype/opt.h"

#ifndef UNIX_PATH_MAX
struct sockaddr_un sizecheck;
#define UNIX_PATH_MAX sizeof(sizecheck.sun_path)
#endif

#define KNOT_PROBE_PREFIX_MAXSIZE (UNIX_PATH_MAX - sizeof("ffff.unix"))

typedef struct {
	uint32_t tcp_rtt;
	uint8_t ip;
	uint8_t proto;

	struct {
		uint8_t addr[16];
		uint16_t port;
	} local;

	struct {
		uint8_t addr[16];
		uint16_t port;
	} remote;

	struct {
		uint8_t hdr[KNOT_WIRE_HEADER_SIZE];
		uint8_t qname[KNOT_DNAME_MAXLEN];
		uint16_t qtype;
		uint16_t qclass;
	} query;

	struct {
		uint8_t hdr[KNOT_WIRE_HEADER_SIZE];
		uint8_t missing;
	} reply;

	struct {
		uint8_t client_subnet[KNOT_EDNS_CLIENT_SUBNET_ADDRESS_MAXLEN];
		uint32_t options;
		uint16_t payload;
		uint16_t flags;
		uint8_t rcode;
		uint8_t version;
	} edns;
} knot_probe_data_t;
