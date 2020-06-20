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

typedef struct {
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

	uint32_t tcp_rtt;

	struct {
		uint8_t hdr[KNOT_WIRE_HEADER_SIZE];
		uint16_t qclass;
		uint16_t qtype;
		uint8_t qname[KNOT_DNAME_MAXLEN];
	} query;

	struct {
		uint8_t hdr[KNOT_WIRE_HEADER_SIZE];
		uint8_t missing;
	} reply;

	struct {
		uint16_t payload;
		uint8_t rcode;
		uint8_t version;
		uint16_t flags;
		uint32_t options;
		uint8_t client_subnet[KNOT_EDNS_CLIENT_SUBNET_ADDRESS_MAXLEN];
	} edns;
} knot_probe_data_t;
