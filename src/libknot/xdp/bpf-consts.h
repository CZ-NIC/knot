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

enum {
	KNOT_XDP_LISTEN_PORT_MASK = 0xFFFF0000, /*!< Listen port option mask. */
	KNOT_XDP_LISTEN_PORT_ALL  = 1 << 16,    /*!< Listen on all ports. */
	KNOT_XDP_LISTEN_PORT_DROP = 1 << 17,    /*!< Drop all incoming messages. */
};

#ifdef ENDIANITY_LITTLE
	#define KNOT_XDP_CONST_PROTO_IPV4	0x0008 // htons(ETH_P_IP)
	#define KNOT_XDP_CONST_PROTO_IPV6	0xDD86 // htons(ETH_P_IP6)
	#define KNOT_XDP_CONST_FLAG_DF		0x0040 // htons(IP_DF)
#else
	#define KNOT_XDP_CONST_PROTO_IPV4	0x0800
	#define KNOT_XDP_CONST_PROTO_IPV6	0x86DD
	#define KNOT_XDP_CONST_FLAG_DF		0x4000
#endif
