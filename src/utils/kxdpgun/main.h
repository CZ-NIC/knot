/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "contrib/json.h"
#include "libknot/xdp/eth.h"
#include "libknot/xdp/tcp.h"

#define PROGRAM_NAME "kxdpgun"
#define SPACE        "  "

#define REMOTE_PORT_DEFAULT        53
#define REMOTE_PORT_DOQ_DEFAULT   853
#define LOCAL_PORT_MIN           2000
#define LOCAL_PORT_MAX          65535
#define QUIC_THREAD_PORTS         100

enum {
	KXDPGUN_WAIT,
	KXDPGUN_START,
	KXDPGUN_STOP,
};

typedef enum {
	KXDPGUN_IGNORE_NONE     = 0,
	KXDPGUN_IGNORE_QUERY    = (1 << 0),
	KXDPGUN_IGNORE_LASTBYTE = (1 << 1),
	KXDPGUN_IGNORE_CLOSE    = (1 << 2),
	KXDPGUN_REUSE_CONN      = (1 << 3),
} xdp_gun_ignore_t;

typedef struct xdp_gun_ctx {
	union {
		struct sockaddr_in local_ip4;
		struct sockaddr_in6 local_ip;
		struct sockaddr_storage local_ip_ss;
	};
	union {
		struct sockaddr_in target_ip4;
		struct sockaddr_in6 target_ip;
		struct sockaddr_storage target_ip_ss;
	};
	char                   dev[IFNAMSIZ];
	uint64_t               qps, duration;
	uint64_t               runid;
	uint64_t               stats_start_us;
	uint32_t               stats_period; // 0 means no periodic stats
	unsigned               at_once;
	uint16_t               msgid;
	uint16_t               edns_size;
	uint16_t               vlan_tci;
	uint8_t                local_mac[6], target_mac[6];
	uint8_t                local_ip_range;
	bool                   ipv6;
	bool                   tcp;
	bool                   quic;
	bool                   quic_full_handshake;
	const char             *qlog_dir;
	const char             *sending_mode;
	xdp_gun_ignore_t       ignore1;
	knot_tcp_ignore_t      ignore2;
	uint16_t               target_port;
	knot_xdp_filter_flag_t flags;
	unsigned               n_threads, thread_id;
	knot_eth_rss_conf_t    *rss_conf;
	jsonw_t                *jw;
	char                   **argv;
	knot_xdp_config_t      xdp_config;
} xdp_gun_ctx_t;
