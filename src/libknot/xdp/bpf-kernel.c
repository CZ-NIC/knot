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

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "../../contrib/libbpf/include/uapi/linux/bpf.h"
#include "../../contrib/libbpf/bpf/bpf_helpers.h"

/* Assume netdev has no more than 128 queues. */
#define QUEUE_MAX 128

/* A set entry here means that the corresponding queue_id
 * has an active AF_XDP socket bound to it. */
struct bpf_map_def SEC("maps") qidconf_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = QUEUE_MAX,
};
struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = QUEUE_MAX,
};

struct ipv6_frag_hdr {
	unsigned char nexthdr;
	unsigned char whatever[7];
} __attribute__((packed));

/* NOTE: this implementation expects little-endian byte ordering! */
SEC("xdp_redirect_udp")
int xdp_redirect_udp_func(struct xdp_md *ctx)
{
	const void *data = (void *)(long)ctx->data;
	const void *data_end = (void *)(long)ctx->data_end;

	const struct ethhdr *eth = data;
	const struct iphdr *ip4;
	const struct ipv6hdr *ip6;
	const struct udphdr *udp;

	__u8 ip_proto;
	__u8 fragmented = 0;

	/* Parse Ethernet header (VLAN not supported). */
	if ((void *)eth + sizeof(*eth) > data_end) {
		return XDP_PASS;
	}
	data += sizeof(*eth);

	/* Parse IPv4 or IPv6 header. */
	switch (eth->h_proto) {
		case 0x0008: /* htons(ETH_P_IP) */
			ip4 = data;
			if ((void *)ip4 + sizeof(*ip4) > data_end) {
				return XDP_PASS;
			}
			if (ip4->frag_off != 0 && ip4->frag_off != 0x0040) { /* htons(IP_DF) */
				fragmented = 1;
			}
			ip_proto = ip4->protocol;
			udp = data + ip4->ihl * 4;
			break;
		case 0xDD86: /* htons(ETH_P_IPV6) */
			ip6 = data;
			if ((void *)ip6 + sizeof(*ip6) > data_end) {
				return XDP_PASS;
			}
			ip_proto = ip6->nexthdr;
			data += sizeof(*ip6);
			if (ip_proto == IPPROTO_FRAGMENT) {
				fragmented = 1;
				const struct ipv6_frag_hdr *frag = data;
				if ((void *)frag + sizeof(*frag) > data_end) {
					return XDP_PASS;
				}
				ip_proto = frag->nexthdr;
				data += sizeof(*frag);
			}
			udp = data;
			break;
		default:
			return XDP_PASS;
	}

	/* Treat UDP only. */
	if (ip_proto != IPPROTO_UDP) {
		return XDP_PASS;
	}

	/* Parse UDP header. */
	if ((void *)udp + sizeof(*udp) > data_end) {
		return XDP_PASS;
	}

	int index = ctx->rx_queue_index;
	int *qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf) {
		return XDP_ABORTED;
	}

	/* Treat specified destination ports only. */
	__u32 port_info = *qidconf;
	switch (port_info & 0xFFFF0000) {
	case (1 << 17):
		return XDP_DROP;
	case (1 << 16):
		break;
	default:
		if (udp->dest != port_info) {
			return XDP_PASS;
		}
	}

	/* Drop fragmented UDP datagrams. */
	if (fragmented) {
		return XDP_DROP;
	}

	return bpf_redirect_map(&xsks_map, index, 0);
}
