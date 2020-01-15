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

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "../../contrib/libbpf/bpf/bpf_helpers.h"
#include "../../contrib/libbpf/bpf/bpf_endian.h"
#include "bpf/parsing_helpers.h"

/** Assume netdev has no more than 64 queues
 * LATER: it might be better to detect this on startup time (per-device). */
#define QUEUE_MAX 64

/** A set entry here means that the corresponding queue_id
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
static const size_t frag_hdr_len = sizeof(struct ipv6_frag_hdr);

SEC("xdp_redirect_udp")
int xdp_redirect_udp_func(struct xdp_md *ctx)
{
	struct ethhdr *eth = NULL;
	struct iphdr *iphdr = NULL;
	struct ipv6hdr *ipv6hdr = NULL;
	struct udphdr *udphdr = NULL;

	void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh = { .pos = (void *)(long)ctx->data };

	int ip_type, eth_type, fragmented = 0;
	eth_type = bpf_ntohs(parse_ethhdr(&nh, data_end, &eth));
	switch (eth_type) {
		case ETH_P_IP:
			ip_type = parse_iphdr(&nh, data_end, &iphdr);
			if (iphdr != NULL && iphdr->frag_off != 0 &&
			    iphdr->frag_off != 0x0040 /* htons(IP_DF) */) {
				fragmented = 1;
			}
			break;
		case ETH_P_IPV6:
			ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
			if (ip_type == IPPROTO_FRAGMENT &&
			    nh.pos + frag_hdr_len < data_end) {
				fragmented = 1;
				struct ipv6_frag_hdr *frag_hdr = nh.pos;
				ip_type = frag_hdr->nexthdr;
				nh.pos += frag_hdr_len;
			}
			break;
		default:
			return XDP_PASS;
	}

	if (ip_type != IPPROTO_UDP) {
		return XDP_PASS;
	}

	if (parse_udphdr(&nh, data_end, &udphdr) < 1) {
		return XDP_PASS;
	}

	int index = ctx->rx_queue_index;
	int *qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf) {
		return XDP_ABORTED;
	}

	if (udphdr->dest != *qidconf) {
		return XDP_PASS;
	}

	if (fragmented) {
		return XDP_DROP;
	}

	return bpf_redirect_map(&xsks_map, index, 0);
}
