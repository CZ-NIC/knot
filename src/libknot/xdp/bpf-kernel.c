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

#include "bpf-consts.h"
#include "../../contrib/libbpf/include/uapi/linux/bpf.h"
#include "../../contrib/libbpf/bpf/bpf_endian.h"
#include "../../contrib/libbpf/bpf/bpf_helpers.h"

/* Don't fragment flag. */
#define	IP_DF 0x4000
#define IPV6_FLOWINFO_MASK __constant_htonl(0x0FFFFFFF)
#define AF_INET  2
#define AF_INET6 10

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
struct bpf_map_def SEC("maps") forward_map = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct ipv6_frag_hdr {
	unsigned char nexthdr;
	unsigned char whatever[7];
} __attribute__((packed));

SEC("xdp_redirect_udp")
int xdp_redirect_udp_func(struct xdp_md *ctx)
{
	const void *data = (void *)(long)ctx->data;
	const void *data_end = (void *)(long)ctx->data_end;

	const struct ethhdr *eth = data;
	struct iphdr *ip4;
	struct ipv6hdr *ip6;
	const struct udphdr *udp;

	__u8 ip_proto;
	__u8 fragmented = 0;

	struct bpf_fib_lookup fib_params;

	/* Parse Ethernet header. */
	if ((void *)eth + sizeof(*eth) > data_end) {
		return XDP_DROP;
	}
	data += sizeof(*eth);

	/* Parse IPv4 or IPv6 header. */
	switch (eth->h_proto) {
	case __constant_htons(ETH_P_IP):
		ip4 = data;
		if ((void *)ip4 + sizeof(*ip4) > data_end) {
			return XDP_DROP;
		}
		if (ip4->version != 4) {
			return XDP_DROP;
		}
		if (ip4->frag_off != 0 &&
		    ip4->frag_off != __constant_htons(IP_DF)) {
			fragmented = 1;
		}
		ip_proto = ip4->protocol;
		udp = data + ip4->ihl * 4;

		break;
	case __constant_htons(ETH_P_IPV6):
		ip6 = data;
		if ((void *)ip6 + sizeof(*ip6) > data_end) {
			return XDP_DROP;
		}
		if (ip6->version != 6) {
			return XDP_DROP;
		}
		ip_proto = ip6->nexthdr;
		data += sizeof(*ip6);
		if (ip_proto == IPPROTO_FRAGMENT) {
			fragmented = 1;
			const struct ipv6_frag_hdr *frag = data;
			if ((void *)frag + sizeof(*frag) > data_end) {
				return XDP_DROP;
			}
			ip_proto = frag->nexthdr;
			data += sizeof(*frag);
		}
		udp = data;
		break;
	default:
		/* Also applies to VLAN. */
		return XDP_PASS;
	}

	/* Treat UDP only. */
	if (ip_proto != IPPROTO_UDP) {
		return XDP_PASS;
	}

	/* Parse UDP header. */
	if ((void *)udp + sizeof(*udp) > data_end) {
		return XDP_DROP;
	}

	/* Check the UDP length. */
	if (data_end - (void *)udp != __bpf_ntohs(udp->len)) {
		return XDP_DROP;
	}

	if (1) {
		__builtin_memset(&fib_params, 0, sizeof(fib_params));

		if (eth->h_proto == __constant_htons(ETH_P_IP)) {
			if ((void *)ip4 + sizeof(*ip4) > data_end) {
				return XDP_DROP;
			}

			fib_params.family	= AF_INET;
			fib_params.tos		= ip4->tos;
			fib_params.l4_protocol	= ip4->protocol;
			fib_params.tot_len	= __bpf_ntohs(ip4->tot_len);
			fib_params.ipv4_src	= ip4->daddr;
			fib_params.ipv4_dst	= ip4->saddr;
		} else {
			if ((void *)ip6 + sizeof(*ip6) > data_end) {
				return XDP_DROP;
			}

			struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
			struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

			fib_params.family	= AF_INET6;
			fib_params.flowinfo	= *(__be32 *)ip6 & IPV6_FLOWINFO_MASK;
			fib_params.l4_protocol	= ip6->nexthdr;
			fib_params.tot_len	= __bpf_ntohs(ip6->payload_len);
			__builtin_memcpy(src, &ip6->daddr, sizeof(*src));
			__builtin_memcpy(dst, &ip6->saddr, sizeof(*dst));
		}

		fib_params.ifindex = ctx->ingress_ifindex;

		int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_OUTPUT | BPF_FIB_LOOKUP_DIRECT);
		switch (rc) {
		case BPF_FIB_LKUP_RET_SUCCESS:
			if (eth->h_proto == bpf_htons(ETH_P_IP)) {
				__u32 check = ip4->check;
				check += bpf_htons(0x0100);
				ip4->check = (__u16)(check + (check >= 0xFFFFF));
				ip4->ttl--;
			} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
				ip6->hop_limit--;
			}
			else {
				return XDP_PASS;
			}
			__builtin_memcpy(eth->h_dest, fib_params.smac, ETH_ALEN);
			__builtin_memcpy(eth->h_source, fib_params.dmac, ETH_ALEN);

			//TODO Not sure, maybe return XDP_PASS instead??
			bpf_redirect_map(&forward_map, fib_params.ifindex, 0);
			/* [[fallthrough]] */
		case BPF_FIB_LKUP_RET_NOT_FWDED:
			break;
		case BPF_FIB_LKUP_RET_FWD_DISABLED: /* Allow using `sudo sysctl net.ipv{4,6}.conf.all.forwarding=1`*/
			bpf_printk("Error: Forwarding not allowed!");
			/* [[fallthrough]] */
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:  /* [[fallthrough]] */
		case BPF_FIB_LKUP_RET_NO_NEIGH:    /* [[fallthrough]] */
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:
			return XDP_PASS;
		case BPF_FIB_LKUP_RET_BLACKHOLE:   /* [[fallthrough]] */
		case BPF_FIB_LKUP_RET_UNREACHABLE: /* [[fallthrough]] */
		case BPF_FIB_LKUP_RET_PROHIBIT:    /* [[fallthrough]] */
		default:
			return XDP_DROP;
		}

		if (fib_params.ifindex != ctx->ingress_ifindex) {
			return XDP_PASS;
		}
	}

	/* Get the queue options. */
	int index = ctx->rx_queue_index;
	int *qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf) {
		return XDP_ABORTED;
	}

	/* Treat specified destination ports only. */
	__u32 port_info = *qidconf;
	switch (port_info & KNOT_XDP_LISTEN_PORT_MASK) {
	case KNOT_XDP_LISTEN_PORT_DROP:
		return XDP_DROP;
	case KNOT_XDP_LISTEN_PORT_ALL:
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

	/* Forward the packet to user space. */
	return bpf_redirect_map(&xsks_map, index, 0);
}

char _license[] SEC("license") = "GPL";
