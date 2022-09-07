/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf-consts.h"
#include "../../contrib/libbpf/include/uapi/linux/bpf.h"
#include "../../contrib/libbpf/bpf/bpf_endian.h"
#include "../../contrib/libbpf/bpf/bpf_helpers.h"

/* Don't fragment flag. */
#define	IP_DF		0x4000

#define AF_INET		2
#define AF_INET6	10

/* Define maximum reasonable number of NIC queues supported. */
#define QUEUE_MAX	256

/* A map of configuration options. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, QUEUE_MAX);
	__uint(key_size, sizeof(__u32)); /* Must be 4 bytes. */
	__uint(value_size, sizeof(knot_xdp_opts_t));
} opts_map SEC(".maps");

/* A map of AF_XDP sockets. */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, QUEUE_MAX);
	__uint(key_size, sizeof(__u32)); /* Must be 4 bytes. */
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct ipv6_frag_hdr {
	unsigned char nexthdr;
	unsigned char whatever[7];
} __attribute__((packed));

struct pkt_desc {
	knot_xdp_opts_t opts;
	struct ethhdr *eth_hdr;
	const void *ip_hdr;
	__u8 ipv4;
};

static __always_inline
int check_route(struct xdp_md *ctx, const struct pkt_desc *desc)
{
	__u32 index = ctx->rx_queue_index;

	/* Take into account routing information. */
	if (desc->opts.flags & KNOT_XDP_FILTER_ROUTE) {
		struct bpf_fib_lookup fib = {
			.ifindex = 1 /* Loopback. */
		};
		if (desc->ipv4) {
			const struct iphdr *ip4 = desc->ip_hdr;
			fib.family   = AF_INET;
			fib.ipv4_src = ip4->daddr;
			fib.ipv4_dst = ip4->saddr;
		} else {
			const struct ipv6hdr *ip6 = desc->ip_hdr;
			struct in6_addr *ipv6_src = (struct in6_addr *)fib.ipv6_src;
			struct in6_addr *ipv6_dst = (struct in6_addr *)fib.ipv6_dst;
			fib.family = AF_INET6;
			*ipv6_src  = ip6->daddr;
			*ipv6_dst  = ip6->saddr;
		}

		int ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
		switch (ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
			/* Cross-interface answers are handled thru normal stack. */
			if (fib.ifindex != ctx->ingress_ifindex) {
				return XDP_PASS;
			}

			/* Update destination MAC for responding. */
			__builtin_memcpy(desc->eth_hdr->h_source, fib.dmac, ETH_ALEN);
			break;
		case BPF_FIB_LKUP_RET_FWD_DISABLED: /* Disabled forwarding on loopback. */
			return XDP_ABORTED;
		case BPF_FIB_LKUP_RET_NO_NEIGH: /* Use normal stack to obtain MAC. */
			return XDP_PASS;
		default:
			return XDP_DROP;
		}
	}

	/* Forward the packet to user space. */
	return bpf_redirect_map(&xsks_map, index, 0);
}

SEC("xdp")
int xdp_redirect_dns_func(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	const void *data_end = (void *)(long)ctx->data_end;

	const struct iphdr *ip4;
	const struct ipv6hdr *ip6;
	const void *l4_hdr;
	__u8 ip_proto;
	__u8 fragmented = 0;

	struct pkt_desc desc = {
		.eth_hdr = data
	};

	/* Parse Ethernet header. */
	if ((void *)desc.eth_hdr + sizeof(*desc.eth_hdr) > data_end) {
		return XDP_DROP;
	}
	data += sizeof(*desc.eth_hdr);
	desc.ip_hdr = data;

	/* Parse IPv4 or IPv6 header. */
	switch (desc.eth_hdr->h_proto) {
	case __constant_htons(ETH_P_IP):
		ip4 = desc.ip_hdr;
		if ((void *)ip4 + sizeof(*ip4) > data_end) {
			return XDP_DROP;
		}
		if (ip4->version != 4) {
			return XDP_DROP;
		}

		/* Check the IP length. Cannot use strict equality due to
		 * Ethernet padding applied to frames shorter than 64 octects. */
		if (data_end - data < __bpf_ntohs(ip4->tot_len)) {
			return XDP_DROP;
		}

		if (ip4->frag_off != 0 &&
		    ip4->frag_off != __constant_htons(IP_DF)) {
			fragmented = 1;
		}
		ip_proto = ip4->protocol;
		l4_hdr = data + ip4->ihl * 4;
		desc.ipv4 = 1;
		break;
	case __constant_htons(ETH_P_IPV6):
		ip6 = desc.ip_hdr;
		if ((void *)ip6 + sizeof(*ip6) > data_end) {
			return XDP_DROP;
		}
		if (ip6->version != 6) {
			return XDP_DROP;
		}

		/* Check the IP length. Cannot use strict equality due to
		 * Ethernet padding applied to frames shorter than 64 octects. */
		if (data_end - data < __bpf_ntohs(ip6->payload_len) + sizeof(*ip6)) {
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
		l4_hdr = data;
		break;
	default:
		/* Also applies to VLAN. */
		return XDP_PASS;
	}

	/* Get the queue options. */
	__u32 index = ctx->rx_queue_index;
	struct knot_xdp_opts *opts = bpf_map_lookup_elem(&opts_map, &index);
	if (!opts) {
		return XDP_ABORTED;
	}
	desc.opts = *opts;

	const struct tcphdr *tcp;
	const struct udphdr *udp;
	__u16 port_dest;
	__u8 match = 0;

	/* Check the transport protocol. */
	switch (ip_proto) {
	case IPPROTO_TCP:
		tcp = l4_hdr;

		/* Parse TCP header. */
		if (l4_hdr + sizeof(*tcp) > data_end) {
			return XDP_DROP;
		}

		port_dest = __bpf_ntohs(tcp->dest);

		if ((desc.opts.flags & KNOT_XDP_FILTER_TCP) &&
		    (port_dest == desc.opts.udp_port ||
		     ((desc.opts.flags & (KNOT_XDP_FILTER_PASS | KNOT_XDP_FILTER_DROP)) &&
		      port_dest >= desc.opts.udp_port))) {
			match = 1;
		}
		break;
	case IPPROTO_UDP:
		udp = l4_hdr;

		/* Parse UDP header. */
		if (l4_hdr + sizeof(*udp) > data_end) {
			return XDP_DROP;
		}

		/* Check the UDP length. */
		if (data_end - (void *)udp < __bpf_ntohs(udp->len)) {
			return XDP_DROP;
		}

		port_dest = __bpf_ntohs(udp->dest);

		if ((desc.opts.flags & KNOT_XDP_FILTER_UDP) &&
		    (port_dest == desc.opts.udp_port ||
		     ((desc.opts.flags & (KNOT_XDP_FILTER_PASS | KNOT_XDP_FILTER_DROP)) &&
		      port_dest >= desc.opts.udp_port))) {
			match = 1;
		} else if ((desc.opts.flags & KNOT_XDP_FILTER_QUIC) &&
		    (port_dest == desc.opts.quic_port ||
		     ((desc.opts.flags & (KNOT_XDP_FILTER_PASS | KNOT_XDP_FILTER_DROP)) &&
		      port_dest >= desc.opts.quic_port))) {
			match = 1;
		}
		break;
	default:
		/* Pass packets of possible other protocols. */
		return XDP_PASS;
	}

	if (!match) {
		/* Pass not-matching packet. */
		return XDP_PASS;
	} else if (desc.opts.flags & KNOT_XDP_FILTER_DROP) {
		/* Drop matching packet if requested. */
		return XDP_DROP;
	} else if (fragmented) {
		/* Drop fragmented packet. */
		return XDP_DROP;
	}

	return check_route(ctx, &desc);
}

char _license[] SEC("license") = "GPL";
