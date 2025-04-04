/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf-consts.h"

/* Don't fragment flag. */
#define	IP_DF		0x4000

#define AF_INET		2
#define AF_INET6	10

/* Define maximum reasonable number of NIC queues supported. */
#define QUEUE_MAX	256

/* Define maximum number of allowed IPv6 headers. */
#define IPV6_HDR_MAX	3

/* DNS header size. */
#define DNS_HDR_SIZE	12

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

SEC("xdp")
int xdp_redirect_dns_func(struct xdp_md *ctx)
{
	/* Get the queue options. */
	__u32 index = ctx->rx_queue_index;
	struct knot_xdp_opts *opts_ptr = bpf_map_lookup_elem(&opts_map, &index);
	if (!opts_ptr) {
		return XDP_ABORTED;
	}
	knot_xdp_opts_t opts = *opts_ptr;

	/* Check if the filter is disabled. */
	if (!(opts.flags & KNOT_XDP_FILTER_ON)) {
		return XDP_PASS;
	}

	/* Try to reserve space in front of the packet for additional (VLAN) data. */
	(void)bpf_xdp_adjust_meta(ctx, - (int)sizeof(struct knot_xdp_info)
	                               - KNOT_XDP_PKT_ALIGNMENT);

	void *data = (void *)(long)ctx->data;
	const void *data_end = (void *)(long)ctx->data_end;
	struct knot_xdp_info *meta = (void *)(long)ctx->data_meta;

	/* Check if the meta data pointer is usable (e.g. not `tap` interface). */
	if ((void *)meta + sizeof(*meta) > data) {
		meta = 0;
	}

	struct ethhdr *eth_hdr = data;
	const void *ip_hdr;
	const struct iphdr *ip4;
	const struct ipv6hdr *ip6;
	__u16 ip_len;
	__u8 ipv4;
	__u8 ip_proto;
	__u8 fragmented = 0; /* Fragmented or IPv6 packet with a header extension. */
	__u16 eth_type; /* In big endian. */

	/* Parse Ethernet header. */
	if ((void *)eth_hdr + sizeof(*eth_hdr) > data_end) {
		return XDP_DROP;
	}
	data += sizeof(*eth_hdr);

	/* Parse possible VLAN (802.1Q) header. */
	if (eth_hdr->h_proto == bpf_htons(ETH_P_8021Q)) {
		if (data + sizeof(__u16) + sizeof(eth_type) > data_end) {
			return XDP_DROP;
		} else if (meta == 0) { /* VLAN not supported. */
			return XDP_PASS;
		}
		__builtin_memcpy(&eth_type, data + sizeof(__u16), sizeof(eth_type));
		data += sizeof(__u16) + sizeof(eth_type);
	} else {
		eth_type = eth_hdr->h_proto;
	}
	ip_hdr = data;

	/* Parse IPv4 or IPv6 header. */
	switch (eth_type) {
	case bpf_htons(ETH_P_IP):
		ip4 = data;
		if ((void *)ip4 + sizeof(*ip4) > data_end) {
			return XDP_DROP;
		}
		if (ip4->version != 4) {
			return XDP_DROP;
		}

		/* Check the IP length. Cannot use strict equality due to
		 * Ethernet padding applied to frames shorter than 64 octects. */
		ip_len = bpf_ntohs(ip4->tot_len);
		if (data_end - data < ip_len) {
			return XDP_DROP;
		}

		if (ip4->frag_off != 0 &&
		    ip4->frag_off != bpf_htons(IP_DF)) {
			fragmented = 1;
		}
		ip_proto = ip4->protocol;
		data += ip4->ihl * 4;
		ipv4 = 1;
		break;
	case bpf_htons(ETH_P_IPV6):
		ip6 = data;
		if ((void *)ip6 + sizeof(*ip6) > data_end) {
			return XDP_DROP;
		}
		if (ip6->version != 6) {
			return XDP_DROP;
		}

		/* Check the IP length. Cannot use strict equality due to
		 * Ethernet padding applied to frames shorter than 64 octects. */
		ip_len = sizeof(*ip6) + bpf_ntohs(ip6->payload_len);
		if (data_end - data < ip_len) {
			return XDP_DROP;
		}

		for (int i = 0; i <= IPV6_HDR_MAX; i++) {
			if (i == IPV6_HDR_MAX) {
				return XDP_DROP;
			}
			const struct ipv6_opt_hdr *ext_hdr = (void *)&ip6->nexthdr;
			if ((void *)ext_hdr + sizeof(*ext_hdr) > data_end) {
				return XDP_DROP;
			}
			ip_proto = ext_hdr->nexthdr;

			switch (ip_proto) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
			case IPPROTO_MH:
			case 139: /* HIP */
			case 140: /* Shim6 */
				fragmented = 1;
				data += (ext_hdr->hdrlen + 1) * 8;
				break;
			case IPPROTO_AH:
				fragmented = 1;
				data += (ext_hdr->hdrlen + 2) * 4;
				break;
			case IPPROTO_FRAGMENT:
				fragmented = 1;
				data += 8;
				break;
			case IPPROTO_NONE:
			case 253: /* Reserved */
			case 254: /* Reserved */
				return XDP_DROP;
			case IPPROTO_ESP: /* IPsec, different header format, stop. */
			default: /* Not an IPv6 extension header, stop. */
				i = IPV6_HDR_MAX + 1;
			}
			ip6 = data;
		}
		data += sizeof(*ip6);
		ipv4 = 0;
		break;
	default:
		/* Pass packets of possible other protocols. */
		return XDP_PASS;
	}

	const struct tcphdr *tcp;
	const struct udphdr *udp;
	__u16 port_dest;
	__u8 match = 0;

	/* Check the transport protocol. */
	switch (ip_proto) {
	case IPPROTO_TCP:
		/* Parse TCP header. */
		tcp = data;
		if ((void *)tcp + sizeof(*tcp) > data_end) {
			return XDP_DROP;
		}

		port_dest = bpf_ntohs(tcp->dest);

		if ((opts.flags & KNOT_XDP_FILTER_TCP) &&
		    (port_dest == opts.udp_port ||
		     ((opts.flags & (KNOT_XDP_FILTER_PASS | KNOT_XDP_FILTER_DROP)) &&
		      port_dest >= opts.udp_port))) {
			match = 1;
		}
		break;
	case IPPROTO_UDP:
		/* Parse UDP header. */
		udp = data;
		if ((void *)udp + sizeof(*udp) > data_end) {
			return XDP_DROP;
		}

		/* Check if the UDP length matches the IP payload length. */
		if ((void *)udp - ip_hdr != ip_len - bpf_ntohs(udp->len)) {
			return XDP_DROP;
		}

		port_dest = bpf_ntohs(udp->dest);

		if ((opts.flags & KNOT_XDP_FILTER_UDP) &&
		    (port_dest == opts.udp_port ||
		     ((opts.flags & (KNOT_XDP_FILTER_PASS | KNOT_XDP_FILTER_DROP)) &&
		      port_dest >= opts.udp_port))) {
			/* Check for minimum DNS message content. */
			if (bpf_ntohs(udp->len) - sizeof(*udp) < DNS_HDR_SIZE) {
				return XDP_DROP;
			}
			match = 1;
		} else if ((opts.flags & KNOT_XDP_FILTER_QUIC) &&
		    (port_dest == opts.quic_port ||
		     ((opts.flags & (KNOT_XDP_FILTER_PASS | KNOT_XDP_FILTER_DROP)) &&
		      port_dest >= opts.quic_port))) {
			match = 1;
		}
		break;
	default:
		/* Pass packets of possible other protocols. */
		return XDP_PASS;
	}

	if (!match) {
		/* Pass non-matching packet. */
		return XDP_PASS;
	} else if (opts.flags & KNOT_XDP_FILTER_DROP) {
		/* Drop matching packet if requested. */
		return XDP_DROP;
	} else if (fragmented) {
		/* Drop fragmented/extended DNS-related (UDP, TCP, QUIC) packet. */
		return XDP_DROP;
	}

	/* Take into account routing information. */
	if (opts.flags & KNOT_XDP_FILTER_ROUTE) {
		struct bpf_fib_lookup fib = {
			.ifindex = 1 /* Loopback. */
		};
		if (ipv4) {
			fib.family   = AF_INET;
			fib.ipv4_src = ip4->daddr;
			fib.ipv4_dst = ip4->saddr;
		} else {
			struct in6_addr *ipv6_src = (struct in6_addr *)fib.ipv6_src;
			struct in6_addr *ipv6_dst = (struct in6_addr *)fib.ipv6_dst;
			fib.family = AF_INET6;
			*ipv6_src  = ip6->daddr;
			*ipv6_dst  = ip6->saddr;
		}

		const __u16 *mac_in = (const __u16 *)eth_hdr->h_dest;
		const __u16 *mac_out = (const __u16 *)fib.smac;
		int ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
		switch (ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
			/* Cross-interface answers are handled through normal stack. */
			if (mac_in[0] != mac_out[0] ||
			    mac_in[1] != mac_out[1] ||
			    mac_in[2] != mac_out[2]) {
				return XDP_PASS;
			}

			/* Store output interface index for later use with VLAN in user space. */
			if (meta != 0) {
				meta->out_if_index = fib.ifindex;
			}

			/* Update destination MAC for responding. */
			__builtin_memcpy(eth_hdr->h_source, fib.dmac, ETH_ALEN);
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
	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";
