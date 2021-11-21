/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <string.h>

#include "libknot/endian.h"
#include "libknot/xdp/msg.h"

/* Don't fragment flag. */
#define	IP_DF 0x4000

/*
 * Following prot_read_*() functions do not check sanity of parsed packet.
 * Broken packets have to be dropped by BPF filter prior getting here.
 */

inline static void *prot_read_udp(void *data, uint16_t *src_port, uint16_t *dst_port)
{
	const struct udphdr *udp = data;

	*src_port = udp->source;
	*dst_port = udp->dest;

	return data + sizeof(*udp);
}

enum {
	PROT_TCP_OPT_ENDOP = 0,
	PROT_TCP_OPT_NOOP  = 1,
	PROT_TCP_OPT_MSS   = 2,
	PROT_TCP_OPT_WSC   = 3, // window scale

	PROT_TCP_OPT_LEN_MSS = 4,
	PROT_TCP_OPT_LEN_WSC = 3,
};

inline static void *prot_read_tcp(void *data, knot_xdp_msg_t *msg, uint16_t *src_port, uint16_t *dst_port)
{
	const struct tcphdr *tcp = data;

	msg->flags |= KNOT_XDP_MSG_TCP;

	if (tcp->syn) {
		msg->flags |= KNOT_XDP_MSG_SYN;
	}
	if (tcp->ack) {
		msg->flags |= KNOT_XDP_MSG_ACK;
	}
	if (tcp->fin) {
		msg->flags |= KNOT_XDP_MSG_FIN;
	}
	if (tcp->rst) {
		msg->flags |= KNOT_XDP_MSG_RST;
	}

	msg->seqno = be32toh(tcp->seq);
	msg->ackno = be32toh(tcp->ack_seq);

	*src_port = tcp->source;
	*dst_port = tcp->dest;

	uint8_t *opts = data + sizeof(*tcp), *hdr_end = data + tcp->doff * 4;
	while (opts < hdr_end) {
		if (opts[0] == PROT_TCP_OPT_ENDOP || opts[0] == PROT_TCP_OPT_NOOP) {
			opts++;
			continue;
		}

		if (opts + 1 > hdr_end || opts + opts[1] > hdr_end) {
			// Malformed option.
			break;
		}

		if (opts[0] == PROT_TCP_OPT_MSS && opts[1] == PROT_TCP_OPT_LEN_MSS) {
			msg->flags |= KNOT_XDP_MSG_MSS;
			memcpy(&msg->mss, &opts[2], sizeof(msg->mss));
			msg->mss = be16toh(msg->mss);
		}

		opts += opts[1];
	}

	return hdr_end;
}

inline static void *prot_read_ipv4(void *data, knot_xdp_msg_t *msg, void **data_end)
{
	const struct iphdr *ip4 = data;

	// Conditions ensured by the BPF filter.
	assert(ip4->version == 4);
	assert(ip4->frag_off == 0 || ip4->frag_off == __constant_htons(IP_DF));
	// IPv4 header checksum is not verified!

	struct sockaddr_in *src = (struct sockaddr_in *)&msg->ip_from;
	struct sockaddr_in *dst = (struct sockaddr_in *)&msg->ip_to;
	memcpy(&src->sin_addr, &ip4->saddr, sizeof(src->sin_addr));
	memcpy(&dst->sin_addr, &ip4->daddr, sizeof(dst->sin_addr));
	src->sin_family = AF_INET;
	dst->sin_family = AF_INET;

	*data_end = data + be16toh(ip4->tot_len);
	data += ip4->ihl * 4;

	if (ip4->protocol == IPPROTO_TCP) {
		return prot_read_tcp(data, msg, &src->sin_port, &dst->sin_port);
	} else {
		assert(ip4->protocol == IPPROTO_UDP);
		return prot_read_udp(data, &src->sin_port, &dst->sin_port);
	}
}

inline static void *prot_read_ipv6(void *data, knot_xdp_msg_t *msg, void **data_end)
{
	const struct ipv6hdr *ip6 = data;

	msg->flags |= KNOT_XDP_MSG_IPV6;

	// Conditions ensured by the BPF filter.
	assert(ip6->version == 6);

	struct sockaddr_in6 *src = (struct sockaddr_in6 *)&msg->ip_from;
	struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&msg->ip_to;
	memcpy(&src->sin6_addr, &ip6->saddr, sizeof(src->sin6_addr));
	memcpy(&dst->sin6_addr, &ip6->daddr, sizeof(dst->sin6_addr));
	src->sin6_family = AF_INET6;
	dst->sin6_family = AF_INET6;
	src->sin6_flowinfo = 0;
	dst->sin6_flowinfo = 0;
	// Scope ID is ignored.

	data += sizeof(*ip6);
	*data_end = data + be16toh(ip6->payload_len);

	if (ip6->nexthdr == IPPROTO_TCP) {
		return prot_read_tcp(data, msg, &src->sin6_port, &dst->sin6_port);
	} else {
		assert(ip6->nexthdr == IPPROTO_UDP);
		return prot_read_udp(data, &src->sin6_port, &dst->sin6_port);
	}
}

inline static void *prot_read_eth(void *data, knot_xdp_msg_t *msg, void **data_end)
{
	const struct ethhdr *eth = data;

	memcpy(msg->eth_from, eth->h_source, ETH_ALEN);
	memcpy(msg->eth_to,   eth->h_dest,   ETH_ALEN);
	msg->flags = 0;

	data += sizeof(*eth);

	if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
		return prot_read_ipv6(data, msg, data_end);
	} else {
		assert(eth->h_proto == __constant_htons(ETH_P_IP));
		return prot_read_ipv4(data, msg, data_end);
	}
}

inline static size_t prot_write_hdrs_len(const knot_xdp_msg_t *msg)
{
	size_t res = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (msg->flags & KNOT_XDP_MSG_IPV6) {
		res += sizeof(struct ipv6hdr) - sizeof(struct iphdr);
	}

	if (msg->flags & KNOT_XDP_MSG_TCP) {
		res += sizeof(struct tcphdr) - sizeof(struct udphdr) + 4; // 4 == PROT_TCP_OPT_LEN_WSC + align

		if (msg->flags & KNOT_XDP_MSG_MSS) {
			res += PROT_TCP_OPT_LEN_MSS;
		}
	}

	return res;
}

/* Checksum endianness implementation notes for ipv4_checksum() and checksum().
 *
 * The basis for checksum is addition on big-endian 16-bit words, with bit 16 carrying
 * over to bit 0.  That can be viewed as first byte carrying to the second and the
 * second one carrying back to the first one, i.e. a symmetrical situation.
 * Therefore the result is the same even when arithmetics is done on little-endian (!)
 */

inline static void checksum(uint32_t *result, const void *_data, uint32_t _data_len)
{
	assert(!(_data_len & 1));
	const uint16_t *data = _data;
	uint32_t len = _data_len / 2;
	while (len-- > 0) {
		*result += *data++;
	}
}

inline static void checksum_uint16(uint32_t *result, uint16_t x)
{
	checksum(result, &x, sizeof(x));
}

inline static void checksum_payload(uint32_t *result, void *payload, size_t pay_len)
{
	if (pay_len & 1) {
		((uint8_t *)payload)[pay_len++] = 0;
	}
	checksum(result, payload, pay_len);
}

inline static uint16_t checksum_finish(uint32_t result, bool nonzero)
{
	while (result > 0xffff) {
		result = (result & 0xffff) + (result >> 16);
	}
	if (!nonzero || result != 0xffff) {
		result = ~result;
	}
	return result;
}

inline static void prot_write_udp(void *data, const knot_xdp_msg_t *msg, void *data_end,
                                  uint16_t src_port, uint16_t dst_port, uint32_t chksum)
{
	struct udphdr *udp = data;

	udp->len    = htobe16(data_end - data);
	udp->source = src_port;
	udp->dest   = dst_port;

	if (msg->flags & KNOT_XDP_MSG_IPV6) {
		udp->check = 0;
		checksum(&chksum, &udp->len, sizeof(udp->len));
		checksum_uint16(&chksum, htobe16(IPPROTO_UDP));
		checksum_payload(&chksum, data, data_end - data);
		udp->check = checksum_finish(chksum, true);
	} else {
		udp->check = 0; // UDP over IPv4 doesn't require checksum.
	}

	assert(data + sizeof(*udp) == msg->payload.iov_base);
}

inline static void prot_write_tcp(void *data, const knot_xdp_msg_t *msg, void *data_end,
                                  uint16_t src_port, uint16_t dst_port, uint32_t chksum,
                                  uint16_t mss)
{
	struct tcphdr *tcp = data;

	tcp->source  = src_port;
	tcp->dest    = dst_port;
	tcp->seq     = htobe32(msg->seqno);
	tcp->ack_seq = htobe32(msg->ackno);
	tcp->window  = htobe16(0xffff); // Practically infinite window (see also WSC option below)
	tcp->check   = 0; // Temporarily initialize before checksum calculation.

	tcp->syn = ((msg->flags & KNOT_XDP_MSG_SYN) ? 1 : 0);
	tcp->ack = ((msg->flags & KNOT_XDP_MSG_ACK) ? 1 : 0);
	tcp->fin = ((msg->flags & KNOT_XDP_MSG_FIN) ? 1 : 0);
	tcp->rst = ((msg->flags & KNOT_XDP_MSG_RST) ? 1 : 0);

	uint8_t *hdr_end = data + sizeof(*tcp);
	hdr_end[0] = PROT_TCP_OPT_WSC;
	hdr_end[1] = PROT_TCP_OPT_LEN_WSC;
	hdr_end[2] = 14; // Maximum possible.
	hdr_end += PROT_TCP_OPT_LEN_WSC;
	*hdr_end++ = PROT_TCP_OPT_NOOP;
	if (msg->flags & KNOT_XDP_MSG_MSS) {
		mss = htobe16(mss);
		hdr_end[0] = PROT_TCP_OPT_MSS;
		hdr_end[1] = PROT_TCP_OPT_LEN_MSS;
		memcpy(&hdr_end[2], &mss, sizeof(mss));
		hdr_end += PROT_TCP_OPT_LEN_MSS;
	}

	tcp->psh = ((data_end - (void *)hdr_end > 0) ? 1 : 0);
	tcp->doff = (hdr_end - (uint8_t *)tcp) / 4;
	assert((hdr_end - (uint8_t *)tcp) % 4 == 0);

	checksum_uint16(&chksum, htobe16(IPPROTO_TCP));
	checksum_uint16(&chksum, htobe16(data_end - data));
	checksum_payload(&chksum, data, data_end - data);
	tcp->check = checksum_finish(chksum, false);

	assert(hdr_end == msg->payload.iov_base);
}

inline static uint16_t from32to16(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

inline static uint16_t ipv4_checksum(const uint16_t *ipv4_hdr)
{
	uint32_t sum32 = 0;
	for (int i = 0; i < 10; ++i) {
		if (i != 5) {
			sum32 += ipv4_hdr[i];
		}
	}
	return ~from32to16(sum32);
}

inline static void prot_write_ipv4(void *data, const knot_xdp_msg_t *msg,
                                   void *data_end, uint16_t tcp_mss)
{
	struct iphdr *ip4 = data;

	ip4->version  = 4;
	ip4->ihl      = sizeof(*ip4) / 4;
	ip4->tos      = 0;
	ip4->tot_len  = htobe16(data_end - data);
	ip4->id       = 0;
	ip4->frag_off = 0;
	ip4->ttl      = IPDEFTTL;
	ip4->protocol = ((msg->flags & KNOT_XDP_MSG_TCP) ? IPPROTO_TCP : IPPROTO_UDP);

	const struct sockaddr_in *src = (const struct sockaddr_in *)&msg->ip_from;
	const struct sockaddr_in *dst = (const struct sockaddr_in *)&msg->ip_to;
	memcpy(&ip4->saddr, &src->sin_addr, sizeof(src->sin_addr));
	memcpy(&ip4->daddr, &dst->sin_addr, sizeof(dst->sin_addr));

	ip4->check = ipv4_checksum(data);

	data += sizeof(*ip4);

	if (msg->flags & KNOT_XDP_MSG_TCP) {
		uint32_t chk = 0;
		checksum(&chk, &src->sin_addr, sizeof(src->sin_addr));
		checksum(&chk, &dst->sin_addr, sizeof(dst->sin_addr));

		prot_write_tcp(data, msg, data_end, src->sin_port, dst->sin_port, chk, tcp_mss);
	} else {
		prot_write_udp(data, msg, data_end, src->sin_port, dst->sin_port, 0); // IPv4/UDP requires no checksum
	}
}

inline static void prot_write_ipv6(void *data, const knot_xdp_msg_t *msg,
                                   void *data_end, uint16_t tcp_mss)
{
	struct ipv6hdr *ip6 = data;

	ip6->version     = 6;
	ip6->priority    = 0;
	ip6->payload_len = htobe16(data_end - data - sizeof(*ip6));
	ip6->nexthdr     = ((msg->flags & KNOT_XDP_MSG_TCP) ? IPPROTO_TCP : IPPROTO_UDP);
	ip6->hop_limit   = IPDEFTTL;

	memset(ip6->flow_lbl, 0, sizeof(ip6->flow_lbl));

	const struct sockaddr_in6 *src = (const struct sockaddr_in6 *)&msg->ip_from;
	const struct sockaddr_in6 *dst = (const struct sockaddr_in6 *)&msg->ip_to;
	memcpy(&ip6->saddr, &src->sin6_addr, sizeof(src->sin6_addr));
	memcpy(&ip6->daddr, &dst->sin6_addr, sizeof(dst->sin6_addr));

	data += sizeof(*ip6);

	uint32_t chk = 0;
	checksum(&chk, &src->sin6_addr, sizeof(src->sin6_addr));
	checksum(&chk, &dst->sin6_addr, sizeof(dst->sin6_addr));

	if (msg->flags & KNOT_XDP_MSG_TCP) {
		prot_write_tcp(data, msg, data_end, src->sin6_port, dst->sin6_port, chk, tcp_mss);
	} else {
		prot_write_udp(data, msg, data_end, src->sin6_port, dst->sin6_port, chk);
	}
}

inline static void prot_write_eth(void *data, const knot_xdp_msg_t *msg,
                                  void *data_end, uint16_t tcp_mss)
{
	struct ethhdr *eth = data;

	memcpy(eth->h_source, msg->eth_from, ETH_ALEN);
	memcpy(eth->h_dest,   msg->eth_to,   ETH_ALEN);

	data += sizeof(*eth);

	if (msg->flags & KNOT_XDP_MSG_IPV6) {
		eth->h_proto = __constant_htons(ETH_P_IPV6);
		prot_write_ipv6(data, msg, data_end, tcp_mss);
	} else {
		eth->h_proto = __constant_htons(ETH_P_IP);
		prot_write_ipv4(data, msg, data_end, tcp_mss);
	}
}
