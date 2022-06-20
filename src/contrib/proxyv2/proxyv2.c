/*  Copyright (C) 2021 Fastly, Inc.

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

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include "contrib/proxyv2/proxyv2.h"
#include "contrib/sockaddr.h"
#include "libknot/errcode.h"

/*
 * Minimal implementation of the haproxy PROXY v2 protocol.
 *
 * Supports extracting the original client address and client port number from
 * the haproxy PROXY v2 protocol's address block.
 *
 * See https://www.haproxy.org/download/2.5/doc/proxy-protocol.txt for the
 * protocol specification.
 */

static const char PROXYV2_SIG[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

/*
 * The part of the PROXY v2 payload following the signature.
 */
struct proxyv2_hdr {
	/*
	 * The protocol version and command.
	 *
	 * The upper four bits contain the version which must be \x2 and the
	 * receiver must only accept this value.
	 *
	 * The lower four bits represent the command, which is \x0 for LOCAL
	 * and \x1 for PROXY.
	 */
	uint8_t		ver_cmd;

	/*
	 * The transport protocol and address family. The upper four bits
	 * contain the address family and the lower four bits contain the
	 * protocol.
	 *
	 * The relevant values for DNS are:
	 *	\x11: TCP over IPv4
	 *	\x12: UDP over IPv4
	 *	\x21: TCP over IPv6
	 *	\x22: UDP over IPv6
	 */
	uint8_t		fam_addr;

	/*
	 * The number of PROXY v2 payload bytes following this header to skip
	 * to reach the proxied packet (i.e., start of the original DNS message).
	 */
	uint16_t	len;
};

/*
 * The PROXY v2 address block for IPv4.
 */
struct proxyv2_addr_ipv4 {
	uint8_t		src_addr[4];
	uint8_t		dst_addr[4];
	uint16_t	src_port;
	uint16_t	dst_port;
};

/*
 * The PROXY v2 address block for IPv6.
 */
struct proxyv2_addr_ipv6 {
	uint8_t		src_addr[16];
	uint8_t		dst_addr[16];
	uint16_t	src_port;
	uint16_t	dst_port;
};

/*
 * Make sure the C compiler lays out the PROXY v2 address block structs so that
 * they can be memcpy()'d off the wire.
 */
#if (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct proxyv2_hdr) == 4,
	       "struct proxyv2_hdr is correct size");
_Static_assert(sizeof(struct proxyv2_addr_ipv4) == 12,
	       "struct proxyv2_addr_ipv4 is correct size");
_Static_assert(sizeof(struct proxyv2_addr_ipv6) == 36,
	       "struct proxyv2_addr_ipv6 is correct size");
#endif

int proxyv2_header_offset(void *base, size_t len_base)
{
	/*
	 * Check that 'base' has enough bytes to read the PROXY v2 signature
	 * and header, and if so whether the PROXY v2 signature is present.
	 */
	if (len_base < (sizeof(PROXYV2_SIG) + sizeof(struct proxyv2_hdr)) ||
	    memcmp(base, PROXYV2_SIG, sizeof(PROXYV2_SIG)) != 0)
	{
		/* Failure. */
		return KNOT_EMALF;
	}

	/* Read the PROXY v2 header. */
	struct proxyv2_hdr *hdr = base + sizeof(PROXYV2_SIG);

	/*
	 * Check that this is a version 2, command "PROXY" payload.
	 *
	 * XXX: The PROXY v2 spec mandates support for the "LOCAL" command
	 * (byte 0x20).
	 */
	if (hdr->ver_cmd != 0x21) {
		/* Failure. */
		return KNOT_EMALF;
	}

	/*
	 * Calculate the offset of the original DNS message inside the packet.
	 * This needs to account for the length of the PROXY v2 signature,
	 * PROXY v2 header, and the bytes of variable length PROXY v2 data
	 * following the PROXY v2 header.
	 */
	const size_t offset_dns = sizeof(PROXYV2_SIG) +
	                          sizeof(struct proxyv2_hdr) + ntohs(hdr->len);
	if (offset_dns < len_base) {
		return offset_dns;
	}

	return KNOT_EMALF;
}

int proxyv2_addr_store(void *base, size_t len_base, struct sockaddr_storage *ss)
{
	/*
	 * Calculate the offset of the PROXY v2 address block. This is the data
	 * immediately following the PROXY v2 header.
	 */
	const size_t offset_proxy_addr = sizeof(PROXYV2_SIG) +
	                                 sizeof(struct proxyv2_hdr);
	struct proxyv2_hdr *hdr = base + sizeof(PROXYV2_SIG);

	/*
	 * Handle proxied UDP-over-IPv4 and UDP-over-IPv6 packets.
	 */
	//TODO What about TCP?
	if (hdr->fam_addr == 0x12) {
		/* This is a proxied UDP-over-IPv4 packet. */
		struct proxyv2_addr_ipv4 *addr;

		/*
		 * Check that the packet is large enough to contain the IPv4
		 * address block.
		 */
		if (offset_proxy_addr + sizeof(addr) < len_base) {
			/* Read the PROXY v2 address block. */
			addr = base + offset_proxy_addr;

			/* Copy the client's IPv4 address to the caller. */
			sockaddr_set_raw(ss, AF_INET, addr->src_addr,
					 sizeof(addr->src_addr));

			/* Copy the client's port to the caller. */
			sockaddr_port_set(ss, ntohs(addr->src_port));

			/* Success. */
			return KNOT_EOK;
		}
	} else if (hdr->fam_addr == 0x22) {
		/* This is a proxied UDP-over-IPv6 packet. */
		struct proxyv2_addr_ipv6 *addr;

		/*
		 * Check that the packet is large enough to contain the IPv6
		 * address block.
		 */
		if (offset_proxy_addr + sizeof(addr) < len_base) {
			/* Read the PROXY v2 address block. */
			addr = base + offset_proxy_addr;

			/* Copy the client's IPv6 address to the caller. */
			sockaddr_set_raw(ss, AF_INET6, addr->src_addr,
					 sizeof(addr->src_addr));

			/* Copy the client's port to the caller. */
			sockaddr_port_set(ss, ntohs(addr->src_port));

			/* Success. */
			return KNOT_EOK;
		}
	}

	/* Failure. */
	return KNOT_EMALF;
}
