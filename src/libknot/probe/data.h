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

/*!
 * \file
 *
 * \brief A DNS traffic probe data structure.
 *
 * \addtogroup probe
 * @{
 */

#pragma once

#include <stdint.h>

#include "libknot/consts.h"
#include "libknot/packet/pkt.h"

/*! EDE absence indication. */
#define KNOT_PROBE_DATA_EDE_NONE	0xFFFF

/*! Data transport protocol types. */
typedef enum {
	KNOT_PROBE_PROTO_UDP = 0,
	KNOT_PROBE_PROTO_TCP,
	KNOT_PROBE_PROTO_QUIC,
	KNOT_PROBE_PROTO_TLS,
	KNOT_PROBE_PROTO_HTTPS,
} knot_probe_proto_t;

/*! DNS message header in wire format (network byte order!). */
typedef struct {
	uint16_t id;
	uint8_t byte3; /*!< QR, OPCODE, AA, TC, RD. */
	uint8_t byte4; /*!< RA, Z, AD, CD, RCODE. */
	uint16_t questions;
	uint16_t answers;
	uint16_t authorities;
	uint16_t additionals;
} knot_probe_data_wire_hdr_t;

/*! Probe data unit. */
typedef struct {
	uint8_t ip;    /*!< IP protocol: 4 or 6. */
	uint8_t proto; /*!< Transport protocol \ref knot_probe_proto_t. */

	struct {
		uint8_t addr[16]; /*!< Query destination address. */
		uint16_t port;    /*!< Query destination port. */
	} local;

	struct {
		uint8_t addr[16]; /*!< Query source address. */
		uint16_t port;    /*!< Query source port. */
	} remote;

	struct {
		knot_probe_data_wire_hdr_t hdr; /*!< DNS reply header. */
		uint16_t size;  /*!< DNS reply size (0 if no reply). */
		uint16_t rcode; /*!< Final RCODE (header + EDNS + TSIG). */
		uint16_t ede;   /*!< EDE code if present. */
	} reply;

	uint32_t tcp_rtt; /*!< Average TCP RTT in microseconds. */

	struct {
		uint32_t options; /*!< EDNS options bit map (e.g. NSID ~ 1 << 3). */
		uint16_t payload; /*!< EDNS payload size. */
		uint8_t version;  /*!< EDNS version. */
		uint8_t present  : 1; /*!< EDNS presence indication. */
		uint8_t flag_do  : 1; /*!< DO flag indication. */
		uint8_t reserved : 6; /*!< Unused. */
	} query_edns;

	struct {
		knot_probe_data_wire_hdr_t hdr; /*!< DNS query header. */
		uint16_t size;     /*!< DNS query size. */
		uint16_t qclass;   /*!< QCLASS. */
		uint16_t qtype;    /*!< QTYPE. */
		uint8_t qname_len; /*!< QNAME length. */
		uint8_t qname[KNOT_DNAME_MAXLEN]; /*!< QNAME. */
	} query;
} knot_probe_data_t;

/*!
 * \brief Initializes a probe data unit.
 *
 * \note 'reply.ede' and 'tcp.rtt' are zeroed only and require further setting.
 *
 * \param data         Output probe data unit.
 * \param proto        Transport protocol \ref knot_probe_proto_t.
 * \param local_addr   Query destination address (optional).
 * \param remote_addr  Query source address.
 * \param query        Query packet.
 * \param reply        Reply packet (optional).
 * \param rcode        Extended rcode (combination of RCODE, EDNS, TSIG).
 *
 * \retval KNOT_EOK  Success.
 * \return KNOT_E*   If error.
 */
int knot_probe_data_set(knot_probe_data_t *data, knot_probe_proto_t proto,
                        const struct sockaddr_storage *local_addr,
                        const struct sockaddr_storage *remote_addr,
                        const knot_pkt_t *query, const knot_pkt_t *reply,
                        uint16_t rcode);

/*!
 * \brief Gets averate TCP RRT for a given socket descriptor.
 *
 * \note Implemented on Linux only!
 *
 * \param sockfd  Socket descriptor of a TCP connection.
 *
 * \return Average TCP RTT in microseconds.
 */
uint32_t knot_probe_tcp_rtt(int sockfd);

/*! @} */
