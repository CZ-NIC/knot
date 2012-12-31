/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "utils/host/host_exec.h"

#include <stdlib.h>			// free
#include <fcntl.h>			// fcntl
#include <netdb.h>			// addrinfo
#include <sys/socket.h>			// AF_INET (BSD)                        
#include <netinet/in.h>			// ntohl (BSD)
#include <sys/select.h>			// fd_set (BSD)

#include "common/lists.h"		// list
#include "common/errcode.h"		// KNOT_EOK
#include "libknot/util/wire.h"		// knot_wire_set_rd
#include "libknot/util/descriptor.h"	// KNOT_CLASS_IN
#include "libknot/packet/packet.h"	// packet_t
#include "libknot/packet/query.h"	// knot_query_init

#include "utils/common/msg.h"		// WARN
#include "utils/common/resolv.h"	// server_t
#include "utils/host/host_params.h"	// host_params_t

static bool use_tcp(const host_params_t *params, const uint16_t type)
{
	switch (params->protocol) {
	case PROTO_TCP:
		return true;
	case PROTO_UDP:
		if (type == KNOT_RRTYPE_AXFR || type == KNOT_RRTYPE_IXFR) {
			WARN("using UDP for zone transfer\n");
		}
		return false;
	default:
		if (type == KNOT_RRTYPE_AXFR || type == KNOT_RRTYPE_IXFR) {
			return true;
		} else {
			return false;
		}
	}
}

static bool use_recursion(const host_params_t *params, const uint16_t type)
{
	if (type == KNOT_RRTYPE_AXFR || type == KNOT_RRTYPE_IXFR) {
		return false;
	} else {
		if (params->recursion == true) {
			return true;
		} else {
			return false;
		}
	}
}

static knot_packet_t* create_query_packet(const host_params_t *params,
                                          const query_t       *query,
                                          uint8_t             **data,
                                          size_t              *data_len)
{
	knot_question_t q;

	// Create packet skeleton.
	knot_packet_t *packet = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);

	if (packet == NULL) {
		return NULL;
	}

	// Set packet buffer size.
	if (use_tcp(params, query->type) == true) {
		// For TCP maximal dns packet size.
		knot_packet_set_max_size(packet, MAX_PACKET_SIZE);
	} else {
		// For UDP default or specified EDNS size.
		knot_packet_set_max_size(packet, params->udp_size);
	}

	// Set random sequence id.
	knot_packet_set_random_id(packet);

	// Initialize query packet.
	knot_query_init(packet);

	// Set recursion bit to wireformat.
	if (use_recursion(params, query->type) == true) {
		knot_wire_set_rd(packet->wireformat);
	} else {
		knot_wire_flags_clear_rd(packet->wireformat);
	}

	// Fill auxiliary question structure.
	q.qclass = params->class_num;
	q.qtype = query->type;
	q.qname = knot_dname_new_from_str(query->name, strlen(query->name), 0);

	if (q.qname == NULL) {
		knot_dname_release(q.qname);
		knot_packet_free(&packet);
		return NULL;
	}

	// Set packet question.
	if (knot_query_set_question(packet, &q) != KNOT_EOK) {
		knot_dname_release(q.qname);
		knot_packet_free(&packet);
		return NULL;
	}

	// For IXFR query add authority section.
	if (query->type == KNOT_RRTYPE_IXFR) {
		int ret;
		size_t pos = 0;
		// SOA rdata in wireformat.
		uint8_t wire[22] = { 0x0 };
		// Set SOA serial.
		uint32_t serial = htonl(params->ixfr_serial);
		memcpy(wire + 2, &serial, sizeof(serial));

		// Create SOA rdata.
		knot_rdata_t *soa_data = knot_rdata_new();
		ret = knot_rdata_from_wire(soa_data,
		                           wire,
		                           &pos,
		                           sizeof(wire),
		                           sizeof(wire),
		                           knot_rrtype_descriptor_by_type(
		                                             KNOT_RRTYPE_SOA));

		if (ret != KNOT_EOK) {
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}

		// Create rrset with SOA record.
		knot_rrset_t *soa = knot_rrset_new(q.qname,
		                                   KNOT_RRTYPE_SOA,
		                                   params->class_num,
		                                   0);
		ret = knot_rrset_add_rdata(soa, soa_data);

		if (ret != KNOT_EOK) {
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}

		// Add authority section.
		ret = knot_query_add_rrset_authority(packet, soa);

		if (ret != KNOT_EOK) {
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}
	}

	// Create wire query.
	if (knot_packet_to_wire(packet, data, data_len) != KNOT_EOK) {
		ERR("can't create wire query packet\n");
		knot_dname_release(q.qname);
		knot_packet_free(&packet);
		return NULL;
	}

	knot_dname_release(q.qname);

	return packet;
}

static int send_query(const host_params_t *params,
                      const query_t       *query,
                      const server_t      *server,
                      const uint8_t       *data,
                      const size_t        data_len)
{
	struct addrinfo hints, *res;
	int sockfd;

	memset(&hints, 0, sizeof hints);

	// Set IP type.
	if (params->ip == IP_4) {
		hints.ai_family = AF_INET;
	} else if (params->ip == IP_6) {
		hints.ai_family = AF_INET6;
	} else {
		hints.ai_family = AF_UNSPEC;
	}

	// Set TCP or UDP.
	if (use_tcp(params, query->type) == true) {
		hints.ai_socktype = SOCK_STREAM;
	} else {
		hints.ai_socktype = SOCK_DGRAM;
	}

	// Get connection parameters.
	if (getaddrinfo(server->name, server->service, &hints, &res) != 0) {
		WARN("can't use nameserver %s port %s\n",
		     server->name, server->service);
		return -1;
	}

	// Create socket.
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	if (sockfd == -1) {
		WARN("can't create socket for nameserver %s port %s\n",
		     server->name, server->service);
		return -1;
	}

	// Set non-blocking socket.
	if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
		WARN("can't create non-blocking socket\n");
	}

	// Connect using socket.
	if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1 &&
	    errno != EINPROGRESS) {
		WARN("can't connect to nameserver %s port %s\n",
		     server->name, server->service);
		shutdown(sockfd, 2);
		return -1;
	}

	fd_set wfds;
	struct timeval tv;

	FD_ZERO(&wfds);
	FD_SET(sockfd, &wfds);

	tv.tv_sec = params->wait;
	tv.tv_usec = 0;

	// Check for connection timeout.
	if (select(sockfd + 1, NULL, &wfds, NULL, &tv) == -1 ||
	    !FD_ISSET(sockfd, &wfds)) {
		WARN("can't connect to nameserver %s port %s\n",
		     server->name, server->service);
		shutdown(sockfd, 2);
		return -1;
	}

	if (use_tcp(params, query->type) == true) {
		uint16_t pktsize = htons(data_len);

		if (send(sockfd, &pktsize, sizeof(pktsize), 0) !=
		    sizeof(pktsize)) {
			WARN("TCP packet leading lenght\n");
		}
	}

	if (send(sockfd, data, data_len, 0) != data_len) {
		WARN("can't send query\n");
	}

	return sockfd;
}

static int process_query(const host_params_t *params, const query_t *query)
{
	uint8_t *data = NULL;
	size_t data_len = 0;
	node *server = NULL;

	// Create query packet.
	knot_packet_t *packet = create_query_packet(params, query,
	                                            &data, &data_len);

	if (packet == NULL) {
		return KNOT_ERROR;
	}

	// Loop over nameserver list.
	WALK_LIST(server, params->servers) {
		server_t *srv = (server_t *)server;
		int sockfd;

		sockfd = send_query(params, query, srv, data, data_len);

		if (sockfd == -1) {
			continue;
		}

		shutdown(sockfd, 2);
	}

	// Drop query packet.
	knot_packet_free(&packet);

	return KNOT_EOK;
}

int host_exec(const host_params_t *params)
{
	node *query = NULL;

	if (params == NULL) {
		return KNOT_EINVAL;
	}

	switch (params->mode) {
	case HOST_MODE_DEFAULT:
		WALK_LIST(query, params->queries) {
			process_query(params, (query_t *)query);
		}

		break;
	case HOST_MODE_LIST_SERIALS:
		break;
	}

	return KNOT_EOK;
}
