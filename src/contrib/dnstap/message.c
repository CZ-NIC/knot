/*  Copyright (C) 2014 Farsight Security, Inc. <software@farsightsecurity.com>

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

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/errcode.h"

#include "contrib/dnstap/convert.h"
#include "contrib/dnstap/message.h"

static void set_address(const struct sockaddr *sockaddr,
                        ProtobufCBinaryData   *addr,
                        protobuf_c_boolean    *has_addr,
                        uint32_t              *port,
                        protobuf_c_boolean    *has_port)
{
	if (sockaddr == NULL) {
		*has_addr = 0;
		*has_port = 0;
		return;
	}

	*has_addr = 1;
	*has_port = 1;

	if (sockaddr->sa_family == AF_INET) {
		const struct sockaddr_in *sai;
		sai = (const struct sockaddr_in *)sockaddr;
		addr->len = sizeof(sai->sin_addr);
		addr->data = (uint8_t *)&sai->sin_addr.s_addr;
		*port = ntohs(sai->sin_port);
	} else if (sockaddr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sai6;
		sai6 = (const struct sockaddr_in6 *)sockaddr;
		addr->len = sizeof(sai6->sin6_addr);
		addr->data = (uint8_t *)&sai6->sin6_addr.s6_addr;
		*port = ntohs(sai6->sin6_port);
	}
}

static int get_family(const struct sockaddr *query_sa,
	              const struct sockaddr *response_sa)
{
	const struct sockaddr *source = query_sa ? query_sa : response_sa;
	if (source == NULL) {
		return 0;
	}

	return dt_family_encode(source->sa_family);
}

int dt_message_fill(Dnstap__Message             *m,
                    const Dnstap__Message__Type type,
                    const struct sockaddr       *query_sa,
                    const struct sockaddr       *response_sa,
                    const int                   protocol,
                    const void                  *wire,
                    const size_t                len_wire,
                    const struct timeval        *qtime,
                    const struct timeval        *rtime)
{
	if (m == NULL) {
		return KNOT_EINVAL;
	}

	memset(m, 0, sizeof(*m));

	m->base.descriptor = &dnstap__message__descriptor;

	// Message.type
	m->type = type;

	// Message.socket_family
	m->socket_family = get_family(query_sa, response_sa);
	m->has_socket_family = m->socket_family != 0;

	// Message.socket_protocol
	m->socket_protocol = dt_protocol_encode(protocol);
	m->has_socket_protocol = m->socket_protocol != 0;

	// Message addresses
	set_address(query_sa, &m->query_address, &m->has_query_address,
	            &m->query_port, &m->has_query_port);
	set_address(response_sa, &m->response_address, &m->has_response_address,
	            &m->response_port, &m->has_response_port);

	if (dt_message_type_is_query(type)) {
		// Message.query_message
		m->query_message.len = len_wire;
		m->query_message.data = (uint8_t *)wire;
		m->has_query_message = 1;
	} else if (dt_message_type_is_response(type)) {
		// Message.response_message
		m->response_message.len = len_wire;
		m->response_message.data = (uint8_t *)wire;
		m->has_response_message = 1;
	}

	// Message.query_time_sec, Message.query_time_nsec
	if (qtime != NULL) {
		m->query_time_sec = qtime->tv_sec;
		m->query_time_nsec = qtime->tv_usec * 1000;
		m->has_query_time_sec = 1;
		m->has_query_time_nsec = 1;
	}

	// Message.response_time_sec, Message.response_time_nsec
	if (rtime != NULL) {
		m->response_time_sec = rtime->tv_sec;
		m->response_time_nsec = rtime->tv_usec * 1000;
		m->has_response_time_sec = 1;
		m->has_response_time_nsec = 1;
	}

	return KNOT_EOK;
}
