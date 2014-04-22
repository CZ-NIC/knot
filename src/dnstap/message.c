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

#include <netinet/in.h>                 // sockaddr_in
#include <stdint.h>
#include <stdlib.h>
#include <string.h>                     // memset

#include "common/errcode.h"

#include "dnstap/message.h"

int dt_message_fill(Dnstap__Message *m,
                    const Dnstap__Message__Type type,
                    const struct sockaddr *response_sa,
                    const int protocol,
                    const void *wire,
                    const size_t len_wire,
                    const struct timeval *qtime,
                    const struct timeval *rtime)
{
	memset(m, 0, sizeof(*m));
	m->base.descriptor = &dnstap__message__descriptor;

	if (type != DNSTAP__MESSAGE__TYPE__TOOL_QUERY &&
	    type != DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE)
	{
		return KNOT_EINVAL;
	}

	// Message.type
	m->type = type;

	if (response_sa->sa_family == AF_INET) {
		const struct sockaddr_in *sai =
			(const struct sockaddr_in *)response_sa;

		// Message.socket_family
		m->has_socket_family = 1;
		m->socket_family = DNSTAP__SOCKET_FAMILY__INET;

		// Message.response_address
		m->response_address.len = 4;
		m->response_address.data = (uint8_t *)
			&sai->sin_addr.s_addr;
		m->has_response_address = 1;

		// Message.response_port
		m->has_response_port = 1;
		m->response_port = ntohs(sai->sin_port);
	} else if (response_sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sai6 =
			(const struct sockaddr_in6 *)response_sa;

		// Message.socket_family
		m->socket_family = DNSTAP__SOCKET_FAMILY__INET6;
		m->has_socket_family = 1;

		// Message.response_address
		m->response_address.len = 16;
		m->response_address.data = (uint8_t *)
			&sai6->sin6_addr.s6_addr;
		m->has_response_address = 1;

		// Message.response_port
		m->has_response_port = 1;
		m->response_port = ntohs(sai6->sin6_port);
	} else {
		return KNOT_EINVAL;
	}

	// Message.socket_protocol
	if (protocol == IPPROTO_UDP) {
		m->socket_protocol = DNSTAP__SOCKET_PROTOCOL__UDP;
	} else if (protocol == IPPROTO_TCP) {
		m->socket_protocol = DNSTAP__SOCKET_PROTOCOL__TCP;
	} else {
		return KNOT_EINVAL;
	}
	m->has_socket_protocol = 1;

	if (type == DNSTAP__MESSAGE__TYPE__TOOL_QUERY) {
		// Message.query_message
		m->query_message.len = len_wire;
		m->query_message.data = (uint8_t *)wire;
		m->has_query_message = 1;
	} else if (type == DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE) {
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
