/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "contrib/dnstap/convert.h"
#include "contrib/dnstap/dnstap.pb-c.h"

/*!
 * \brief Translation between real and Dnstap value.
 */
typedef struct mapping {
	int real;
	int dnstap;
} mapping_t;

/*!
 * \brief Mapping for network family.
 */
static const mapping_t SOCKET_FAMILY_MAPPING[] = {
	{ AF_INET,  DNSTAP__SOCKET_FAMILY__INET },
	{ AF_INET6, DNSTAP__SOCKET_FAMILY__INET6 },
	{ 0 }
};

/*!
 * \brief Mapping from network protocol.
 */
static const mapping_t SOCKET_PROTOCOL_MAPPING[] = {
	{ IPPROTO_UDP, DNSTAP__SOCKET_PROTOCOL__UDP },
	{ IPPROTO_TCP, DNSTAP__SOCKET_PROTOCOL__TCP },
	{ 0 }
};

/*!
 * \brief Get Dnstap value for a given real value.
 */
static int encode(const mapping_t *mapping, int real)
{
	for (const mapping_t *m = mapping; m->real != 0; m += 1) {
		if (m->real == real) {
			return m->dnstap;
		}
	}

	return 0;
}

/*!
 * \brief Get real value for a given Dnstap value.
 */
static int decode(const mapping_t *mapping, int dnstap)
{
	for (const mapping_t *m = mapping; m->real != 0; m += 1) {
		if (m->dnstap == dnstap) {
			return m->real;
		}
	}

	return 0;
}

/* -- public API ----------------------------------------------------------- */

Dnstap__SocketFamily dt_family_encode(int family)
{
	return encode(SOCKET_FAMILY_MAPPING, family);
}

int dt_family_decode(Dnstap__SocketFamily dnstap_family)
{
	return decode(SOCKET_FAMILY_MAPPING, dnstap_family);
}

Dnstap__SocketProtocol dt_protocol_encode(int protocol)
{
	return encode(SOCKET_PROTOCOL_MAPPING, protocol);
}

int dt_protocol_decode(Dnstap__SocketProtocol dnstap_protocol)
{
	return decode(SOCKET_PROTOCOL_MAPPING, dnstap_protocol);
}

bool dt_message_type_is_query(Dnstap__Message__Type type)
{
	switch (type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_QUERY:
	case DNSTAP__MESSAGE__TYPE__CLIENT_QUERY:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY:
	case DNSTAP__MESSAGE__TYPE__STUB_QUERY:
	case DNSTAP__MESSAGE__TYPE__TOOL_QUERY:
		return true;
	default:
		return false;
	}
}

bool dt_message_type_is_response(Dnstap__Message__Type type)
{
	switch (type) {
	case DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__STUB_RESPONSE:
	case DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE:
		return true;
	default:
		return false;
	}
}
