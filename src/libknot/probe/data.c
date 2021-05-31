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

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "libknot/probe/probe.h"
#include "contrib/macros.h"

_public_
int knot_probe_data_set(knot_probe_data_t *data, knot_probe_proto_t proto,
                        const struct sockaddr_storage *local_addr,
                        const struct sockaddr_storage *remote_addr,
                        const knot_pkt_t *query, const knot_pkt_t *reply,
                        uint16_t rcode)
{
	if (data == NULL || remote_addr == NULL || query == NULL) {
		return KNOT_EINVAL;
	}

	data->proto = proto;

	if (remote_addr->ss_family == AF_INET) {
		const struct sockaddr_in *sa = (struct sockaddr_in *)remote_addr;
		const struct sockaddr_in *da = (struct sockaddr_in *)local_addr;

		memcpy(data->remote.addr, &sa->sin_addr, sizeof(sa->sin_addr));
		memset(data->remote.addr + sizeof(sa->sin_addr), 0,
		       sizeof(data->remote.addr) - sizeof(sa->sin_addr));
		data->remote.port = be16toh(sa->sin_port);

		if (da != NULL) {
			memcpy(data->local.addr, &da->sin_addr, sizeof(da->sin_addr));
			memset(data->local.addr + sizeof(da->sin_addr), 0,
			       sizeof(data->local.addr) - sizeof(da->sin_addr));
			data->local.port = be16toh(da->sin_port);
		} else {
			memset(&data->local, 0, sizeof(data->local));
		}

		data->ip = 4;
	} else {
		assert(remote_addr->ss_family == AF_INET6);

		const struct sockaddr_in6 *sa = (struct sockaddr_in6 *)remote_addr;
		const struct sockaddr_in6 *da = (struct sockaddr_in6 *)local_addr;

		memcpy(data->remote.addr, &sa->sin6_addr, sizeof(sa->sin6_addr));
		data->remote.port = be16toh(sa->sin6_port);

		if (da != NULL) {
			memcpy(data->local.addr, &da->sin6_addr, sizeof(da->sin6_addr));
			data->local.port = be16toh(da->sin6_port);
		} else {
			memset(&data->local, 0, sizeof(data->local));
		}

		data->ip = 6;
	}

	if (reply != NULL) {
		memcpy(&data->reply.hdr, reply->wire, sizeof(data->reply.hdr));
		data->reply.size = knot_pkt_size(reply);
		data->reply.rcode = rcode;
	} else {
		memset(&data->reply, 0, sizeof(data->reply));
	}
	data->reply.ede = KNOT_PROBE_DATA_EDE_NONE;

	data->tcp_rtt = 0;

	if (query->opt_rr != NULL) {
		data->query_edns.options = 0;
		data->query_edns.payload = knot_edns_get_payload(query->opt_rr);
		data->query_edns.version = knot_edns_get_version(query->opt_rr);
		data->query_edns.present = 1;
		data->query_edns.flag_do = knot_edns_do(query->opt_rr);
		if (query->edns_opts != NULL) {
			for (int i = 0; i <= KNOT_EDNS_MAX_OPTION_CODE; i++) {
				if (query->edns_opts->ptr[i] != NULL) {
					data->query_edns.options |= (1 << i);
				}
			}
		}
		data->query_edns.reserved = 0;
	} else {
		memset(&data->query_edns, 0, sizeof(data->query_edns));
	}

	memcpy(&data->query.hdr, query->wire, sizeof(data->query.hdr));
	data->query.size = knot_pkt_size(query);
	data->query.qclass = knot_pkt_qclass(query);
	data->query.qtype = knot_pkt_qtype(query);
	data->query.qname_len = knot_dname_size(knot_pkt_qname(query));
	memcpy(data->query.qname, knot_pkt_qname(query), data->query.qname_len);
	memset(data->query.qname + data->query.qname_len, 0,
	       MIN(8, sizeof(data->query.qname) - data->query.qname_len));

	return KNOT_EOK;
}

_public_
uint32_t knot_probe_tcp_rtt(int sockfd)
{
#if defined(__linux__)
	struct tcp_info info = { 0 };
	socklen_t info_length = sizeof(info);
	if (getsockopt(sockfd, SOL_TCP, TCP_INFO, &info, &info_length) == 0) {
		return info.tcpi_rtt;
	}
#endif

	return 0;
}
