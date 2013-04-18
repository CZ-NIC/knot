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

#include "utils/dig/dig_exec.h"

#include <stdlib.h>			// free
#include <sys/time.h>			// gettimeofday
#include <sys/socket.h>			// AF_INET
#include <netinet/in.h>			// sockaddr_in (BSD)

#include "libknot/libknot.h"
#include "common/lists.h"		// list
#include "common/print.h"		// time_diff
#include "common/errcode.h"		// KNOT_EOK
#include "common/descriptor.h"		// KNOT_RRTYPE_
#include "utils/common/msg.h"		// WARN
#include "utils/common/netio.h"		// get_socktype
#include "utils/common/exec.h"		// print_packet

static knot_packet_t* create_query_packet(const query_t *query,
                                          uint8_t       **data,
                                          size_t        *data_len)
{
	knot_question_t q;
	knot_packet_t   *packet;

	// Set packet buffer size.
	int max_size = query->udp_size;

	if (max_size < 0) {
		if (get_socktype(query->protocol, query->type_num)
		    == SOCK_STREAM) {
			max_size = MAX_PACKET_SIZE;
		} else if (query->flags.do_flag == true) {
			max_size = DEFAULT_EDNS_SIZE;
		} else {
			max_size = DEFAULT_UDP_SIZE;
		}
	}

	// Create packet skeleton.
	packet = create_empty_packet(KNOT_PACKET_PREALLOC_NONE, max_size);

	if (packet == NULL) {
		return NULL;
	}

	// Set flags to wireformat.
	if (query->flags.aa_flag == true) {
		knot_wire_set_aa(packet->wireformat);
	}
	if (query->flags.tc_flag == true) {
		knot_wire_set_tc(packet->wireformat);
	}
	if (query->flags.rd_flag == true) {
		knot_wire_set_rd(packet->wireformat);
	}
	if (query->flags.ra_flag == true) {
		knot_wire_set_ra(packet->wireformat);
	}
	if (query->flags.z_flag == true) {
		knot_wire_set_z(packet->wireformat);
	}
	if (query->flags.ad_flag == true) {
		knot_wire_set_ad(packet->wireformat);
	}
	if (query->flags.cd_flag == true) {
		knot_wire_set_cd(packet->wireformat);
	}

	// Fill auxiliary question structure.
	q.qclass = query->class_num;
	q.qtype = query->type_num;
	q.qname = knot_dname_new_from_str(query->owner, strlen(query->owner), 0);

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
	if (query->type_num == KNOT_RRTYPE_IXFR) {
		// SOA rdata in wireformat.
		uint8_t wire[22] = { 0x0 };
		size_t  pos = 0;
		int     ret;

		// Create rrset with SOA record.
		knot_rrset_t *soa = knot_rrset_new(q.qname,
		                                   KNOT_RRTYPE_SOA,
		                                   query->class_num,
		                                   0);
		if (soa == NULL) {
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}

		// Fill in blank SOA rdata to rrset.
		ret = knot_rrset_rdata_from_wire_one(soa, wire, &pos,
		                                    sizeof(wire), sizeof(wire));
		if (ret != KNOT_EOK) {
			free(soa);
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}

		// Set SOA serial.
		knot_rrset_rdata_soa_serial_set(soa, query->xfr_serial);

		// Add authority section.
		ret = knot_query_add_rrset_authority(packet, soa);
		if (ret != KNOT_EOK) {
			free(soa);
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}
	}

	// Set DO flag to EDNS section.
	if (query->flags.do_flag == true) {
		knot_opt_rr_t *opt_rr = knot_edns_new();

		if (opt_rr == NULL) {
			ERR("can't create EDNS section\n");
			knot_edns_free(&opt_rr);
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}

		knot_edns_set_version(opt_rr, 0);
		knot_edns_set_payload(opt_rr, max_size);

		if (knot_response_add_opt(packet, opt_rr, 0, 0) != KNOT_EOK) {
			ERR("can't set EDNS section\n");
			knot_edns_free(&opt_rr);
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}

		knot_edns_set_do(&packet->opt_rr);

		knot_edns_free(&opt_rr);
	}

	// Create wire query.
	if (knot_packet_to_wire(packet, data, data_len) != KNOT_EOK) {
		ERR("can't create wire query packet\n");
		knot_dname_release(q.qname);
		knot_packet_free(&packet);
		return NULL;
	}

	// Sign the packet if a key was specified.
	if (query->key_params.name != NULL) {
		int ret = sign_packet(packet, (sign_context_t *)&query->sign_ctx,
		                      &query->key_params);
		if (ret != KNOT_EOK) {
			ERR("failed to sign query packet (%s)\n",
			    knot_strerror(ret));
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}
		*data_len = packet->size;
	}

	return packet;
}

static bool check_reply_id(const knot_packet_t *reply,
                                 const knot_packet_t *query)
{
	uint16_t query_id = knot_wire_get_id(query->wireformat);
	uint16_t reply_id = knot_wire_get_id(reply->wireformat);

	if (reply_id != query_id) {
		WARN("reply ID (%u) is different from query ID (%u)\n",
		     reply_id, query_id);
		return false;
	}

	return true;
}

static void check_reply_question(const knot_packet_t *reply,
                                 const knot_packet_t *query)
{
	if (reply->header.qdcount < 1) {
		WARN("response doesn't have question section\n");
		return;
	}

	int name_diff = knot_dname_compare_cs(reply->question.qname,
	                                      query->question.qname);

	if (reply->question.qclass != query->question.qclass ||
	    reply->question.qtype  != query->question.qtype ||
	    name_diff != 0) {
		WARN("query/response question sections are different\n");
		return;
	}
}

static int process_query_packet(const knot_packet_t     *query,
                                const server_t          *server,
                                const ip_t              ip_type,
                                const int               sock_type,
                                const int32_t           wait,
                                const bool              ignore_tc,
                                const sign_context_t    *sign_ctx,
                                const knot_key_params_t *key_params,
                                const style_t           *style)
{
	struct timeval	t_start, t_query, t_end;
	knot_packet_t	*reply;
	uint8_t		in[MAX_PACKET_SIZE];
	int		in_len;
	net_t		net;
	int		ret;

	// Get initial time.
	gettimeofday(&t_start, NULL);

	// Connect to the server.
	ret = net_connect(NULL, server, ip_type, sock_type, wait, &net);
	if (ret != KNOT_EOK) {
		return -1;
	}

	INFO("quering server %s#%i over %s\n", net.addr, net.port, net.proto);

	// Send query packet.
	ret = net_send(&net, query->wireformat, query->size);

	// Get query time.
	gettimeofday(&t_query, NULL);

	if (ret != KNOT_EOK) {
		net_close(&net);
		return -1;
	}

	// Print query packet if required.
	if (style->show_query) {
		print_packet(query, query->size, &net,
		             time_diff(&t_start, &t_query),
		             false, style);
	}

	// Loop over incoming messages, unless reply id is correct or timeout.
	while (true) {
		// Receive a reply message.
		in_len = net_receive(&net, in, sizeof(in));
		if (in_len <= 0) {
			net_close(&net);
			return -1;
		}

		// Stop meassuring of query time.
		gettimeofday(&t_end, NULL);

		// Create reply packet structure to fill up.
		reply = knot_packet_new(KNOT_PACKET_PREALLOC_NONE);
		if (reply == NULL) {
			net_close(&net);
			return -1;
		}

		// Parse reply to the packet structure.
		if (knot_packet_parse_from_wire(reply, in, in_len, 0,
		                                KNOT_PACKET_DUPL_NO_MERGE)
		    != KNOT_EOK) {
			ERR("Malformed reply packet\n");
			knot_packet_free(&reply);
			net_close(&net);
			return -1;
		}

		// Compare reply header id.
		if (check_reply_id(reply, query)) {
			break;
		// Check for timeout.
		} else if (time_diff(&t_query, &t_end) > 1000 * wait) {
			knot_packet_free(&reply);
			net_close(&net);
			return -1;
		}
	}

	// Check for TC bit and repeat query with TCP if required.
	if (knot_wire_get_tc(reply->wireformat) != 0 &&
	    ignore_tc == false && sock_type == SOCK_DGRAM) {
		WARN("truncated reply\n");
		knot_packet_free(&reply);
		net_close(&net);

		return process_query_packet(query, server, ip_type, SOCK_STREAM,
		                            wait, true, sign_ctx, key_params,
		                            style);
	}

	// Check for question sections equality.
	if (knot_wire_get_rcode(in) == KNOT_RCODE_NOERROR) {
		check_reply_question(reply, query);
	}

	// Verify signature if a key was specified.
	if (key_params->name != NULL) {
		ret = verify_packet(reply, sign_ctx, key_params);
		if (ret != KNOT_EOK) {
			ERR("%s\n", knot_strerror(ret));
			knot_packet_free(&reply);
			net_close(&net);
			return -1;
		}
	}

	// Print reply packet.
	print_packet(reply, in_len, &net, time_diff(&t_query, &t_end),
	             true, style);

	knot_packet_free(&reply);
	net_close(&net);

	return 0;
}

void process_query(const query_t *query)
{
	node          *server = NULL;
	knot_packet_t *out_packet;
	uint8_t       *out = NULL;
	size_t        out_len = 0;
	int           ret;

	if (query == NULL) {
		DBG_NULL;
		return;
	}

	// Create query packet.
	out_packet = create_query_packet(query, &out, &out_len);
	if (out_packet == NULL) {
		return;
	}

	// Get connection parameters.
	ip_t ip_type = get_iptype(query->ip);
	int sock_type = get_socktype(query->protocol, query->type_num);

	// Loop over server list.
	WALK_LIST(server, query->servers) {
		for (size_t i = 0; i <= query->retries; i++) {
			ret = process_query_packet(out_packet,
			                           (server_t *)server,
			                           ip_type, sock_type,
			                           query->wait, query->ignore_tc,
			                           &query->sign_ctx,
			                           &query->key_params,
			                           &query->style);
	
			if (ret == 0) {
				knot_packet_free(&out_packet);
				return;
			} else if (query->servfail_stop == true) {
				INFO("no reply\n");
				knot_packet_free(&out_packet);
				return;
			}
		}
	}

	INFO("no reply\n");
	knot_packet_free(&out_packet);
}

int dig_exec(const dig_params_t *params)
{
	node *n = NULL;

	if (params == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	// Loop over query list.
	WALK_LIST(n, params->queries) {
		query_t *query = (query_t *)n;

		switch (query->operation) {
		case OPERATION_QUERY:
			process_query(query);
			break;
		case OPERATION_XFR:
// TODO
			break;
		case OPERATION_LIST_SOA:
			break;
		default:
			ERR("unsupported operation\n");
			break;
		}
	}

	return KNOT_EOK;
}
