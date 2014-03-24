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

#include <config.h>
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
	knot_packet_t   *packet;

	// Set packet buffer size.
	int max_size = query->udp_size;
	if (max_size < 0) {
		if (get_socktype(query->protocol, query->type_num)
		    == SOCK_STREAM) {
			max_size = MAX_PACKET_SIZE;
		} else if (query->flags.do_flag || query->nsid ||
		           query->edns > -1) {
			max_size = DEFAULT_EDNS_SIZE;
		} else {
			max_size = DEFAULT_UDP_SIZE;
		}
	}

	// Create packet skeleton.
	packet = create_empty_packet(max_size);
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

	// Create QNAME from string.
	knot_dname_t *qname = knot_dname_from_str(query->owner);
	if (qname == NULL) {
		knot_packet_free(&packet);
		return NULL;
	}

	// Set packet question.
	int ret = knot_query_set_question(packet, qname,
	                                  query->class_num, query->type_num);
	if (ret != KNOT_EOK) {
		knot_dname_free(&qname);
		knot_packet_free(&packet);
		return NULL;
	}

	// For IXFR query add authority section.
	if (query->type_num == KNOT_RRTYPE_IXFR) {
		// SOA rdata in wireformat.
		uint8_t wire[22] = { 0x0 };
		size_t  pos = 0;

		// Create rrset with SOA record.
		knot_rrset_t *soa = knot_rrset_new(qname,
		                                   KNOT_RRTYPE_SOA,
		                                   query->class_num,
		                                   0);
		if (soa == NULL) {
			knot_dname_free(&qname);
			knot_packet_free(&packet);
			return NULL;
		}

		// Fill in blank SOA rdata to rrset.
		ret = knot_rrset_rdata_from_wire_one(soa, wire, &pos,
		                                    sizeof(wire), sizeof(wire));
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&soa, 1);
			knot_packet_free(&packet);
			return NULL;
		}

		// Set SOA serial.
		knot_rdata_soa_serial_set(soa, query->xfr_serial);

		// Add authority section.
		ret = knot_query_add_rrset_authority(packet, soa);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&soa, 1);
			knot_packet_free(&packet);
			return NULL;
		}
	} else {
		knot_dname_free(&qname);
	}

	// Create EDNS section if required.
	if (query->udp_size > 0 || query->flags.do_flag || query->nsid ||
	    query->edns > -1) {
		knot_opt_rr_t *opt_rr = knot_edns_new();
		if (opt_rr == NULL) {
			ERR("can't create EDNS section\n");
			knot_edns_free(&opt_rr);
			knot_packet_free(&packet);
			return NULL;
		}

		uint8_t edns_version = query->edns > -1 ? query->edns : 0;

		knot_edns_set_version(opt_rr, edns_version);
		knot_edns_set_payload(opt_rr, max_size);

		if (knot_response_add_opt(packet, opt_rr, 0) != KNOT_EOK) {
			ERR("can't set EDNS section\n");
			knot_edns_free(&opt_rr);
			knot_packet_free(&packet);
			return NULL;
		}

		// Set DO flag to EDNS section.
		if (query->flags.do_flag) {
			knot_edns_set_do(&packet->opt_rr);
		}

		if (query->nsid) {
			if (knot_edns_add_option(&packet->opt_rr,
			                         EDNS_OPTION_NSID,
			                         0, NULL) != KNOT_EOK) {
				ERR("can't set NSID query\n");
				knot_edns_free(&opt_rr);
				knot_packet_free(&packet);
				return NULL;
			}
		}

		knot_edns_free(&opt_rr);
	}

	// Create wire query.
	if (knot_packet_to_wire(packet, data, data_len) != KNOT_EOK) {
		ERR("can't create wire query packet\n");
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
	if (knot_wire_get_qdcount(reply->wireformat) < 1) {
		WARN("response doesn't have question section\n");
		return;
	}

	int name_diff = knot_dname_cmp(knot_packet_qname(reply),
	                               knot_packet_qname(query));

	if (knot_packet_qclass(reply) != knot_packet_qclass(query) ||
	    knot_packet_qtype(reply)  != knot_packet_qtype(query) ||
	    name_diff != 0) {
		WARN("query/response question sections are different\n");
		return;
	}
}

static int64_t first_serial_check(const knot_packet_t *reply)
{
	if (knot_wire_get_ancount(reply->wireformat) <= 0) {
		return -1;
	}

	const knot_rrset_t *first = *(reply->answer);

	if (first->type != KNOT_RRTYPE_SOA) {
		return -1;
	} else {
		return knot_rdata_soa_serial(first);
	}
}

static bool last_serial_check(const uint32_t serial, const knot_packet_t *reply)
{
	if (knot_wire_get_ancount(reply->wireformat) <= 0) {
		return false;
	}

	const knot_rrset_t *last = *(reply->answer + knot_wire_get_ancount(reply->wireformat) - 1);

	if (last->type != KNOT_RRTYPE_SOA) {
		return false;
	} else {
		int64_t last_serial = knot_rdata_soa_serial(last);

		if (last_serial == serial) {
			return true;
		} else {
			return false;
		}
	}
}

static int process_query_packet(const knot_packet_t     *query,
                                net_t                   *net,
                                const bool              ignore_tc,
                                const sign_context_t    *sign_ctx,
                                const knot_key_params_t *key_params,
                                const style_t           *style)
{
	struct timeval	t_start, t_query, t_end;
	knot_packet_t	*reply;
	uint8_t		in[MAX_PACKET_SIZE];
	int		in_len;
	int		ret;

	// Get start query time.
	gettimeofday(&t_start, NULL);

	// Connect to the server.
	ret = net_connect(net);
	if (ret != KNOT_EOK) {
		return -1;
	}

	// Send query packet.
	ret = net_send(net, query->wireformat, query->size);
	if (ret != KNOT_EOK) {
		net_close(net);
		return -1;
	}

	// Get stop query time and start reply time.
	gettimeofday(&t_query, NULL);

	// Print query packet if required.
	if (style->show_query) {
		print_packet(query, query->size, net,
		             time_diff(&t_start, &t_query),
		             false, style);
	}

	// Loop over incoming messages, unless reply id is correct or timeout.
	while (true) {
		// Receive a reply message.
		in_len = net_receive(net, in, sizeof(in));
		if (in_len <= 0) {
			net_close(net);
			return -1;
		}

		// Get stop reply time.
		gettimeofday(&t_end, NULL);

		// Create reply packet structure to fill up.
		reply = knot_packet_new();
		if (reply == NULL) {
			net_close(net);
			return -1;
		}

		// Parse reply to the packet structure.
		if (knot_packet_parse_from_wire(reply, in, in_len, 0,
		                                KNOT_PACKET_DUPL_NO_MERGE)
		    != KNOT_EOK) {
			ERR("malformed reply packet from %s\n", net->remote_str);
			knot_packet_free(&reply);
			net_close(net);
			return -1;
		}

		// Compare reply header id.
		if (check_reply_id(reply, query)) {
			break;
		// Check for timeout.
		} else if (time_diff(&t_query, &t_end) > 1000 * net->wait) {
			knot_packet_free(&reply);
			net_close(net);
			return -1;
		}

		knot_packet_free(&reply);
	}

	// Check for TC bit and repeat query with TCP if required.
	if (knot_wire_get_tc(reply->wireformat) != 0 &&
	    ignore_tc == false && net->socktype == SOCK_DGRAM) {
		WARN("truncated reply from %s, retrying over TCP\n",
		     net->remote_str);
		knot_packet_free(&reply);
		net_close(net);

		net->socktype = SOCK_STREAM;

		return process_query_packet(query, net, true, sign_ctx,
		                            key_params, style);
	}

	// Check for question sections equality.
	check_reply_question(reply, query);

	// Verify signature if a key was specified.
	if (key_params->name != NULL) {
		ret = verify_packet(reply, sign_ctx, key_params);
		if (ret != KNOT_EOK) {
			ERR("reply verification for %s (%s)\n",
			    net->remote_str, knot_strerror(ret));
			knot_packet_free(&reply);
			net_close(net);
			return -1;
		}
	}

	// Print reply packet.
	print_packet(reply, in_len, net, time_diff(&t_query, &t_end),
	             true, style);

	knot_packet_free(&reply);
	net_close(net);

	// Check for SERVFAIL.
	if (knot_wire_get_rcode(in) == KNOT_RCODE_SERVFAIL) {
		return 1;
	}

	return 0;
}

static void process_query(const query_t *query)
{
	node_t        *server = NULL;
	knot_packet_t *out_packet;
	uint8_t       *out = NULL;
	size_t        out_len = 0;
	net_t         net;
	int           ret;

	if (query == NULL) {
		DBG_NULL;
		return;
	}

	// Create query packet.
	out_packet = create_query_packet(query, &out, &out_len);
	if (out_packet == NULL) {
		ERR("can't create query packet\n");
		return;
	}

	// Get connection parameters.
	int iptype = get_iptype(query->ip);
	int socktype = get_socktype(query->protocol, query->type_num);

	// Loop over server list to process query.
	WALK_LIST(server, query->servers) {
		srv_info_t *remote = (srv_info_t *)server;

		DBG("Querying for owner(%s), class(%u), type(%u), server(%s), "
		    "port(%s), protocol(%s)\n", query->owner, query->class_num,
		    query->type_num, remote->name, remote->service,
		    get_sockname(socktype));

		// Loop over the number of retries.
		for (size_t i = 0; i <= query->retries; i++) {
			// Initialize network structure for current server.
			ret = net_init(query->local, remote, iptype, socktype,
				       query->wait, &net);
			if (ret != KNOT_EOK) {
				continue;
			}

			// Loop over all resolved addresses for remote.
			while (net.srv != NULL) {
				ret = process_query_packet(out_packet, &net,
							   query->ignore_tc,
							   &query->sign_ctx,
							   &query->key_params,
							   &query->style);
				// If error try next resolved address.
				if (ret != 0) {
					net.srv = (net.srv)->ai_next;
					if (net.srv != NULL) {
						printf("\n");
					}

					continue;
				}

				break;
			}

			// Success.
			if (ret == 0) {
				net_clean(&net);
				knot_packet_free(&out_packet);
				return;
			// SERVFAIL.
			} else if (ret == 1 && query->servfail_stop == true) {
				WARN("failed to query server %s#%s(%s)\n",
				     remote->name, remote->service,
				     get_sockname(socktype));
				net_clean(&net);
				knot_packet_free(&out_packet);
				return;
			}

			if (i < query->retries) {
				printf("\n");
				DBG("retrying server %s#%s(%s)\n",
				    remote->name, remote->service,
				    get_sockname(socktype));
			}

			net_clean(&net);
		}

		WARN("failed to query server %s#%s(%s)\n",
		     remote->name, remote->service, get_sockname(socktype));
	}

	knot_packet_free(&out_packet);
}

static int process_packet_xfr(const knot_packet_t     *query,
                              net_t                   *net,
                              const sign_context_t    *sign_ctx,
                              const knot_key_params_t *key_params,
                              const style_t           *style)
{
	struct timeval t_start, t_query, t_end;
	knot_packet_t  *reply;
	uint8_t        in[MAX_PACKET_SIZE];
	int            in_len;
	int            ret;
	int64_t        serial = 0;
	size_t         total_len = 0;
	size_t         msg_count = 0;
	size_t         rr_count = 0;

	// Get start query time.
	gettimeofday(&t_start, NULL);

	// Connect to the server.
	ret = net_connect(net);
	if (ret != KNOT_EOK) {
		return -1;
	}

	// Send query packet.
	ret = net_send(net, query->wireformat, query->size);
	if (ret != KNOT_EOK) {
		net_close(net);
		return -1;
	}

	// Get stop query time and start reply time.
	gettimeofday(&t_query, NULL);


	// Print query packet if required.
	if (style->show_query) {
		print_packet(query, query->size, net,
		             time_diff(&t_start, &t_query),
		             false, style);
	}

	// Print leading transfer information.
	print_header_xfr(query, style);

	// Loop over reply messages unless first and last SOA serials differ.
	while (true) {
		// Receive a reply message.
		in_len = net_receive(net, in, sizeof(in));
		if (in_len <= 0) {
			net_close(net);
			return -1;
		}

		// Create reply packet structure to fill up.
		reply = knot_packet_new();
		if (reply == NULL) {
			net_close(net);
			return -1;
		}

		// Parse reply to the packet structure.
		if (knot_packet_parse_from_wire(reply, in, in_len, 0,
		                                KNOT_PACKET_DUPL_NO_MERGE)
		    != KNOT_EOK) {
			ERR("malformed reply packet from %s\n", net->remote_str);
			knot_packet_free(&reply);
			net_close(net);
			return -1;
		}

		// Compare reply header id.
		if (check_reply_id(reply, query) == false) {
			knot_packet_free(&reply);
			net_close(net);
			return -1;
		}

		// Check for reply error.
		uint8_t rcode_id = knot_wire_get_rcode(in);
		if (rcode_id != KNOT_RCODE_NOERROR) {
			knot_lookup_table_t *rcode =
				knot_lookup_by_id(knot_rcode_names, rcode_id);
			if (rcode != NULL) {
				ERR("server %s responded %s\n",
				    net->remote_str, rcode->name);
			} else {
				ERR("server %s responded %i\n",
				    net->remote_str, rcode_id);
			}

			knot_packet_free(&reply);
			net_close(net);
			return -1;
		}

		// The first message has a special treatment.
		if (msg_count == 0) {
			// Verify 1. signature if a key was specified.
			if (key_params->name != NULL) {
				ret = verify_packet(reply, sign_ctx, key_params);
				if (ret != KNOT_EOK) {
					ERR("reply verification for %s (%s)\n",
					    net->remote_str, knot_strerror(ret));
					knot_packet_free(&reply);
					net_close(net);
					return -1;
				}
			}

			// Read first SOA serial.
			serial = first_serial_check(reply);

			if (serial < 0) {
				ERR("first answer record isn't SOA\n");
				knot_packet_free(&reply);
				net_close(net);
				return -1;
			}

			// Check for question sections equality.
			check_reply_question(reply, query);
		}

		msg_count++;
		rr_count += knot_wire_get_ancount(reply->wireformat);
		total_len += in_len;

		// Print reply packet.
		print_data_xfr(reply, style);

		// Stop if last SOA record has correct serial.
		if (last_serial_check(serial, reply)) {
			knot_packet_free(&reply);
			break;
		}

		knot_packet_free(&reply);
	}

	// Get stop reply time.
	gettimeofday(&t_end, NULL);

	// Print trailing transfer information.
	print_footer_xfr(total_len, msg_count, rr_count, net,
	                 time_diff(&t_query, &t_end), style);

	net_close(net);

	return 0;
}

static void process_query_xfr(const query_t *query)
{
	knot_packet_t *out_packet;
	uint8_t       *out = NULL;
	size_t        out_len = 0;
	net_t         net;
	int           ret;

	if (query == NULL) {
		DBG_NULL;
		return;
	}

	// Create query packet.
	out_packet = create_query_packet(query, &out, &out_len);
	if (out_packet == NULL) {
		ERR("can't create query packet\n");
		return;
	}

	// Get connection parameters.
	int iptype = get_iptype(query->ip);
	int socktype = get_socktype(query->protocol, query->type_num);

	// Use the first nameserver from the list.
	srv_info_t *remote = HEAD(query->servers);

	DBG("Querying for owner(%s), class(%u), type(%u), server(%s), "
	    "port(%s), protocol(%s)\n", query->owner, query->class_num,
	    query->type_num, remote->name, remote->service,
	    get_sockname(socktype));

	// Initialize network structure.
	ret = net_init(query->local, remote, iptype, socktype,
	               query->wait, &net);
	if (ret != KNOT_EOK) {
		knot_packet_free(&out_packet);
		return;
	}

	// Loop over all resolved addresses for remote.
	while (net.srv != NULL) {
		ret = process_packet_xfr(out_packet, &net,
		                         &query->sign_ctx,
		                         &query->key_params,
		                         &query->style);
		// If error try next resolved address.
		if (ret != 0) {
			net.srv = (net.srv)->ai_next;
			continue;
		}

		break;
	}

	if (ret != 0) {
		ERR("failed to query server %s#%s(%s)\n",
		    remote->name, remote->service, get_sockname(socktype));
	}

	net_clean(&net);
	knot_packet_free(&out_packet);
}

int dig_exec(const dig_params_t *params)
{
	node_t *n = NULL;

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
			process_query_xfr(query);
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
