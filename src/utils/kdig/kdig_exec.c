/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "utils/kdig/kdig_exec.h"
#include "utils/common/exec.h"
#include "utils/common/msg.h"
#include "utils/common/netio.h"
#include "utils/common/sign.h"
#include "libknot/libknot.h"
#include "contrib/sockaddr.h"
#include "contrib/print.h"
#include "contrib/ucw/lists.h"

#if USE_DNSTAP
# include "contrib/dnstap/convert.h"
# include "contrib/dnstap/message.h"
# include "contrib/dnstap/writer.h"

static int write_dnstap(dt_writer_t          *writer,
                        const bool           is_query,
                        const uint8_t        *wire,
                        const size_t         wire_len,
                        net_t                *net,
                        const struct timeval *qtime,
                        const struct timeval *rtime)
{
	Dnstap__Message       msg;
	Dnstap__Message__Type msg_type;
	int                   ret;
	int                   protocol = 0;

	if (writer == NULL) {
		return KNOT_EOK;
	}

	net_set_local_info(net);

	msg_type = is_query ? DNSTAP__MESSAGE__TYPE__TOOL_QUERY :
	                      DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE;

	if (net->socktype == SOCK_DGRAM) {
		protocol = IPPROTO_UDP;
	} else if (net->socktype == SOCK_STREAM) {
		protocol = IPPROTO_TCP;
	}

	ret = dt_message_fill(&msg, msg_type, net->local_info->ai_addr,
	                      net->srv->ai_addr, protocol,
	                      wire, wire_len, qtime, rtime);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return dt_writer_write(writer, (const ProtobufCMessage *)&msg);
}

static float get_query_time(const Dnstap__Dnstap *frame)
{
	struct timeval from = {
		.tv_sec = frame->message->query_time_sec,
		.tv_usec = frame->message->query_time_nsec / 1000
	};

	struct timeval to = {
		.tv_sec = frame->message->response_time_sec,
		.tv_usec = frame->message->response_time_nsec / 1000
	};

	return time_diff(&from, &to);
}

static void process_dnstap(const query_t *query)
{
	dt_reader_t *reader = query->dt_reader;

	if (query->dt_reader == NULL) {
		return;
	}

	for (;;) {
		Dnstap__Dnstap      *frame = NULL;
		Dnstap__Message     *message = NULL;
		ProtobufCBinaryData *wire = NULL;
		bool                is_query;

		// Read next message.
		int ret = dt_reader_read(reader, &frame);
		if (ret == KNOT_EOF) {
			break;
		} else if (ret != KNOT_EOK) {
			ERR("can't read dnstap message\n");
			break;
		}

		// Check for dnstap message.
		if (frame->type == DNSTAP__DNSTAP__TYPE__MESSAGE) {
			message = frame->message;
		} else {
			WARN("ignoring non-dnstap message\n");
			dt_reader_free_frame(reader, &frame);
			continue;
		}

		// Check for the type of dnstap message.
		if (message->has_response_message) {
			wire = &message->response_message;
			is_query = false;
		} else if (message->has_query_message) {
			wire = &message->query_message;
			is_query = true;
		} else {
			WARN("dnstap frame contains no message\n");
			dt_reader_free_frame(reader, &frame);
			continue;
		}

		// Ignore query message if requested.
		if (is_query && !query->style.show_query) {
			dt_reader_free_frame(reader, &frame);
			continue;
		}

		// Create dns packet based on dnstap wire data.
		knot_pkt_t *pkt = knot_pkt_new(wire->data, wire->len, NULL);
		if (pkt == NULL) {
			ERR("can't allocate packet\n");
			dt_reader_free_frame(reader, &frame);
			break;
		}

		// Parse packet and reconstruct required data.
		if (knot_pkt_parse(pkt, 0) == KNOT_EOK) {
			time_t timestamp = 0;
			float  query_time = 0.0;
			net_t  net_ctx = { 0 };

			if (is_query) {
				timestamp = message->query_time_sec;
			} else {
				timestamp = message->response_time_sec;
				query_time = get_query_time(frame);
			}

			// Prepare connection information string.
			if (message->query_address.data != NULL &&
			    message->has_socket_family &&
			    message->has_socket_protocol) {
				struct sockaddr_storage ss;
				int family, proto, sock_type;

				family = dt_family_decode(message->socket_family);
				proto = dt_protocol_decode(message->socket_protocol);

				switch (proto) {
				case IPPROTO_TCP:
					sock_type = SOCK_STREAM;
					break;
				case IPPROTO_UDP:
					sock_type = SOCK_DGRAM;
					break;
				default:
					sock_type = 0;
					break;
				}

				sockaddr_set_raw(&ss, family,
				                 message->query_address.data,
				                 message->query_address.len);
				sockaddr_port_set(&ss, message->query_port);
				get_addr_str(&ss, sock_type, &net_ctx.remote_str);
			}

			print_packet(pkt, &net_ctx, pkt->size, query_time,
			             timestamp, is_query, &query->style);

			net_clean(&net_ctx);
		} else {
			ERR("can't print dnstap message\n");
		}

		knot_pkt_free(&pkt);
		dt_reader_free_frame(reader, &frame);
	}
}
#endif // USE_DNSTAP

static int add_query_edns(knot_pkt_t *packet, const query_t *query, int max_size)
{
	/* Initialize OPT RR. */
	knot_rrset_t opt_rr;
	int ret = knot_edns_init(&opt_rr, max_size, 0,
	                         query->edns > -1 ? query->edns : 0, &packet->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (query->flags.do_flag) {
		knot_edns_set_do(&opt_rr);
	}

	/* Append NSID. */
	if (query->nsid) {
		ret = knot_edns_add_option(&opt_rr, KNOT_EDNS_OPTION_NSID,
		                           0, NULL, &packet->mm);
		if (ret != KNOT_EOK) {
			knot_rrset_clear(&opt_rr, &packet->mm);
			return ret;
		}
	}

	/* Append EDNS-client-subnet. */
	if (query->subnet != NULL) {
		uint8_t  data[KNOT_EDNS_MAX_OPTION_CLIENT_SUBNET] = { 0 };
		uint16_t data_len = sizeof(data);

		ret = knot_edns_client_subnet_create(query->subnet->family,
		                                     query->subnet->addr,
		                                     query->subnet->addr_len,
		                                     query->subnet->netmask,
		                                     0, data, &data_len);
		if (ret != KNOT_EOK) {
			knot_rrset_clear(&opt_rr, &packet->mm);
			return ret;
		}

		ret = knot_edns_add_option(&opt_rr, KNOT_EDNS_OPTION_CLIENT_SUBNET,
		                           data_len, data, &packet->mm);
		if (ret != KNOT_EOK) {
			knot_rrset_clear(&opt_rr, &packet->mm);
			return ret;
		}
	}

	/* Add prepared OPT to packet. */
	ret = knot_pkt_put(packet, KNOT_COMPR_HINT_NONE, &opt_rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &packet->mm);
	}

	return ret;
}

static bool use_edns(const query_t *query)
{
	return query->flags.do_flag || query->nsid || query->edns > -1 ||
	       query->subnet != NULL;
}

static knot_pkt_t* create_query_packet(const query_t *query)
{
	knot_pkt_t *packet;
	int        ret = 0;

	// Set packet buffer size.
	uint16_t max_size;
	if (query->udp_size < 0) {
		if (use_edns(query)) {
			max_size = DEFAULT_EDNS_SIZE;
		} else {
			max_size = DEFAULT_UDP_SIZE;
		}
	} else {
		max_size = query->udp_size;
	}

	// Create packet skeleton.
	packet = create_empty_packet(max_size);
	if (packet == NULL) {
		return NULL;
	}

	// Set flags to wireformat.
	if (query->flags.aa_flag) {
		knot_wire_set_aa(packet->wire);
	}
	if (query->flags.tc_flag) {
		knot_wire_set_tc(packet->wire);
	}
	if (query->flags.rd_flag) {
		knot_wire_set_rd(packet->wire);
	}
	if (query->flags.ra_flag) {
		knot_wire_set_ra(packet->wire);
	}
	if (query->flags.z_flag) {
		knot_wire_set_z(packet->wire);
	}
	if (query->flags.ad_flag) {
		knot_wire_set_ad(packet->wire);
	}
	if (query->flags.cd_flag) {
		knot_wire_set_cd(packet->wire);
	}

	// Set NOTIFY opcode.
	if (query->notify) {
		knot_wire_set_opcode(packet->wire, KNOT_OPCODE_NOTIFY);
	}

	// Create QNAME from string.
	knot_dname_t *qname = knot_dname_from_str_alloc(query->owner);
	if (qname == NULL) {
		knot_pkt_free(&packet);
		return NULL;
	}

	// Set packet question.
	ret = knot_pkt_put_question(packet, qname, query->class_num,
	                            query->type_num);
	if (ret != KNOT_EOK) {
		knot_dname_free(&qname, NULL);
		knot_pkt_free(&packet);
		return NULL;
	}

	// For IXFR query or NOTIFY query with SOA serial, add a proper section.
	if (query->serial >= 0) {
		if (query->notify) {
			knot_pkt_begin(packet, KNOT_ANSWER);
		} else {
			knot_pkt_begin(packet, KNOT_AUTHORITY);
		}

		// SOA rdata in wireformat.
		uint8_t wire[22] = { 0x0 };

		// Create rrset with SOA record.
		knot_rrset_t *soa = knot_rrset_new(qname,
		                                   KNOT_RRTYPE_SOA,
		                                   query->class_num,
		                                   &packet->mm);
		knot_dname_free(&qname, NULL);
		if (soa == NULL) {
			knot_pkt_free(&packet);
			return NULL;
		}

		// Fill in blank SOA rdata to rrset.
		ret = knot_rrset_add_rdata(soa, wire, sizeof(wire), 0,
		                           &packet->mm);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&soa, &packet->mm);
			knot_pkt_free(&packet);
			return NULL;
		}

		// Set SOA serial.
		knot_soa_serial_set(&soa->rrs, query->serial);

		ret = knot_pkt_put(packet, 0, soa, KNOT_PF_FREE);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&soa, &packet->mm);
			knot_pkt_free(&packet);
			return NULL;
		}
	} else {
		knot_dname_free(&qname, NULL);
	}

	// Begin additional section
	knot_pkt_begin(packet, KNOT_ADDITIONAL);

	// Create EDNS section if required.
	if (query->udp_size >= 0 || use_edns(query)) {
		int ret = add_query_edns(packet, query, max_size);
		if (ret != KNOT_EOK) {
			ERR("can't set up EDNS section\n");
			knot_pkt_free(&packet);
			return NULL;
		}
	}

	return packet;
}

static bool check_reply_id(const knot_pkt_t *reply,
                           const knot_pkt_t *query)
{
	uint16_t query_id = knot_wire_get_id(query->wire);
	uint16_t reply_id = knot_wire_get_id(reply->wire);

	if (reply_id != query_id) {
		WARN("reply ID (%u) is different from query ID (%u)\n",
		     reply_id, query_id);
		return false;
	}

	return true;
}

static void check_reply_question(const knot_pkt_t *reply,
                                 const knot_pkt_t *query)
{
	if (knot_wire_get_qdcount(reply->wire) < 1) {
		WARN("response doesn't have question section\n");
		return;
	}

	int name_diff = knot_dname_cmp(knot_pkt_qname(reply),
	                               knot_pkt_qname(query));

	if (knot_pkt_qclass(reply) != knot_pkt_qclass(query) ||
	    knot_pkt_qtype(reply)  != knot_pkt_qtype(query) ||
	    name_diff != 0) {
		WARN("query/response question sections are different\n");
		return;
	}
}

static int64_t first_serial_check(const knot_pkt_t *reply)
{
	const knot_pktsection_t *answer = knot_pkt_section(reply, KNOT_ANSWER);

	if (answer->count <= 0) {
		return -1;
	}

	const knot_rrset_t *first = knot_pkt_rr(answer, 0);

	if (first->type != KNOT_RRTYPE_SOA) {
		return -1;
	} else {
		return knot_soa_serial(&first->rrs);
	}
}

static bool last_serial_check(const uint32_t serial, const knot_pkt_t *reply)
{
	const knot_pktsection_t *answer = knot_pkt_section(reply, KNOT_ANSWER);
	if (answer->count <= 0) {
		return false;
	}

	const knot_rrset_t *last = knot_pkt_rr(answer, answer->count - 1);

	if (last->type != KNOT_RRTYPE_SOA) {
		return false;
	} else {
		int64_t last_serial = knot_soa_serial(&last->rrs);
		if (last_serial == serial) {
			return true;
		} else {
			return false;
		}
	}
}

static int sign_query(knot_pkt_t *pkt, const query_t *query, sign_context_t *ctx)
{
	if (query->tsig_key.name == NULL) {
		return KNOT_EOK;
	}

	int ret = sign_context_init_tsig(ctx, &query->tsig_key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = sign_packet(pkt, ctx);
	if (ret != KNOT_EOK) {
		sign_context_deinit(ctx);
		return ret;
	}

	return KNOT_EOK;
}

static int process_query_packet(const knot_pkt_t      *query,
                                net_t                 *net,
                                const query_t         *query_ctx,
                                const bool            ignore_tc,
                                const sign_context_t  *sign_ctx,
                                const style_t         *style)
{
	struct timeval	t_start, t_query, t_end;
	knot_pkt_t	*reply;
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
	ret = net_send(net, query->wire, query->size);
	if (ret != KNOT_EOK) {
		net_close(net);
		return -1;
	}

	// Get stop query time and start reply time.
	gettimeofday(&t_query, NULL);

#if USE_DNSTAP
	// Make the dnstap copy of the query.
	write_dnstap(query_ctx->dt_writer, true, query->wire, query->size,
	             net, &t_query, NULL);
#endif // USE_DNSTAP

	// Print query packet if required.
	if (style->show_query) {
		// Create copy of query packet for parsing.
		knot_pkt_t *q = knot_pkt_new(query->wire, query->size, NULL);
		if (q != NULL) {
			if (knot_pkt_parse(q, 0) == KNOT_EOK) {
				print_packet(q, net, query->size,
				             time_diff(&t_start, &t_query), 0,
				             false, style);
			} else {
				ERR("can't print query packet\n");
			}
			knot_pkt_free(&q);
		} else {
			ERR("can't print query packet\n");
		}

		printf("\n");
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

#if USE_DNSTAP
		// Make the dnstap copy of the response.
		write_dnstap(query_ctx->dt_writer, false, in, in_len, net,
		             &t_query, &t_end);
#endif // USE_DNSTAP

		// Create reply packet structure to fill up.
		reply = knot_pkt_new(in, in_len, NULL);
		if (reply == NULL) {
			ERR("internal error (%s)\n", knot_strerror(KNOT_ENOMEM));
			net_close(net);
			return 0;
		}

		// Parse reply to the packet structure.
		if (knot_pkt_parse(reply, 0) != KNOT_EOK) {
			ERR("malformed reply packet from %s\n", net->remote_str);
			knot_pkt_free(&reply);
			net_close(net);
			return 0;
		}

		// Compare reply header id.
		if (check_reply_id(reply, query)) {
			break;
		// Check for timeout.
		} else if (time_diff(&t_query, &t_end) > 1000 * net->wait) {
			knot_pkt_free(&reply);
			net_close(net);
			return -1;
		}

		knot_pkt_free(&reply);
	}

	// Check for TC bit and repeat query with TCP if required.
	if (knot_wire_get_tc(reply->wire) != 0 &&
	    ignore_tc == false && net->socktype == SOCK_DGRAM) {
		WARN("truncated reply from %s, retrying over TCP\n",
		     net->remote_str);
		knot_pkt_free(&reply);
		net_close(net);

		net->socktype = SOCK_STREAM;

		return process_query_packet(query, net, query_ctx, true,
		                            sign_ctx, style);
	}

	// Check for question sections equality.
	check_reply_question(reply, query);

	// Print reply packet.
	print_packet(reply, net, in_len, time_diff(&t_query, &t_end), 0,
	             true, style);

	// Verify signature if a key was specified.
	if (sign_ctx->digest != NULL) {
		ret = verify_packet(reply, sign_ctx);
		if (ret != KNOT_EOK) {
			WARN("reply verification for %s (%s)\n",
			     net->remote_str, knot_strerror(ret));
		}
	}

	knot_pkt_free(&reply);
	net_close(net);

	return 0;
}

static void process_query(const query_t *query)
{
	node_t     *server = NULL;
	knot_pkt_t *out_packet;
	net_t      net;
	int        ret;

	if (query == NULL) {
		DBG_NULL;
		return;
	}

	// Create query packet.
	out_packet = create_query_packet(query);
	if (out_packet == NULL) {
		ERR("can't create query packet\n");
		return;
	}

	// Sign the query.
	sign_context_t sign_ctx = { 0 };
	ret = sign_query(out_packet, query, &sign_ctx);
	if (ret != KNOT_EOK) {
		ERR("can't sign the packet (%s)\n", knot_strerror(ret));
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
				                           query,
				                           query->ignore_tc,
				                           &sign_ctx,
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
				sign_context_deinit(&sign_ctx);
				knot_pkt_free(&out_packet);
				return;
			}

			if (i < query->retries) {
				printf("\n");
				DBG("retrying server %s@%s(%s)\n",
				    remote->name, remote->service,
				    get_sockname(socktype));
			}

			net_clean(&net);
		}

		WARN("failed to query server %s@%s(%s)\n",
		     remote->name, remote->service, get_sockname(socktype));

		// If not last server, print separation.
		if (server->next->next) {
			printf("\n");
		}
	}

	sign_context_deinit(&sign_ctx);
	knot_pkt_free(&out_packet);
}

static int process_xfr_packet(const knot_pkt_t      *query,
                              net_t                 *net,
                              const query_t         *query_ctx,
                              const sign_context_t  *sign_ctx,
                              const style_t         *style)
{
	struct timeval t_start, t_query, t_end;
	knot_pkt_t     *reply;
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
	ret = net_send(net, query->wire, query->size);
	if (ret != KNOT_EOK) {
		net_close(net);
		return -1;
	}

	// Get stop query time and start reply time.
	gettimeofday(&t_query, NULL);

#if USE_DNSTAP
	// Make the dnstap copy of the query.
	write_dnstap(query_ctx->dt_writer, true, query->wire, query->size,
	             net, &t_query, NULL);
#endif // USE_DNSTAP

	// Print query packet if required.
	if (style->show_query) {
		// Create copy of query packet for parsing.
		knot_pkt_t *q = knot_pkt_new(query->wire, query->size, NULL);
		if (q != NULL) {
			if (knot_pkt_parse(q, 0) == KNOT_EOK) {
				print_packet(q, net, query->size,
				             time_diff(&t_start, &t_query), 0,
				             false, style);
			} else {
				ERR("can't print query packet\n");
			}
			knot_pkt_free(&q);
		} else {
			ERR("can't print query packet\n");
		}

		printf("\n");
	}

	// Loop over reply messages unless first and last SOA serials differ.
	while (true) {
		// Receive a reply message.
		in_len = net_receive(net, in, sizeof(in));
		if (in_len <= 0) {
			net_close(net);
			return -1;
		}

		// Get stop message time.
		gettimeofday(&t_end, NULL);

#if USE_DNSTAP
		// Make the dnstap copy of the response.
		write_dnstap(query_ctx->dt_writer, false, in, in_len, net,
		             &t_query, &t_end);
#endif // USE_DNSTAP

		// Create reply packet structure to fill up.
		reply = knot_pkt_new(in, in_len, NULL);
		if (reply == NULL) {
			ERR("internal error (%s)\n", knot_strerror(KNOT_ENOMEM));
			net_close(net);
			return 0;
		}

		// Parse reply to the packet structure.
		if (knot_pkt_parse(reply, 0) != KNOT_EOK) {
			ERR("malformed reply packet from %s\n", net->remote_str);
			knot_pkt_free(&reply);
			net_close(net);
			return 0;
		}

		// Compare reply header id.
		if (check_reply_id(reply, query) == false) {
			ERR("reply ID mismatch from %s\n", net->remote_str);
			knot_pkt_free(&reply);
			net_close(net);
			return 0;
		}

		// The first message has a special treatment.
		if (msg_count == 0) {
			// Print leading transfer information.
			print_header_xfr(query, style);

			// Verify 1. signature if a key was specified.
			if (sign_ctx->digest != NULL) {
				ret = verify_packet(reply, sign_ctx);
				if (ret != KNOT_EOK) {
					style_t tsig_style = {
						.format = style->format,
						.style = style->style,
						.show_tsig = true
					};
					print_data_xfr(reply, &tsig_style);

					ERR("reply verification for %s (%s)\n",
					    net->remote_str, knot_strerror(ret));
					knot_pkt_free(&reply);
					net_close(net);
					return 0;
				}
			}

			// Read first SOA serial.
			serial = first_serial_check(reply);

			if (serial < 0) {
				ERR("first answer record from %s isn't SOA\n",
				    net->remote_str);
				knot_pkt_free(&reply);
				net_close(net);
				return 0;
			}

			// Check for question sections equality.
			check_reply_question(reply, query);
		}

		msg_count++;
		rr_count += knot_wire_get_ancount(reply->wire);
		total_len += in_len;

		// Print reply packet.
		print_data_xfr(reply, style);

		// Stop if last SOA record has correct serial.
		if (last_serial_check(serial, reply)) {
			knot_pkt_free(&reply);
			break;
		}

		knot_pkt_free(&reply);
	}

	// Get stop reply time.
	gettimeofday(&t_end, NULL);

	// Print trailing transfer information.
	print_footer_xfr(total_len, msg_count, rr_count, net,
	                 time_diff(&t_query, &t_end), 0, style);

	net_close(net);

	return 0;
}

static void process_xfr(const query_t *query)
{
	knot_pkt_t *out_packet;
	net_t      net;
	int        ret;

	if (query == NULL) {
		DBG_NULL;
		return;
	}

	// Create query packet.
	out_packet = create_query_packet(query);
	if (out_packet == NULL) {
		ERR("can't create query packet\n");
		return;
	}

	// Sign the query.
	sign_context_t sign_ctx = { 0 };
	ret = sign_query(out_packet, query, &sign_ctx);
	if (ret != KNOT_EOK) {
		ERR("can't sign the packet (%s)\n", knot_strerror(ret));
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
		sign_context_deinit(&sign_ctx);
		knot_pkt_free(&out_packet);
		return;
	}

	// Loop over all resolved addresses for remote.
	while (net.srv != NULL) {
		ret = process_xfr_packet(out_packet, &net,
		                         query,
		                         &sign_ctx,
		                         &query->style);
		// If error try next resolved address.
		if (ret != 0) {
			net.srv = (net.srv)->ai_next;
			continue;
		}

		break;
	}

	if (ret != 0) {
		ERR("failed to query server %s@%s(%s)\n",
		    remote->name, remote->service, get_sockname(socktype));
	}

	net_clean(&net);
	sign_context_deinit(&sign_ctx);
	knot_pkt_free(&out_packet);
}

int kdig_exec(const kdig_params_t *params)
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
			process_xfr(query);
			break;
#if USE_DNSTAP
		case OPERATION_LIST_DNSTAP:
			process_dnstap(query);
			break;
#endif // USE_DNSTAP
		case OPERATION_LIST_SOA:
			break;
		default:
			ERR("unsupported operation\n");
			break;
		}

		// If not last query, print separation.
		if (n->next->next && params->config->style.format == FORMAT_FULL) {
			printf("\n");
		}
	}

	return KNOT_EOK;
}
