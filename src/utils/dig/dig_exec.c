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
#include <sys/socket.h>                 // AF_INET
#include <netinet/in.h>                 // sockaddr_in (BSD)

#include "common/lists.h"		// list
#include "common/errcode.h"		// KNOT_EOK
#include "libknot/consts.h"		// KNOT_RCODE_NOERROR
#include "libknot/util/wire.h"		// knot_wire_set_rd
#include "libknot/packet/query.h"	// knot_query_init
#include "libknot/packet/response.h"	// knot_response_add_opt
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
		int ret;
		size_t pos = 0;
		// SOA rdata in wireformat.
		uint8_t wire[22] = { 0x0 };
		// Set SOA serial.
		uint32_t serial = htonl(query->xfr_serial);
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
			free(soa_data);
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}

		// Create rrset with SOA record.
		knot_rrset_t *soa = knot_rrset_new(q.qname,
		                                   KNOT_RRTYPE_SOA,
		                                   query->class_num,
		                                   0);
		ret = knot_rrset_add_rdata(soa, soa_data);

		if (ret != KNOT_EOK) {
			free(soa_data);
			free(soa);
			knot_dname_release(q.qname);
			knot_packet_free(&packet);
			return NULL;
		}

		// Add authority section.
		ret = knot_query_add_rrset_authority(packet, soa);

		if (ret != KNOT_EOK) {
			free(soa_data);
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

	return packet;
}

static bool check_id(const knot_packet_t *query, const knot_packet_t *reply)
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

static int check_rcode(const bool servfail_stop, const knot_packet_t *reply)
{
	uint8_t rcode = knot_wire_get_rcode(reply->wireformat);

	if (rcode == KNOT_RCODE_SERVFAIL && servfail_stop == true) {
		return -1;
	}

	return rcode;
}

static void check_question(const knot_packet_t *query,
                           const knot_packet_t *reply)
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

static int64_t first_serial_check(const knot_packet_t *reply)
{
	if (reply->an_rrsets <= 0) {
		return -1;
	}

	const knot_rrset_t *first = *(reply->answer);

	if (first->type != KNOT_RRTYPE_SOA) {
		return -1;
	} else {
		return knot_rdata_soa_serial(first->rdata);
	}
}

static bool last_serial_check(const uint32_t serial, const knot_packet_t *reply)
{
	if (reply->an_rrsets <= 0) {
		return false;
	}

	const knot_rrset_t *last = *(reply->answer + reply->an_rrsets - 1);

	if (last->type != KNOT_RRTYPE_SOA) {
		return false;
	} else {
		int64_t last_serial = knot_rdata_soa_serial(last->rdata);

		if (last_serial == serial) {
			return true;
		} else {
			return false;
		}
	}
}

void process_query(const query_t *query)
{
	float		elapsed;
	bool 		id_ok, stop;
	node		*server = NULL;
	knot_packet_t	*out_packet;
	size_t		out_len = 0;
	uint8_t		*out = NULL;
	knot_packet_t	*in_packet;
	int		in_len;
	uint8_t		in[MAX_PACKET_SIZE];
	struct timeval	t_start, t_end;
	size_t		total_len = 0;
	size_t		msg_count = 0;

	if (query == NULL) {
		return;
	}

	// Create query packet.
	out_packet = create_query_packet(query, &out, &out_len);

	if (out_packet == NULL) {
		return;
	}

	WALK_LIST(server, query->servers) {
		int  sockfd;
		int  rcode;

		// Start meassuring of query/xfr time.
		gettimeofday(&t_start, NULL);

		// Send query message.
		sockfd = send_msg((server_t *)server,
		                  get_iptype(query->ip),
		                  get_socktype(query->protocol, query->type_num),
		                  query->wait, out, out_len);

		if (sockfd < 0) {
			continue;
		}

		id_ok = false;
		stop = false;
		// Loop over incomming messages, unless reply id is correct.
		while (id_ok == false) {
			// Receive reply message.
			in_len = receive_msg(sockfd,
			                     get_socktype(query->protocol, query->type_num),
			                     query->wait, in, sizeof(in));

			if (in_len <= 0) {
				stop = true;
				break;
			}

			// Create reply packet structure to fill up.
			in_packet = knot_packet_new(KNOT_PACKET_PREALLOC_NONE);

			if (in_packet == NULL) {
				stop = true;
				break;
			}

			// Parse reply to packet structure.
			if (knot_packet_parse_from_wire(in_packet, in,
			                                in_len, 0,
			                              KNOT_PACKET_DUPL_NO_MERGE)
			    != KNOT_EOK) {
				knot_packet_free(&in_packet);
				stop = true;
				break;
			}

			// Compare reply header id.
			id_ok = check_id(out_packet, in_packet);
		}

		// Timeout/data error -> try next nameserver.
		if (stop == true) {
			shutdown(sockfd, SHUT_RDWR);
			continue;
		}

		// Check rcode.
		rcode = check_rcode(query->servfail_stop, in_packet);

		// Servfail + stop if servfail -> stop processing.
		if (rcode == -1) {
			shutdown(sockfd, SHUT_RDWR);
			break;
		// Servfail -> try next nameserver.
		} else if (rcode == KNOT_RCODE_SERVFAIL) {
			shutdown(sockfd, SHUT_RDWR);
			continue;
		}

		// Check for question sections equality.
		check_question(out_packet, in_packet);

		// Dump one standard reply message and finish.
		if (query->type_num != KNOT_RRTYPE_AXFR &&
		    query->type_num != KNOT_RRTYPE_IXFR) {
			// Stop meassuring of query time.
			gettimeofday(&t_end, NULL);

			// Calculate elapsed time.
			elapsed = (t_end.tv_sec - t_start.tv_sec) * 1000 +
			          ((t_end.tv_usec - t_start.tv_usec) / 1000.0);

			// Count reply message.
			msg_count++;
			total_len += in_len;

			// Print formated data.
			print_packet(&query->style, in_packet, total_len,
			             sockfd, elapsed, msg_count);

			knot_packet_free(&in_packet);

			shutdown(sockfd, SHUT_RDWR);

			// Stop quering nameservers.
			break;
		}

		// Count first XFR message.
		msg_count++;
		total_len += in_len;

		// Start XFR dump.
		print_header_xfr(&query->style, query->type_num);

		print_data_xfr(&query->style, in_packet);

		// Read first SOA serial.
		int64_t serial = first_serial_check(in_packet);

		if (serial < 0) {
			ERR("first answer resource record must be SOA\n");
			shutdown(sockfd, SHUT_RDWR);
			continue;
		}

		stop = false;
		// Loop over incoming XFR messages unless last
		// SOA serial != first SOA serial.
		while (last_serial_check(serial, in_packet) == false) {
			knot_packet_free(&in_packet);

			// Receive reply message.
			in_len = receive_msg(sockfd,
			                     get_socktype(query->protocol, query->type_num),
			                     query->wait, in, sizeof(in));

			if (in_len <= 0) {
				stop = true;
				break;
			}

			// Create reply packet structure to fill up.
			in_packet = knot_packet_new(KNOT_PACKET_PREALLOC_NONE);

			if (in_packet == NULL) {
				stop = true;
				break;
			}

			// Parse reply to packet structure.
			if (knot_packet_parse_from_wire(in_packet, in,
							in_len, 0,
						      KNOT_PACKET_DUPL_NO_MERGE)
			    != KNOT_EOK) {
				stop = true;
				knot_packet_free(&in_packet);
				break;
			}

			// Compare reply header id.
			id_ok = check_id(out_packet, in_packet);

			// Check rcode.
			rcode = check_rcode(query->servfail_stop, in_packet);

			if (rcode != KNOT_RCODE_NOERROR) {
				stop = true;
				knot_packet_free(&in_packet);
				break;
			}

			// Dump message data.
			print_data_xfr(&query->style, in_packet);

			// Count non-first XFR message.
			msg_count++;
			total_len += in_len;
		}

		// For successful XFR print final information.
		if (stop == false) {
			// Stop meassuring of query time.
			gettimeofday(&t_end, NULL);

			// Calculate elapsed time.
			elapsed = (t_end.tv_sec - t_start.tv_sec) * 1000 +
			          ((t_end.tv_usec - t_start.tv_usec) / 1000.0);

			print_footer_xfr(&query->style, total_len, sockfd,
			                 elapsed, msg_count);

			knot_packet_free(&in_packet);
		}

		shutdown(sockfd, SHUT_RDWR);

		// Stop quering nameservers.
		break;
	}

	// Drop query packet.
	knot_packet_free(&out_packet);
}

int dig_exec(const dig_params_t *params)
{
	node *n = NULL;

	if (params == NULL) {
		return KNOT_EINVAL;
	}

	// Loop over query list.
	WALK_LIST(n, params->queries) {
		query_t *query = (query_t *)n;

		switch (query->operation) {
		case OPERATION_QUERY:
			process_query(query);
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
