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

#include "utils/common/exec.h"

#include <stdlib.h>			// free
#include <time.h>			// localtime_r
#include <sys/time.h>			// gettimeofday

#include "common/lists.h"		// list
#include "common/errcode.h"		// KNOT_EOK
#include "libknot/consts.h"		// KNOT_RCODE_NOERROR
#include "libknot/util/wire.h"		// knot_wire_set_rd
#include "libknot/packet/packet.h"	// packet_t
#include "libknot/packet/query.h"	// knot_query_init

#include "utils/common/msg.h"		// WARN
#include "utils/common/resolv.h"	// server_t
#include "utils/common/params.h"	// params_t
#include "utils/common/netio.h"		// send_msg

static knot_packet_t* create_query_packet(const params_t *params,
                                          const query_t  *query,
                                          uint8_t        **data,
                                          size_t         *data_len)
{
	knot_question_t q;

	// Create packet skeleton.
	knot_packet_t *packet = knot_packet_new(KNOT_PACKET_PREALLOC_NONE);

	if (packet == NULL) {
		return NULL;
	}

	// Set packet buffer size.
	if (get_socktype(params, query->type) == SOCK_STREAM) {
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
	if (params->recursion == true) {
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
		                                   params->class_num,
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

	// Create wire query.
	if (knot_packet_to_wire(packet, data, data_len) != KNOT_EOK) {
		ERR("can't create wire query packet\n");
		knot_dname_release(q.qname);
		knot_packet_free(&packet);
		return NULL;
	}

	return packet;
}

static knot_lookup_table_t opcodes[] = {
	{ KNOT_OPCODE_QUERY,  "QUERY" },
	{ KNOT_OPCODE_IQUERY, "IQUERY" },
	{ KNOT_OPCODE_STATUS, "STATUS" },
	{ KNOT_OPCODE_NOTIFY, "NOTIFY" },
	{ KNOT_OPCODE_UPDATE, "UPDATE" },
	{ KNOT_OPCODE_OFFSET, "OFFSET" },
	{ 0, NULL }
};

static knot_lookup_table_t rcodes[] = {
	{ KNOT_RCODE_NOERROR,  "NOERROR" },
	{ KNOT_RCODE_FORMERR,  "FORMERR" },
	{ KNOT_RCODE_SERVFAIL, "SERVFAIL" },
	{ KNOT_RCODE_NXDOMAIN, "NXDOMAIN" },
	{ KNOT_RCODE_NOTIMPL,  "NOTIMPL" },
	{ KNOT_RCODE_REFUSED,  "REFUSED" },
	{ KNOT_RCODE_YXDOMAIN, "YXDOMAIN" },
	{ KNOT_RCODE_YXRRSET,  "YXRRSET" },
	{ KNOT_RCODE_NXRRSET,  "NXRRSET" },
	{ KNOT_RCODE_NOTAUTH,  "NOTAUTH" },
	{ KNOT_RCODE_NOTZONE,  "NOTZONE" },
	{ 0, NULL }
};

static knot_lookup_table_t rtypes[] = {
	{ KNOT_RRTYPE_A,      "has IPv4 address" },
	{ KNOT_RRTYPE_NS,     "nameserver is" },
	{ KNOT_RRTYPE_CNAME,  "is an alias for" },
	{ KNOT_RRTYPE_SOA,    "start of authority is" },
	{ KNOT_RRTYPE_PTR,    "points to" },
	{ KNOT_RRTYPE_MX,     "mail is handled by" },
	{ KNOT_RRTYPE_TXT,    "description is" },
	{ KNOT_RRTYPE_AAAA,   "has IPv6 address" },
	{ KNOT_RRTYPE_LOC,    "location is" },
	{ KNOT_RRTYPE_DS,     "delegation signature is" },
	{ KNOT_RRTYPE_SSHFP,  "SSH fingerprint is" },
	{ KNOT_RRTYPE_RRSIG,  "RR set signature is" },
	{ KNOT_RRTYPE_DNSKEY, "DNSSEC key is" },
	{ KNOT_RRTYPE_TLSA,   "has TLS certificate" },
	{ 0, NULL }
};

static void print_answer(const params_t *params, const knot_packet_t *packet)
{
	char buf[100000];

	for (int i = 0; i < packet->an_rrsets; i++) {
		rrset_write_mem(buf, sizeof(buf), (packet->answer)[i]);
		printf("%s", buf);
	}
}

static void print_header(const knot_packet_t *packet)
{
	char    flags[64] = "\0";
	uint8_t rcode_id, opcode_id;
	knot_lookup_table_t *rcode, *opcode;

	// Get codes.
	rcode_id = knot_wire_get_rcode(packet->wireformat);
	opcode_id = knot_wire_get_opcode(packet->wireformat);

	rcode = knot_lookup_by_id(rcodes, rcode_id);
	opcode = knot_lookup_by_id(opcodes, opcode_id);

	// Get flags.
	if (knot_wire_get_qr(packet->wireformat) != 0) {
		strcat(flags, " qr");
	}
	if (knot_wire_get_aa(packet->wireformat) != 0) {
		strcat(flags, " aa");
	}
	if (knot_wire_get_tc(packet->wireformat) != 0) {
		strcat(flags, " tc");
	}
	if (knot_wire_get_rd(packet->wireformat) != 0) {
		strcat(flags, " rd");
	}
	if (knot_wire_get_ra(packet->wireformat) != 0) {
		strcat(flags, " ra");
	}
	if (knot_wire_get_z(packet->wireformat) != 0) {
		strcat(flags, " z");
	}
	if (knot_wire_get_ad(packet->wireformat) != 0) {
		strcat(flags, " ad");
	}
	if (knot_wire_get_cd(packet->wireformat) != 0) {
		strcat(flags, " cd");
	}

	// Print formated info.
	printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n"
	       ";; Flags:%1s, "
	       "QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
	       opcode->name, rcode->name, knot_packet_id(packet),
	       flags, packet->header.qdcount, packet->an_rrsets,
	       packet->ns_rrsets, packet->ar_rrsets);
}

static void print_footer(const size_t wire_len,
                         const int    sockfd,
                         const float  elapsed)
{
	struct tm tm;
	char      date[64];

	struct sockaddr_storage addr;
	socklen_t addr_len;
	socklen_t socktype_len;
	int       socktype;
	char      proto[8] = "NULL";
	char      ip[INET6_ADDRSTRLEN] = "NULL";
	int       port = -1;

	addr_len = sizeof(addr);
	socktype_len = sizeof(socktype);

	// Get current timestamp.
	time_t now = time(NULL);
	localtime_r(&now, &tm);

	// Create formated date-time string.
	strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S %Z", &tm);

	// Get connected address.
	if (getpeername(sockfd, (struct sockaddr*)&addr, &addr_len) == 0) {
		if (addr.ss_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *)&addr;
			port = ntohs(s->sin_port);
			inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
		} else { // AF_INET6
			struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
			port = ntohs(s->sin6_port);
			inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof(ip));
		}
	}

	// Get connected socket type.
	if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, (char*)&socktype,
	    &socktype_len) == 0) {
		switch (socktype) {
		case SOCK_STREAM:
			strcpy(proto, "TCP");
			break;
		case SOCK_DGRAM:
			strcpy(proto, "UDP");
			break;
		}
	}

	// Print formated info.
	printf(";; Received %zu B (1 message)\n"
	       ";; From %s#%i over %s in %.1f ms\n"
	       ";; On %s\n",
	       wire_len, ip, port, proto, elapsed, date);
}

static void print_xfr_header()
{
	printf("XFR Header:\n");
}

static void print_xfr_footer()
{
	printf("XFR Footer:\n");
}

void print_packet(const params_t      *params,
                  const knot_packet_t *packet,
                  const size_t        wire_len,
                  const int           sockfd,
                  const float         elapsed)
{
	switch (params->format) {
	case FORMAT_DIG:
		break;
	case FORMAT_HOST:
		break;
	case FORMAT_VERBOSE:
	case FORMAT_MULTILINE:
		print_header(packet);
	
		printf("\n;; QUESTION SECTION:\n");

		printf("\n;; ANSWER SECTION:\n");
		print_answer(params, packet);

		printf("\n;; AUTHORITY SECTION:\n");

		printf("\n;; ADDITIONAL SECTION:\n");

		print_footer(wire_len, sockfd, elapsed);

		break;
	default:
		break;
	}
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

static int check_rcode(const params_t *params, const knot_packet_t *reply)
{
	uint8_t rcode = knot_wire_get_rcode(reply->wireformat);

	if (rcode == KNOT_RCODE_SERVFAIL && params->servfail_stop == true) {
		return -1;
	}

	return rcode;
}

static bool check_question(const knot_packet_t *query,
                           const knot_packet_t *reply)
{
	int name_diff = knot_dname_compare_cs(reply->question.qname,
	                                      query->question.qname);

	if (reply->question.qclass != query->question.qclass ||
	    reply->question.qtype  != query->question.qtype ||
	    name_diff != 0) {
		WARN("different question sections\n");
		return false;
	}

	return true;
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

void process_query(const params_t *params, const query_t *query)
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

	// Create query packet.
	out_packet = create_query_packet(params, query, &out, &out_len);

	if (out_packet == NULL) {
		return;
	}

	WALK_LIST(server, params->servers) {
		int  sockfd;
		int  rcode;

		// Start meassuring of query/xfr time.
		gettimeofday(&t_start, NULL);

		// Send query message.
		sockfd = send_msg(params, query, (server_t *)server,
		                  out, out_len);

		if (sockfd < 0) {
			continue;
		}

		id_ok = false;
		stop = false;
		// Loop over incomming messages, unless reply id is correct.
		while (id_ok == false) {
			// Receive reply message.
			in_len = receive_msg(params, query, sockfd,
			                     in, sizeof(in));

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
		rcode = check_rcode(params, in_packet);

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
		if (check_question(out_packet, in_packet) == false) {
			shutdown(sockfd, SHUT_RDWR);
			continue;
		}

		// Dump one standard reply message and finish.
		if (query->type != KNOT_RRTYPE_AXFR &&
		    query->type != KNOT_RRTYPE_IXFR) {
			// Stop meassuring of query time.
			gettimeofday(&t_end, NULL);

			elapsed = (t_end.tv_sec - t_start.tv_sec) * 1000 +
			          ((t_end.tv_usec - t_start.tv_usec) / 1000.0);

			print_packet(params, in_packet, in_len, sockfd, elapsed);

			knot_packet_free(&in_packet);

			shutdown(sockfd, SHUT_RDWR);

			// Stop quering nameservers.
			break;
		}

		// Start XFR dump.
		print_xfr_header(params);

		print_answer(params, in_packet);

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
			in_len = receive_msg(params, query, sockfd,
					     in, sizeof(in));

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
			rcode = check_rcode(params, in_packet);

			if (rcode != KNOT_RCODE_NOERROR) {
				stop = true;
				knot_packet_free(&in_packet);
				break;
			}

			// Dump message data.
			print_answer(params, in_packet);
		}

		// For successful XFR print final information.
		if (stop == false) {
			print_xfr_footer(params);

			knot_packet_free(&in_packet);
		}

		shutdown(sockfd, SHUT_RDWR);

		// Stop quering nameservers.
		break;
	}

	// Drop query packet.
	knot_packet_free(&out_packet);
}

