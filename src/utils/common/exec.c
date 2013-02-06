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
#include <arpa/inet.h>			// inet_ntop
#include <sys/socket.h>			// AF_INET
#include <netinet/in.h>			// sockaddr_in (BSD)

#include "common/lists.h"		// list
#include "common/errcode.h"		// KNOT_EOK
#include "libknot/consts.h"		// KNOT_RCODE_NOERROR
#include "libknot/util/wire.h"		// knot_wire_set_rd
#include "libknot/packet/query.h"	// knot_query_init
#include "utils/common/msg.h"		// WARN
#include "utils/common/params.h"	// params_t
#include "utils/common/netio.h"		// send_msg
#include "utils/common/rr-serialize.h"	// rrset_write_mem

knot_lookup_table_t opcodes[] = {
	{ KNOT_OPCODE_QUERY,  "QUERY" },
	{ KNOT_OPCODE_IQUERY, "IQUERY" },
	{ KNOT_OPCODE_STATUS, "STATUS" },
	{ KNOT_OPCODE_NOTIFY, "NOTIFY" },
	{ KNOT_OPCODE_UPDATE, "UPDATE" },
	{ KNOT_OPCODE_OFFSET, "OFFSET" },
	{ 0, NULL }
};

knot_lookup_table_t rcodes[] = {
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

knot_lookup_table_t rtypes[] = {
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

knot_packet_t* create_empty_packet(knot_packet_prealloc_type_t t, int max_size)
{
	// Create packet skeleton.
	knot_packet_t *packet = knot_packet_new(t);
	if (packet == NULL) {
		return NULL;
	}

	// Set packet buffer size.
	knot_packet_set_max_size(packet, max_size);

	// Set random sequence id.
	knot_packet_set_random_id(packet);

	// Initialize query packet.
	knot_query_init(packet);

	return packet;
}

static void print_header(const style_t *style, const knot_packet_t *packet)
{
	char    flags[64] = "";
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
	switch (style->format) {
	case FORMAT_NSUPDATE:
		printf("\n;; ->>HEADER<<- opcode: %s, status: %s, id: %u\n"
		       ";; Flags:%1s, "
		       "ZONE: %u, PREREQ: %u, UPDATE: %u, ADDITIONAL: %u\n",
		       opcode->name, rcode->name, knot_packet_id(packet),
		       flags, packet->header.qdcount, packet->an_rrsets,
		       packet->ns_rrsets, packet->ar_rrsets);

		break;
	default:
		printf("\n;; ->>HEADER<<- opcode: %s, status: %s, id: %u\n"
		       ";; Flags:%1s, "
		       "QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
		       opcode->name, rcode->name, knot_packet_id(packet),
		       flags, packet->header.qdcount, packet->an_rrsets,
		       packet->ns_rrsets, packet->ar_rrsets);
		break;
	}
}

static void print_footer(const size_t total_len,
                         const int    sockfd,
                         const float  elapsed,
                         const size_t msg_count)
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
	printf("\n;; Received %zu B (%zu messages)\n"
	       ";; From %s#%i over %s in %.1f ms\n"
	       ";; On %s\n",
	       total_len, msg_count, ip, port, proto, elapsed, date);
}

static void print_section_question(const knot_dname_t *owner,
                                   const uint16_t     qclass,
                                   const uint16_t     qtype)
{
	size_t buflen = 8192;
	char   *buf = malloc(buflen);

	knot_rrset_t *question = knot_rrset_new((knot_dname_t *)owner, qtype,
	                                        qclass, 0);

	if (rrset_header_write_mem(buf, buflen, question, true, false) < 0) {
		WARN("can't dump whole question section\n");
	}

	printf("%s\n", buf);

	knot_rrset_free(&question);
	free(buf);
}

static void print_section_verbose(const knot_rrset_t **rrsets,
                                  const uint16_t     count)
{
	size_t buflen = 8192;
	char   *buf = malloc(buflen);

	for (uint16_t i = 0; i < count; i++) {
		while (rrset_write_mem(buf, buflen, rrsets[i]) < 0) {
			buflen += 4096;
			buf = realloc(buf, buflen);

			// Oversize protection.
			if (buflen > 1000000) {
				WARN("can't print whole section\n");
				break;
			}
		}
		printf("%s", buf);
	}

	free(buf);
}

static void print_section_dig(const knot_rrset_t **rrsets,
                              const uint16_t     count)
{
	size_t buflen = 8192;
	char   *buf = malloc(buflen);

	for (uint16_t i = 0; i < count; i++) {
		const knot_rrset_t *rrset = rrsets[i];
		knot_rdata_t *tmp = rrset->rdata;

		do {
			while (rdata_write_mem(buf, buflen, tmp, rrset->type)
			       < 0) {
				buflen += 4096;
				buf = realloc(buf, buflen);

				// Oversize protection.
				if (buflen > 1000000) {
					WARN("can't print whole section\n");
					break;
				}
			}
			printf("%s\n", buf);

			tmp = tmp->next;
		} while (tmp != rrset->rdata);
	}

	free(buf);
}

static void print_section_host(const knot_rrset_t **rrsets,
                               const uint16_t     count)
{
	size_t buflen = 8192;
	char   *buf = malloc(buflen);

	for (uint16_t i = 0; i < count; i++) {
		const knot_rrset_t  *rrset = rrsets[i];
		knot_rdata_t        *tmp = rrset->rdata;
		knot_lookup_table_t *descr;
		char                type[32] = "NULL";
		char                *owner;

		owner = knot_dname_to_str(rrset->owner);
		descr = knot_lookup_by_id(rtypes, rrset->type);

		do {
			while (rdata_write_mem(buf, buflen, tmp, rrset->type)
			       < 0) {
				buflen += 4096;
				buf = realloc(buf, buflen);

				// Oversize protection.
				if (buflen > 1000000) {
					WARN("can't print whole RR set\n");
					break;
				}
			}

			if (descr != NULL) {
				printf("%s %s %s\n", owner, descr->name, buf);
			} else {
				knot_rrtype_to_string(rrset->type, type,
				                      sizeof(type));
				printf("%s has %s record %s\n",
				       owner, type, buf);
			}

			tmp = tmp->next;
		} while (tmp != rrset->rdata);

		free(owner);
	}

	free(buf);
}

static void print_error_host(const uint8_t         code,
                             const knot_question_t *question)
{
	char type[32] = "NULL";
	char *owner;

	knot_lookup_table_t *rcode;

	owner = knot_dname_to_str(question->qname);
	rcode = knot_lookup_by_id(rcodes, code);
	knot_rrtype_to_string(question->qtype, type, sizeof(type));

	if (code == KNOT_RCODE_NOERROR) {
		printf("Host %s has no %s record\n", owner, type);
	} else { 
		printf("Host %s type %s error: %s\n", owner, type, rcode->name);
	}

	free(owner);
}

void print_header_xfr(const style_t *style, const knot_rr_type_t type)
{
	char name[16] = "";

	switch (type) {
	case KNOT_RRTYPE_AXFR:
		strcpy(name, "AXFR");
		break;
	case KNOT_RRTYPE_IXFR:
		strcpy(name, "IXFR");
		break;
	default:
		return;
	}

	switch (style->format) {
	case FORMAT_VERBOSE:
	case FORMAT_MULTILINE:
		printf(";; %s transfer\n\n", name);
		break;
	case FORMAT_DIG:
	case FORMAT_HOST:
	default:
		break;
	}
}

void print_data_xfr(const style_t       *style,
                    const knot_packet_t *packet)
{
	if (packet == NULL) {
		return;
	}

	switch (style->format) {
	case FORMAT_DIG:
		print_section_dig(packet->answer, packet->an_rrsets);
		break;
	case FORMAT_HOST:
		print_section_host(packet->answer, packet->an_rrsets);
		break;
	case FORMAT_VERBOSE:
	case FORMAT_MULTILINE:
		print_section_verbose(packet->answer, packet->an_rrsets);
		break;
	default:
		break;
	}
}

void print_footer_xfr(const style_t  *style,
                      const size_t   total_len,
                      const int      sockfd,
                      const float    elapsed,
                      const size_t   msg_count)
{
	switch (style->format) {
	case FORMAT_VERBOSE:
	case FORMAT_MULTILINE:
		print_footer(total_len, sockfd, elapsed, msg_count);
		break;
	case FORMAT_DIG:
	case FORMAT_HOST:
	default:
		break;
	}
}

void print_packet(const style_t       *style,
                  const knot_packet_t *packet,
                  const size_t        total_len,
                  const int           sockfd,
                  const float         elapsed,
                  const size_t        msg_count)
{
	if (packet == NULL) {
		return;
	}

	switch (style->format) {
	case FORMAT_DIG:
		if (packet->an_rrsets > 0) {
			print_section_dig(packet->answer, packet->an_rrsets);
		}
		break;
	case FORMAT_HOST:
		if (packet->an_rrsets > 0) {
			print_section_host(packet->answer, packet->an_rrsets);
		} else {
			uint8_t rcode = knot_wire_get_rcode(packet->wireformat);
			print_error_host(rcode, &packet->question);
		}
		break;
	case FORMAT_NSUPDATE:
		print_header(style, packet);

		if (packet->header.qdcount > 0) {
			printf("\n;; ZONE SECTION:\n;; ");
			print_section_question(packet->question.qname,
			                       packet->question.qclass,
			                       packet->question.qtype);
		}

		if (packet->an_rrsets > 0) {
			printf("\n;; PREREQUISITE SECTION:\n");
			print_section_verbose(packet->answer,
			                      packet->an_rrsets);
		}

		if (packet->ns_rrsets > 0) {
			printf("\n;; UPDATE SECTION:\n");
			print_section_verbose(packet->authority,
			                      packet->ns_rrsets);
		}

		if (packet->ar_rrsets > 0) {
			printf("\n;; ADDITIONAL DATA:\n");
			print_section_verbose(packet->additional,
			                      packet->ar_rrsets);
		}
		break;
	case FORMAT_VERBOSE:
	case FORMAT_MULTILINE:
		print_header(style, packet);

		if (packet->header.qdcount > 0) {
			printf("\n;; QUESTION SECTION:\n;; ");
			print_section_question(packet->question.qname,
			                       packet->question.qclass,
			                       packet->question.qtype);
		}

		if (packet->an_rrsets > 0) {
			printf("\n;; ANSWER SECTION:\n");
			print_section_verbose(packet->answer,
			                      packet->an_rrsets);
		}

		if (packet->ns_rrsets > 0) {
			printf("\n;; AUTHORITY SECTION:\n");
			print_section_verbose(packet->authority,
			                      packet->ns_rrsets);
		}

		if (packet->ar_rrsets > 0) {
			printf("\n;; ADDITIONAL SECTION:\n");
			print_section_verbose(packet->additional,
			                      packet->ar_rrsets);
		}

		print_footer(total_len, sockfd, elapsed, msg_count);
		break;
	default:
		break;
	}
}
