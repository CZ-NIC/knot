/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>

#include "libdnssec/random.h"
#include "utils/common/exec.h"
#include "utils/common/msg.h"
#include "utils/common/netio.h"
#include "utils/common/params.h"
#include "libknot/libknot.h"
#include "contrib/ctype.h"
#include "contrib/sockaddr.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/ucw/lists.h"
#include "contrib/wire_ctx.h"

static const char *JSON_INDENT = "  ";

static knot_lookup_t rtypes[] = {
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

static void print_header(const knot_pkt_t *packet, const style_t *style)
{
	char flags[64] = "";
	char unknown_rcode[64] = "";
	char unknown_opcode[64] = "";

	const char *rcode_str = NULL;
	const char *opcode_str = NULL;

	// Get extended RCODE.
	const char *code_name = knot_pkt_ext_rcode_name(packet);
	if (code_name[0] != '\0') {
		rcode_str = code_name;
	} else {
		uint16_t code = knot_pkt_ext_rcode(packet);
		(void)snprintf(unknown_rcode, sizeof(unknown_rcode), "RCODE %d", code);
		rcode_str = unknown_rcode;
	}

	// Get OPCODE.
	uint8_t code = knot_wire_get_opcode(packet->wire);
	const knot_lookup_t *opcode = knot_lookup_by_id(knot_opcode_names, code);
	if (opcode != NULL) {
		opcode_str = opcode->name;
	} else {
		(void)snprintf(unknown_opcode, sizeof(unknown_opcode), "OPCODE %d", code);
		opcode_str = unknown_opcode;
	}

	// Get flags.
	size_t flags_rest = sizeof(flags);
	const size_t flag_len = 4;
	if (knot_wire_get_qr(packet->wire) != 0 && flags_rest > flag_len) {
		flags_rest -= strlcat(flags, " qr", flags_rest);
	}
	if (knot_wire_get_aa(packet->wire) != 0 && flags_rest > flag_len) {
		flags_rest -= strlcat(flags, " aa", flags_rest);
	}
	if (knot_wire_get_tc(packet->wire) != 0 && flags_rest > flag_len) {
		flags_rest -= strlcat(flags, " tc", flags_rest);
	}
	if (knot_wire_get_rd(packet->wire) != 0 && flags_rest > flag_len) {
		flags_rest -= strlcat(flags, " rd", flags_rest);
	}
	if (knot_wire_get_ra(packet->wire) != 0 && flags_rest > flag_len) {
		flags_rest -= strlcat(flags, " ra", flags_rest);
	}
	if (knot_wire_get_z(packet->wire) != 0 && flags_rest > flag_len) {
		flags_rest -= strlcat(flags, " z", flags_rest);
	}
	if (knot_wire_get_ad(packet->wire) != 0 && flags_rest > flag_len) {
		flags_rest -= strlcat(flags, " ad", flags_rest);
	}
	if (knot_wire_get_cd(packet->wire) != 0 && flags_rest > flag_len) {
		strlcat(flags, " cd", flags_rest);
	}

	uint16_t id = knot_wire_get_id(packet->wire);
	uint16_t qdcount = knot_wire_get_qdcount(packet->wire);
	uint16_t ancount = knot_wire_get_ancount(packet->wire);
	uint16_t nscount = knot_wire_get_nscount(packet->wire);
	uint16_t arcount = knot_wire_get_arcount(packet->wire);

	if (knot_pkt_has_tsig(packet)) {
		arcount++;
	}

	// Print formatted info.
	switch (style->format) {
	case FORMAT_NSUPDATE:
		printf(";; ->>HEADER<<- opcode: %s; status: %s; id: %u\n"
		       ";; Flags:%1s; "
		       "ZONE: %u; PREREQ: %u; UPDATE: %u; ADDITIONAL: %u\n",
		       opcode_str, rcode_str, id, flags, qdcount, ancount,
		       nscount, arcount);
		break;
	default:
		printf(";; ->>HEADER<<- opcode: %s; status: %s; id: %u\n"
		       ";; Flags:%1s; "
		       "QUERY: %u; ANSWER: %u; AUTHORITY: %u; ADDITIONAL: %u\n",
		       opcode_str, rcode_str, id, flags, qdcount, ancount,
		       nscount, arcount);
		break;
	}
}

static void print_footer(const size_t total_len,
                         const size_t msg_count,
                         const size_t rr_count,
                         const net_t  *net,
                         const float  elapsed,
                         time_t       exec_time,
                         const bool   incoming)
{
	struct tm tm;
	char date[64];

	// Get current timestamp.
	if (exec_time == 0) {
		exec_time = time(NULL);
	}

	// Create formatted date-time string.
	localtime_r(&exec_time, &tm);
	strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S %Z", &tm);

	// Print messages statistics.
	if (incoming) {
		printf(";; Received %zu B", total_len);
	} else {
		printf(";; Sent %zu B", total_len);
	}

	// If multimessage (XFR) print additional statistics.
	if (msg_count > 0) {
		printf(" (%zu messages, %zu records)\n", msg_count, rr_count);
	} else {
		printf("\n");
	}
	// Print date.
	printf(";; Time %s\n", date);

	// Print connection statistics.
	if (net != NULL) {
		if (incoming) {
			printf(";; From %s", net->remote_str);
		} else {
			printf(";; To %s", net->remote_str);
		}

		if (elapsed >= 0) {
			printf(" in %.1f ms\n", elapsed);
		} else {
			printf("\n");
		}
	}
}

static void print_hex(const uint8_t *data, uint16_t len)
{
	for (int i = 0; i < len; i++) {
		printf("%02X", data[i]);
	}
}

static void print_nsid(const uint8_t *data, uint16_t len)
{
	if (len == 0) {
		return;
	}

	print_hex(data, len);

	// Check if printable string.
	for (int i = 0; i < len; i++) {
		if (!is_print(data[i])) {
			return;
		}
	}
	printf(" \"%.*s\"", len, data);
}

static bool print_text(const uint8_t *data, uint16_t len)
{
	if (len == 0) {
		return false;
	}

	// Check if printable string.
	for (int i = 0; i < len; i++) {
		if (!is_print(data[i])) {
			return false;
		}
	}
	printf("%.*s", len, data);
	return true;
}

static void print_edns_client_subnet(const uint8_t *data, uint16_t len)
{
	knot_edns_client_subnet_t ecs = { 0 };
	int ret = knot_edns_client_subnet_parse(&ecs, data, len);
	if (ret != KNOT_EOK) {
		return;
	}

	struct sockaddr_storage addr = { 0 };
	ret = knot_edns_client_subnet_get_addr(&addr, &ecs);
	assert(ret == KNOT_EOK);

	char addr_str[SOCKADDR_STRLEN] = { 0 };
	sockaddr_tostr(addr_str, sizeof(addr_str), &addr);

	printf("%s/%u/%u", addr_str, ecs.source_len, ecs.scope_len);
}

static void print_ede(const uint8_t *data, uint16_t len)
{
	if (len < 2) {
		printf("(malformed)");
		return;
	}


	uint16_t errcode;
	memcpy(&errcode, data, sizeof(errcode));
	errcode = be16toh(errcode);

	const knot_lookup_t *item = knot_lookup_by_id(knot_edns_ede_names, errcode);
	const char *strerr = (item != NULL) ? item->name : "Unknown code";

	if (len > 2) {
		printf("%hu (%s): '%.*s'", errcode, strerr, (int)(len - 2), data + 2);
	} else {
		printf("%hu (%s)", errcode, strerr);
	}
}

static void print_expire(const uint8_t *data, uint16_t len)
{
	if (len == 0) {
		printf("(empty)");
	} else if (len != sizeof(uint32_t)) {
		printf("(malformed)");
	} else {
		uint32_t timer = knot_wire_read_u32(data);
		printf("%u", timer);
	}
}

static void print_section_opt(const knot_pkt_t *packet, const style_t *style)
{
	char unknown_ercode[64] = "";
	const char *ercode_str = NULL;

	uint16_t ercode = knot_edns_get_ext_rcode(packet->opt_rr);
	if (ercode > 0) {
		ercode = knot_edns_whole_rcode(ercode,
		                               knot_wire_get_rcode(packet->wire));
	}

	const knot_lookup_t *item = knot_lookup_by_id(knot_rcode_names, ercode);
	if (item != NULL) {
		ercode_str = item->name;
	} else {
		(void)snprintf(unknown_ercode, sizeof(unknown_ercode), "RCODE %d", ercode);
		ercode_str = unknown_ercode;
	}

	printf("Version: %u; flags: %s; UDP size: %u B; ext-rcode: %s\n",
	       knot_edns_get_version(packet->opt_rr),
	       (knot_edns_do(packet->opt_rr) != 0) ? "do" : "",
	       knot_edns_get_payload(packet->opt_rr),
	       ercode_str);

	assert(packet->opt_rr->rrs.count > 0);
	knot_rdata_t *rdata = packet->opt_rr->rrs.rdata;
	wire_ctx_t wire = wire_ctx_init_const(rdata->data, rdata->len);

	while (wire_ctx_available(&wire) >= KNOT_EDNS_OPTION_HDRLEN) {
		uint16_t opt_code = wire_ctx_read_u16(&wire);
		uint16_t opt_len = wire_ctx_read_u16(&wire);
		uint8_t *opt_data = wire.position;

		if (wire.error != KNOT_EOK) {
			WARN("invalid OPT record data");
			return;
		}

		switch (opt_code) {
		case KNOT_EDNS_OPTION_NSID:
			printf(";; NSID: ");
			print_nsid(opt_data, opt_len);
			break;
		case KNOT_EDNS_OPTION_CLIENT_SUBNET:
			printf(";; CLIENT-SUBNET: ");
			print_edns_client_subnet(opt_data, opt_len);
			break;
		case KNOT_EDNS_OPTION_PADDING:
			printf(";; PADDING: %u B", opt_len);
			break;
		case KNOT_EDNS_OPTION_COOKIE:
			printf(";; COOKIE: ");
			print_hex(opt_data, opt_len);
			break;
		case KNOT_EDNS_OPTION_EDE:
			printf(";; EDE: ");
			print_ede(opt_data, opt_len);
			break;
		case KNOT_EDNS_OPTION_EXPIRE:
			printf(";; EXPIRE: ");
			print_expire(opt_data, opt_len);
			break;
		default:
			printf(";; Option (%u): ", opt_code);
			if (style->show_edns_opt_text) {
				if (!print_text(opt_data, opt_len)) {
					print_hex(opt_data, opt_len);
				}
			} else {
				print_hex(opt_data, opt_len);
			}
		}
		printf("\n");

		wire_ctx_skip(&wire, opt_len);
	}

	if (wire_ctx_available(&wire) > 0) {
		WARN("invalid OPT record data");
	}
}

static void print_section_question(const knot_dname_t *owner,
                                   const uint16_t     qclass,
                                   const uint16_t     qtype,
                                   const style_t      *style)
{
	size_t buflen = 8192;
	char *buf = calloc(buflen, 1);

	// Don't print zero TTL.
	knot_dump_style_t qstyle = style->style;
	qstyle.empty_ttl = true;

	knot_rrset_t *question = knot_rrset_new(owner, qtype, qclass, 0, NULL);

	if (knot_rrset_txt_dump_header(question, 0, buf, buflen, &qstyle) < 0) {
		WARN("can't print whole question section");
	}

	printf("%s\n", buf);

	knot_rrset_free(question, NULL);
	free(buf);
}

static void print_section_full(const knot_rrset_t *rrsets,
                               const uint16_t     count,
                               const style_t      *style,
                               const bool         no_tsig)
{
	size_t buflen = 8192;
	char *buf = calloc(buflen, 1);

	for (size_t i = 0; i < count; i++) {
		// Ignore OPT records.
		if (rrsets[i].type == KNOT_RRTYPE_OPT) {
			continue;
		}

		// Exclude TSIG record.
		if (no_tsig && rrsets[i].type == KNOT_RRTYPE_TSIG) {
			continue;
		}

		if (knot_rrset_txt_dump(&rrsets[i], &buf, &buflen,
		                        &(style->style)) < 0) {
				WARN("can't print whole section");
				break;
		}
		printf("%s", buf);
	}

	free(buf);
}

static void print_section_dig(const knot_rrset_t *rrsets,
                              const uint16_t     count,
                              const style_t      *style)
{
	size_t buflen = 8192;
	char *buf = calloc(buflen, 1);

	for (size_t i = 0; i < count; i++) {
		const knot_rrset_t *rrset = &rrsets[i];
		uint16_t rrset_rdata_count = rrset->rrs.count;
		for (uint16_t j = 0; j < rrset_rdata_count; j++) {
			while (knot_rrset_txt_dump_data(rrset, j, buf, buflen,
			                                &(style->style)) < 0) {
				buflen += 4096;
				// Oversize protection.
				if (buflen > 100000) {
					WARN("can't print whole section");
					break;
				}

				char *newbuf = realloc(buf, buflen);
				if (newbuf == NULL) {
					WARN("can't print whole section");
					break;
				}
				buf = newbuf;
			}
			printf("%s\n", buf);
		}
	}

	free(buf);
}

static void print_section_host(const knot_rrset_t *rrsets,
                               const uint16_t     count,
                               const style_t      *style)
{
	size_t buflen = 8192;
	char *buf = calloc(buflen, 1);

	for (size_t i = 0; i < count; i++) {
		const knot_rrset_t *rrset = &rrsets[i];
		const knot_lookup_t *descr;
		char type[32] = "NULL";
		char *owner;

		owner = knot_dname_to_str_alloc(rrset->owner);
		if (style->style.ascii_to_idn != NULL) {
			style->style.ascii_to_idn(&owner);
		}
		descr = knot_lookup_by_id(rtypes, rrset->type);

		uint16_t rrset_rdata_count = rrset->rrs.count;
		for (uint16_t j = 0; j < rrset_rdata_count; j++) {
			if (rrset->type == KNOT_RRTYPE_CNAME &&
			    style->hide_cname) {
				continue;
			}

			while (knot_rrset_txt_dump_data(rrset, j, buf, buflen,
			                                &(style->style)) < 0) {
				buflen += 4096;
				// Oversize protection.
				if (buflen > 100000) {
					WARN("can't print whole section");
					break;
				}

				char *newbuf = realloc(buf, buflen);
				if (newbuf == NULL) {
					WARN("can't print whole section");
					break;
				}
				buf = newbuf;
			}

			if (descr != NULL) {
				printf("%s %s %s\n", owner, descr->name, buf);
			} else {
				knot_rrtype_to_string(rrset->type, type, sizeof(type));
				printf("%s has %s record %s\n", owner, type, buf);
			}
		}

		free(owner);
	}

	free(buf);
}

static void print_error_host(const knot_pkt_t *packet, const style_t *style)
{
	char type[32] = "Unknown";
	const char *rcode_str = "Unknown";

	knot_rrtype_to_string(knot_pkt_qtype(packet), type, sizeof(type));

	// Get extended RCODE.
	const char *code_name = knot_pkt_ext_rcode_name(packet);
	if (code_name[0] != '\0') {
		rcode_str = code_name;
	}

	// Get record owner.
	char *owner = knot_dname_to_str_alloc(knot_pkt_qname(packet));
	if (style->style.ascii_to_idn != NULL) {
		style->style.ascii_to_idn(&owner);
	}

	if (knot_pkt_ext_rcode(packet) == KNOT_RCODE_NOERROR) {
		printf("Host %s has no %s record\n", owner, type);
	} else {
		printf("Host %s type %s error: %s\n", owner, type, rcode_str);
	}

	free(owner);
}

static void json_dname(jsonw_t *w, const char *key, const knot_dname_t *dname)
{
	knot_dname_txt_storage_t name;
	if (knot_dname_to_str(name, dname, sizeof(name)) != NULL) {
		jsonw_str(w, key, name);
	}
}

static void json_rdata(jsonw_t *w, const knot_rrset_t *rrset)
{
	char type[16];
	if (knot_rrtype_to_string(rrset->type, type, sizeof(type)) <= 0 ||
	    strncmp(type, "TYPE", 4) == 0) { // Unknown/hex format.
		return;
	}

	char key[32] = "rdata";
	strlcat(key, type, sizeof(key));

	char data[16384];
	const knot_dump_style_t *style = &KNOT_DUMP_STYLE_DEFAULT;
	if (knot_rrset_txt_dump_data(rrset, 0, data, sizeof(data), style) > 0) {
		jsonw_str(w, key, data);
	}
}

static void json_print_section(jsonw_t *w, const char *name,
                               const knot_pktsection_t *section)
{
	if (section->count == 0) {
		return;
	}

	char str[16];

	jsonw_list(w, name);

	for (int i = 0; i < section->count; i++) {
		const knot_rrset_t *rr = knot_pkt_rr(section, i);
		jsonw_object(w, NULL);
		json_dname(w, "NAME", rr->owner);
		jsonw_int(w, "TYPE", rr->type);
		if (knot_rrtype_to_string(rr->type, str, sizeof(str)) > 0) {
			jsonw_str(w, "TYPEname", str);
		}
		jsonw_int(w, "CLASS", rr->rclass);
		if (rr->type != KNOT_RRTYPE_OPT && // OPT class meaning is different.
		    knot_rrclass_to_string(rr->rclass, str, sizeof(str)) > 0) {
			jsonw_str(w, "CLASSname", str);
		}
		jsonw_int(w, "TTL", rr->ttl);
		if (rr->type != KNOT_RRTYPE_OPT) { // OPT with HEX rdata.
			json_rdata(w, rr);
		}
		jsonw_int(w, "RDLENGTH", rr->rrs.rdata->len);
		if (rr->rrs.rdata->len > 0 ) {
			jsonw_hex(w, "RDATAHEX", rr->rrs.rdata->data, rr->rrs.rdata->len);
		}
		jsonw_end(w);
	}

	jsonw_end(w);
}

static void print_packet_json(jsonw_t *w, const knot_pkt_t *pkt, time_t time)
{
	if (pkt == NULL) {
		return;
	}

	char str[16];

	struct tm tm;
	char date[64];
	localtime_r(&time, &tm);
	strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S%z", &tm);
	jsonw_str(w, "dateString", date);
	jsonw_int(w, "dateSeconds", time);

	jsonw_int(w, "msgLength", pkt->size);

	if (pkt->parsed >= KNOT_WIRE_HEADER_SIZE) {
		jsonw_int(w, "ID", knot_wire_get_id(pkt->wire));
		jsonw_int(w, "QR", (bool)knot_wire_get_qr(pkt->wire));
		jsonw_int(w, "Opcode", knot_wire_get_opcode(pkt->wire));
		jsonw_int(w, "AA", (bool)knot_wire_get_aa(pkt->wire));
		jsonw_int(w, "TC", (bool)knot_wire_get_tc(pkt->wire));
		jsonw_int(w, "RD", (bool)knot_wire_get_rd(pkt->wire));
		jsonw_int(w, "RA", (bool)knot_wire_get_ra(pkt->wire));
		jsonw_int(w, "AD", (bool)knot_wire_get_ad(pkt->wire));
		jsonw_int(w, "CD", (bool)knot_wire_get_cd(pkt->wire));
		jsonw_int(w, "RCODE", knot_wire_get_rcode(pkt->wire));
		jsonw_int(w, "QDCOUNT", knot_wire_get_qdcount(pkt->wire));
		jsonw_int(w, "ANCOUNT", knot_wire_get_ancount(pkt->wire));
		jsonw_int(w, "NSCOUNT", knot_wire_get_nscount(pkt->wire));
		jsonw_int(w, "ARCOUNT", knot_wire_get_arcount(pkt->wire));
	}
	if (knot_wire_get_qdcount(pkt->wire) == 1) {
		json_dname(w, "QNAME", knot_pkt_qname(pkt));
		jsonw_int(w, "QTYPE", knot_pkt_qtype(pkt));
		if (knot_rrtype_to_string(knot_pkt_qtype(pkt), str, sizeof(str)) > 0) {
			jsonw_str(w, "QTYPEname", str);
		}
		jsonw_int(w, "QCLASS", knot_pkt_qclass(pkt));
		if (knot_rrclass_to_string(knot_pkt_qclass(pkt), str, sizeof(str)) > 0) {
			jsonw_str(w, "QCLASSname", str);
		}
	}
	if (pkt->rrset_count) {
		json_print_section(w, "answerRRs", knot_pkt_section(pkt, KNOT_ANSWER));
		json_print_section(w, "authorityRRs", knot_pkt_section(pkt, KNOT_AUTHORITY));
		json_print_section(w, "additionalRRs", knot_pkt_section(pkt, KNOT_ADDITIONAL));
	}
	if (pkt->parsed < pkt->size) {
		jsonw_hex(w, "messageOctetsHEX", pkt->wire, pkt->size);
	}
}

knot_pkt_t *create_empty_packet(const uint16_t max_size)
{
	// Create packet skeleton.
	knot_pkt_t *packet = knot_pkt_new(NULL, max_size, NULL);
	if (packet == NULL) {
		DBG_NULL;
		return NULL;
	}

	// Set random sequence id.
	knot_wire_set_id(packet->wire, dnssec_random_uint16_t());

	return packet;
}

jsonw_t *print_header_xfr_json(const knot_pkt_t *query,
                               const time_t     exec_time,
                               const style_t    *style)
{
	if (style == NULL) {
		DBG_NULL;
		return NULL;
	}

	jsonw_t *w = jsonw_new(stdout, JSON_INDENT);
	if (w == NULL) {
		return NULL;
	}

	if (style->show_query) {
		jsonw_object(w, NULL);
		jsonw_object(w, "queryMessage");
		print_packet_json(w, query, exec_time);
		jsonw_end(w);
		jsonw_list(w, "responseMessage");
	} else {
		jsonw_list(w, NULL);
	}

	return w;
}

void print_data_xfr_json(jsonw_t          *w,
                         const knot_pkt_t *reply,
                         const time_t     exec_time)
{
	if (w == NULL) {
		DBG_NULL;
		return;
	}

	jsonw_object(w, NULL);
	print_packet_json(w, reply, exec_time);
	jsonw_end(w);
}

void print_footer_xfr_json(jsonw_t       **w,
                           const style_t *style)
{
	if (w == NULL || style == NULL) {
		DBG_NULL;
		return;
	}

	jsonw_end(*w); // list (responseMessage)
	if (style->show_query) {
		jsonw_end(*w); // object
	}

	jsonw_free(w);
	*w = NULL;
}

void print_header_xfr(const knot_pkt_t *packet, const style_t *style)
{
	if (style == NULL) {
		DBG_NULL;
		return;
	}

	char xfr[16] = "AXFR";

	switch (knot_pkt_qtype(packet)) {
	case KNOT_RRTYPE_AXFR:
		break;
	case KNOT_RRTYPE_IXFR:
		xfr[0] = 'I';
		break;
	default:
		return;
	}

	if (style->show_header) {
		char *owner = knot_dname_to_str_alloc(knot_pkt_qname(packet));
		if (style->style.ascii_to_idn != NULL) {
			style->style.ascii_to_idn(&owner);
		}
		if (owner != NULL) {
			printf(";; %s for %s\n", xfr, owner);
			free(owner);
		}
	}
}

void print_data_xfr(const knot_pkt_t *packet,
                    const style_t    *style)
{
	if (packet == NULL || style == NULL) {
		DBG_NULL;
		return;
	}

	const knot_pktsection_t *answers = knot_pkt_section(packet, KNOT_ANSWER);

	switch (style->format) {
	case FORMAT_DIG:
		print_section_dig(knot_pkt_rr(answers, 0), answers->count, style);
		break;
	case FORMAT_HOST:
		print_section_host(knot_pkt_rr(answers, 0), answers->count, style);
		break;
	case FORMAT_FULL:
		print_section_full(knot_pkt_rr(answers, 0), answers->count, style, true);

		// Print TSIG record.
		if (style->show_tsig && knot_pkt_has_tsig(packet)) {
			print_section_full(packet->tsig_rr, 1, style, false);
		}
		break;
	default:
		break;
	}
}

void print_footer_xfr(const size_t  total_len,
                      const size_t  msg_count,
                      const size_t  rr_count,
                      const net_t   *net,
                      const float   elapsed,
                      const time_t  exec_time,
                      const style_t *style)
{
	if (style == NULL) {
		DBG_NULL;
		return;
	}

	if (style->show_footer) {
		print_footer(total_len, msg_count, rr_count, net, elapsed,
		             exec_time, true);
	}
}

void print_packets_json(const knot_pkt_t *query,
                        const knot_pkt_t *reply,
                        const net_t      *net,
                        const time_t     exec_time,
                        const style_t    *style)
{
	if (style == NULL) {
		DBG_NULL;
		return;
	}

	jsonw_t *w = jsonw_new(stdout, JSON_INDENT);
	if (w == NULL) {
		return;
	}
	jsonw_object(w, NULL);

	if (style->show_query) {
		jsonw_object(w, "queryMessage");
		print_packet_json(w, query, exec_time);
		jsonw_end(w);
		jsonw_object(w, "responseMessage");
	}

	print_packet_json(w, reply, exec_time);

	if (style->show_query) {
		jsonw_end(w);
	}

	jsonw_end(w);
	jsonw_free(&w);
}

void print_packet(const knot_pkt_t *packet,
                  const net_t      *net,
                  const size_t     size,
                  const float      elapsed,
                  const time_t     exec_time,
                  const bool       incoming,
                  const style_t    *style)
{
	if (packet == NULL || style == NULL) {
		DBG_NULL;
		return;
	}

	const knot_pktsection_t *answers = knot_pkt_section(packet,
	                                                    KNOT_ANSWER);
	const knot_pktsection_t *authority = knot_pkt_section(packet,
	                                                      KNOT_AUTHORITY);
	const knot_pktsection_t *additional = knot_pkt_section(packet,
	                                                       KNOT_ADDITIONAL);

	uint16_t qdcount = knot_wire_get_qdcount(packet->wire);
	uint16_t ancount = knot_wire_get_ancount(packet->wire);
	uint16_t nscount = knot_wire_get_nscount(packet->wire);
	uint16_t arcount = knot_wire_get_arcount(packet->wire);

	// Disable additionals printing if there are no other records.
	// OPT record may be placed anywhere within additionals!
	if (knot_pkt_has_edns(packet) && arcount == 1) {
		arcount = 0;
	}

	// Print packet information header.
	if (style->show_header) {
		if (net != NULL) {
#ifdef ENABLE_QUIC
			if (net->quic.params.enable) {
				print_quic(&net->quic);
			} else
#endif
			{
				print_tls(&net->tls);
#ifdef LIBNGHTTP2
				print_https(&net->https);
#endif
			}
		}
		print_header(packet, style);
	}

	// Print EDNS section.
	if (style->show_edns && knot_pkt_has_edns(packet)) {
		printf("%s", style->show_section ? "\n;; EDNS PSEUDOSECTION:\n;; " : ";;");
		print_section_opt(packet, style);
	}

	// Print DNS sections.
	switch (style->format) {
	case FORMAT_DIG:
		if (ancount > 0) {
			print_section_dig(knot_pkt_rr(answers, 0), ancount, style);
		}
		break;
	case FORMAT_HOST:
		if (ancount > 0) {
			print_section_host(knot_pkt_rr(answers, 0), ancount, style);
		} else {
			print_error_host(packet, style);
		}
		break;
	case FORMAT_NSUPDATE:
		if (style->show_question && qdcount > 0) {
			printf("%s", style->show_section ? "\n;; ZONE SECTION:\n;; " : ";;");
			print_section_question(knot_pkt_qname(packet),
			                       knot_pkt_qclass(packet),
			                       knot_pkt_qtype(packet),
			                       style);
		}

		if (style->show_answer && ancount > 0) {
			printf("%s", style->show_section ? "\n;; PREREQUISITE SECTION:\n" : "");
			print_section_full(knot_pkt_rr(answers, 0), ancount, style, true);
		}

		if (style->show_authority && nscount > 0) {
			printf("%s", style->show_section ? "\n;; UPDATE SECTION:\n" : "");
			print_section_full(knot_pkt_rr(authority, 0), nscount, style, true);
		}

		if (style->show_additional && arcount > 0) {
			printf("%s", style->show_section ? "\n;; ADDITIONAL DATA:\n" : "");
			print_section_full(knot_pkt_rr(additional, 0), arcount, style, true);
		}
		break;
	case FORMAT_FULL:
		if (style->show_question && qdcount > 0) {
			printf("%s", style->show_section ? "\n;; QUESTION SECTION:\n;; " : ";;");
			print_section_question(knot_pkt_wire_qname(packet),
			                       knot_pkt_qclass(packet),
			                       knot_pkt_qtype(packet),
			                       style);
		}

		if (style->show_answer && ancount > 0) {
			printf("%s", style->show_section ? "\n;; ANSWER SECTION:\n" : "");
			print_section_full(knot_pkt_rr(answers, 0), ancount, style, true);
		}

		if (style->show_authority && nscount > 0) {
			printf("%s", style->show_section ? "\n;; AUTHORITY SECTION:\n" : "");
			print_section_full(knot_pkt_rr(authority, 0), nscount, style, true);
		}

		if (style->show_additional && arcount > 0) {
			printf("%s", style->show_section ? "\n;; ADDITIONAL SECTION:\n" : "");
			print_section_full(knot_pkt_rr(additional, 0), arcount, style, true);
		}
		break;
	default:
		break;
	}

	// Print TSIG section.
	if (style->show_tsig && knot_pkt_has_tsig(packet)) {
		printf("%s", style->show_section ? "\n;; TSIG PSEUDOSECTION:\n" : "");
		print_section_full(packet->tsig_rr, 1, style, false);
	}

	// Print packet statistics.
	if (style->show_footer) {
		printf("\n");
		print_footer(size, 0, 0, net, elapsed, exec_time, incoming);
	}
}
