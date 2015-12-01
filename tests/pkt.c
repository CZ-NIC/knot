/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include "libknot/libknot.h"
#include "libknot/descriptor.h"
#include "libknot/libknot.h"
#include "libknot/packet/pkt.h"
#include "libknot/rrtype/tsig.h"
#include "contrib/ucw/mempool.h"

#define TTL 7200
#define NAMECOUNT 3
#define DATACOUNT 3
const char *g_names[NAMECOUNT] = {
        "example.com",
        "ns1.example.com",
        "ns2.example.com"
};

const char *g_rdata[DATACOUNT] = {
        "\x04" "\xc2\x0c\x00\x01", /* 4B, 194.0.12.1" */
        "\x11" "\x03""ns1""\x07""example""\x03""com""\x00", /* domain name */
        "\x11" "\x03""ns2""\x07""example""\x03""com""\x00", /* domain name */
};

#define RDVAL(i) ((const uint8_t*)(g_rdata[(i)] + 1))
#define RDLEN(i) ((uint16_t)(g_rdata[(i)][0]))

/* @note Packet equivalence test, 5 checks. */
static void packet_match(knot_pkt_t *in, knot_pkt_t *out)
{
	/* Check counts */
	is_int(knot_wire_get_qdcount(out->wire),
	       knot_wire_get_qdcount(in->wire), "pkt: QD match");
	is_int(knot_wire_get_ancount(out->wire),
	       knot_wire_get_ancount(in->wire), "pkt: AN match");
	is_int(knot_wire_get_nscount(out->wire),
	       knot_wire_get_nscount(in->wire), "pkt: NS match");
	is_int(knot_wire_get_arcount(out->wire),
	       knot_wire_get_arcount(in->wire), "pkt: AR match");

	/* Check RRs */
	int rr_matched = 0;
	for (unsigned i = 0; i < NAMECOUNT; ++i) {
		if (knot_rrset_equal(&out->rr[i], &in->rr[i], KNOT_RRSET_COMPARE_WHOLE) > 0) {
			++rr_matched;
		}
	}
	is_int(NAMECOUNT, rr_matched, "pkt: RR content match");
}

int main(int argc, char *argv[])
{
	plan(25);

	/* Create memory pool context. */
	int ret = 0;
	mm_ctx_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	/* Create names and data. */
	knot_dname_t* dnames[NAMECOUNT] = {0};
	knot_rrset_t* rrsets[NAMECOUNT] = {0};
	for (unsigned i = 0; i < NAMECOUNT; ++i) {
		dnames[i] = knot_dname_from_str_alloc(g_names[i]);
	}

	uint8_t *edns_str = (uint8_t *)"ab";
	/* Create OPT RR. */
	knot_rrset_t opt_rr;
	ret = knot_edns_init(&opt_rr, 1024, 0, 0, &mm);
	if (ret != KNOT_EOK) {
		skip_block(25, "Failed to initialize OPT RR.");
		return 0;
	}
	/* Add NSID */
	ret = knot_edns_add_option(&opt_rr, KNOT_EDNS_OPTION_NSID,
	                           strlen((char *)edns_str), edns_str, &mm);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &mm);
		skip_block(25, "Failed to add NSID to OPT RR.");
		return 0;
	}

	/*
	 * Packet writer tests.
	 */

	/* Create packet. */
	knot_pkt_t *out = knot_pkt_new(NULL, MM_DEFAULT_BLKSIZE, &mm);
	ok(out != NULL, "pkt: new");

	/* Mark as response (not part of the test). */
	knot_wire_set_qr(out->wire);

	/* Secure packet. */
	const char *tsig_secret = "abcd";
	knot_tsig_key_t tsig_key;
	tsig_key.algorithm = DNSSEC_TSIG_HMAC_MD5;
	tsig_key.name = dnames[0];
	tsig_key.secret.data = (uint8_t *)strdup(tsig_secret);
	tsig_key.secret.size = strlen(tsig_secret);
	ret = knot_pkt_reserve(out, knot_tsig_wire_maxsize(&tsig_key));
	ok(ret == KNOT_EOK, "pkt: set TSIG key");

	/* Write question. */
	ret = knot_pkt_put_question(out, dnames[0], KNOT_CLASS_IN, KNOT_RRTYPE_A);
	ok(ret == KNOT_EOK, "pkt: put question");

	/* Add OPT to packet (empty NSID). */
	ret = knot_pkt_reserve(out, knot_edns_wire_size(&opt_rr));
	ok(ret == KNOT_EOK, "pkt: reserve OPT RR");

	/* Begin ANSWER section. */
	ret = knot_pkt_begin(out, KNOT_ANSWER);
	ok(ret == KNOT_EOK, "pkt: begin ANSWER");

	/* Write ANSWER section. */
	rrsets[0] = knot_rrset_new(dnames[0], KNOT_RRTYPE_A, KNOT_CLASS_IN, NULL);
	knot_dname_free(&dnames[0], NULL);
	knot_rrset_add_rdata(rrsets[0], RDVAL(0), RDLEN(0), TTL, NULL);
	ret = knot_pkt_put(out, KNOT_COMPR_HINT_QNAME, rrsets[0], 0);
	ok(ret == KNOT_EOK, "pkt: write ANSWER");

	/* Begin AUTHORITY. */
	ret = knot_pkt_begin(out, KNOT_AUTHORITY);
	ok(ret == KNOT_EOK, "pkt: begin AUTHORITY");

	/* Write rest to AUTHORITY. */
	ret = KNOT_EOK;
	for (unsigned i = 1; i < NAMECOUNT; ++i) {
		rrsets[i] = knot_rrset_new(dnames[i], KNOT_RRTYPE_NS, KNOT_CLASS_IN, NULL);
		knot_dname_free(&dnames[i], NULL);
		knot_rrset_add_rdata(rrsets[i], RDVAL(i), RDLEN(i), TTL, NULL);
		ret |= knot_pkt_put(out, KNOT_COMPR_HINT_NONE, rrsets[i], 0);
	}
	ok(ret == KNOT_EOK, "pkt: write AUTHORITY(%u)", NAMECOUNT - 1);

	/* Begin ADDITIONALS */
	ret = knot_pkt_begin(out, KNOT_ADDITIONAL);
	ok(ret == KNOT_EOK, "pkt: begin ADDITIONALS");

	/* Encode OPT RR. */
	ret = knot_pkt_put(out, KNOT_COMPR_HINT_NONE, &opt_rr, 0);
	ok(ret == KNOT_EOK, "pkt: write OPT RR");

	/*
	 * Packet reader tests.
	 */

	/* Create new packet from query packet. */
	knot_pkt_t *in = knot_pkt_new(out->wire, out->size, &out->mm);
	ok(in != NULL, "pkt: create packet for parsing");

	/* Read packet header. */
	ret = knot_pkt_parse_question(in);
	ok(ret == KNOT_EOK, "pkt: read header");

	/* Read packet payload. */
	ret = knot_pkt_parse_payload(in, 0);
	ok(ret == KNOT_EOK, "pkt: read payload");

	/* Compare parsed packet to written packet. */
	packet_match(in, out);

	/*
	 * Copied packet tests.
	 */
	knot_pkt_t *copy = knot_pkt_new(NULL, in->max_size, &in->mm);
	ret = knot_pkt_copy(copy, in);
	ok(ret == KNOT_EOK, "pkt: create packet copy");

	/* Compare copied packet to original. */
	packet_match(in, copy);

	/* Free packets. */
	knot_pkt_free(&copy);
	knot_pkt_free(&out);
	knot_pkt_free(&in);
	ok(in == NULL && out == NULL && copy == NULL, "pkt: free");

	/* Free extra data. */
	for (unsigned i = 0; i < NAMECOUNT; ++i) {
		knot_rrset_free(&rrsets[i], NULL);
	}
	free(tsig_key.secret.data);
	mp_delete((struct mempool *)mm.ctx);

	return 0;
}
