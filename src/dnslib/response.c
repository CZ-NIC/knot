#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>

#include "response.h"
#include "rrset.h"
#include "common.h"
#include "packet.h"
#include "descriptor.h"

enum {
	DEFAULT_ANCOUNT = 6,
	DEFAULT_NSCOUNT = 8,
	DEFAULT_ARCOUNT = 28,
	DEFAULT_DOMAINS_IN_RESPONSE = 22,
	DEFAULT_TMP_DOMAINS = 5
};

enum {
	PREALLOC_RESPONSE = sizeof(dnslib_response_t),
	PREALLOC_QNAME = 256,

	PREALLOC_ANSWER = DEFAULT_ANCOUNT * sizeof(dnslib_dname_t *),
	PREALLOC_AUTHORITY = DEFAULT_NSCOUNT * sizeof(dnslib_dname_t *),
	PREALLOC_ADDITIONAL = DEFAULT_ARCOUNT * sizeof(dnslib_dname_t *),

	PREALLOC_RRSETS = PREALLOC_ANSWER
	                  + PREALLOC_AUTHORITY
	                  + PREALLOC_ADDITIONAL,
	PREALLOC_DOMAINS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(dnslib_dname_t *),
	PREALLOC_OFFSETS =
		DEFAULT_DOMAINS_IN_RESPONSE * sizeof(size_t *),
	PREALLOC_TMP_DOMAINS =
		DEFAULT_TMP_DOMAINS * sizeof(dnslib_dname_t *),

	PREALLOC_TOTAL = PREALLOC_RESPONSE
	                 + PREALLOC_QNAME
	                 + PREALLOC_RRSETS
	                 + PREALLOC_DOMAINS
	                 + PREALLOC_OFFSETS
	                 + PREALLOC_TMP_DOMAINS
};

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static void dnslib_response_parse_host_edns(dnslib_response_t *response,
                                     const uint8_t *edns_wire, short edns_size)
{

}

/*----------------------------------------------------------------------------*/

static void dnslib_response_init_pointers(dnslib_response_t *resp)
{
	// put QNAME directly after the structure
	resp->question.qname =
		(dnslib_dname_t *)((char *)resp + PREALLOC_RESPONSE);

	// then answer, authority and additional sections
	resp->answer = (dnslib_rrset_t *)
	                   ((char *)resp->question.qname + PREALLOC_QNAME);
	resp->authority = resp->answer + DEFAULT_ANCOUNT;
	resp->additional = resp->authority + DEFAULT_NSCOUNT;

	resp->max_ancount = DEFAULT_ANCOUNT;
	resp->max_nscount = DEFAULT_NSCOUNT;
	resp->max_arcount = DEFAULT_ARCOUNT;

	// then domain names for compression and offsets
	resp->compression.dnames = (dnslib_dname_t *)
	                               (resp->additional + DEFAULT_ARCOUNT);
	resp->compression.offsets = (size_t *)
		(resp->compression.dnames + DEFAULT_DOMAINS_IN_RESPONSE);

	resp->compression.max = DEFAULT_DOMAINS_IN_RESPONSE;

	resp->tmp_dnames = (dnslib_dname_t **)
		(resp->compression.offsets + DEFAULT_DOMAINS_IN_RESPONSE);

	resp->tmp_dname_max = DEFAULT_TMP_DOMAINS;

	assert((char *)(resp->tmp_dnames + DEFAULT_TMP_DOMAINS)
	       == (char *)resp + PREALLOC_TOTAL);
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_init(dnslib_response_t *resp,
                                 const uint8_t *edns_wire, short edns_size)
{
	memset(resp, 0, PREALLOC_TOTAL);

	resp->edns_wire = edns_wire;
	resp->edns_size = edns_size;

	if (edns_wire != NULL && edns_size > 0) {
		// parse given EDNS record and save max size
		dnslib_response_parse_host_edns(resp, edns_wire, edns_size);
	}

	// save default pointers to the space after the structure
	dnslib_response_init_pointers(resp);
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_header(const uint8_t **pos, size_t *remaining,
                                        dnslib_header_t *header)
{
	if (pos == NULL || *pos == NULL || remaining == NULL
	    || header == NULL) {
		return -1;
	}

	if (*remaining < DNSLIB_PACKET_HEADER_SIZE) {
		return -2;
	}

	header->id = dnslib_packet_get_id(*pos);
	header->flags1 = dnslib_packet_get_flags1(*pos);
	header->flags2 = dnslib_packet_get_flags2(*pos);
	header->qdcount = dnslib_packet_get_qdcount(*pos);
	header->ancount = dnslib_packet_get_ancount(*pos);
	header->nscount = dnslib_packet_get_nscount(*pos);
	header->arcount = dnslib_packet_get_arcount(*pos);

	*pos += DNSLIB_PACKET_HEADER_SIZE;
	*remaining -= DNSLIB_PACKET_HEADER_SIZE;

	return 0;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_question(const uint8_t **pos,
                                          size_t *remaining,
                                          dnslib_question_t *question)
{
	if (pos == NULL || *pos == NULL || remaining == NULL
	    || question == NULL) {
		return -1;
	}

	if (*remaining < DNSLIB_PACKET_QUESTION_MIN_SIZE) {
		return -2;  // malformed
	}

	// domain name must end with 0, so just search for 0
	int i = 0;
	while (i < *remaining && (*pos)[i] != 0) {
		++i;
	}

	if (i == *remaining || *remaining - i - 1 < 4) {
		return -2;  // no 0 found or not enough data left
	}

	question->qname = dnslib_dname_new_from_wire(*pos, i + 1, NULL);
	*pos += i + 1;
	question->qtype = dnslib_packet_read_u16(*pos);
	*pos += 2;
	question->qclass = dnslib_packet_read_u16(*pos);
	*pos += 2;

	*remaining -= (i + 5);

	return 0;
}

/*----------------------------------------------------------------------------*/

static int dnslib_response_parse_client_edns(const uint8_t **pos,
                                             size_t *remaining,
                                             dnslib_edns_data_t *edns)
{
	if (pos == NULL || *pos == NULL || remaining == NULL
	    || edns == NULL) {
		return -1;
	}

	if (*remaining < DNSLIB_PACKET_RR_MIN_SIZE) {
		return -2;
	}

	// owner of EDNS OPT RR must be root (0)
	if (**pos != 0) {
		return -2;
	}
	*pos += 1;

	// check the type of the record (must be OPT)
	if (dnslib_packet_read_u16(*pos) != DNSLIB_RRTYPE_OPT) {
		return -2;
	}
	*pos += 2;

	edns->payload = dnslib_packet_read_u16(*pos);
	*pos += 2;
	edns->ext_rcode = *(*pos)++;
	edns->version = *(*pos)++;
	// skip Z
	*pos += 2;

	// ignore RDATA, but move pos behind them
	uint16_t rdlength = dnslib_packet_read_u16(*pos);
	*remaining -= 11;

	if (*remaining < rdlength) {
		return -3;
	}

	*pos += 2 + rdlength;
	*remaining -= rdlength;

	return 0;
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_free_tmp_domains(dnslib_response_t *resp)
{
	for (int i = 0; i < resp->tmp_dname_count; ++i) {
		dnslib_dname_free(&resp->tmp_dnames[i]);
	}
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_free_allocated_space(dnslib_response_t *resp)
{
	if (resp->max_ancount > DEFAULT_ANCOUNT) {
		free(resp->answer);
	}
	if (resp->max_nscount > DEFAULT_NSCOUNT) {
		free(resp->authority);
	}
	if (resp->max_arcount > DEFAULT_ARCOUNT) {
		free(resp->additional);
	}

	if (resp->compression.max > DEFAULT_DOMAINS_IN_RESPONSE) {
		free(resp->compression.dnames);
		free(resp->compression.offsets);
	}

	if (resp->tmp_dname_max > DEFAULT_TMP_DOMAINS) {
		free(resp->tmp_dnames);
	}
}

/*----------------------------------------------------------------------------*/

static void dnslib_response_dump(const dnslib_response_t *resp)
{
	printf("DNS response:\n-------------------------------------\n");

	printf("\nHeader:\n");
	printf("  ID: %u", resp->header.id);
	printf("  FLAGS: %s %s %s %s %s %s %s\n",
	       dnslib_packet_flags_get_qr(resp->header.flags1) ? "qr" : "",
	       dnslib_packet_flags_get_aa(resp->header.flags1) ? "aa" : "",
	       dnslib_packet_flags_get_tc(resp->header.flags1) ? "tc" : "",
	       dnslib_packet_flags_get_rd(resp->header.flags1) ? "rd" : "",
	       dnslib_packet_flags_get_ra(resp->header.flags2) ? "ra" : "",
	       dnslib_packet_flags_get_ad(resp->header.flags2) ? "ad" : "",
	       dnslib_packet_flags_get_cd(resp->header.flags2) ? "cd" : "");
	printf("  QDCOUNT: %u\n", resp->header.qdcount);
	printf("  ANCOUNT: %u\n", resp->header.ancount);
	printf("  NSCOUNT: %u\n", resp->header.nscount);
	printf("  ARCOUNT: %u\n", resp->header.arcount);

	printf("\nQuestion:\n");
	char *qname = dnslib_dname_to_str(resp->question.qname);
	printf("  QNAME: %s\n", qname);
	free(qname);
	printf("  QTYPE: %u (%s)\n", resp->question.qtype,
	       dnslib_rrtype_to_string(resp->question.qtype));
	printf("  QCLASS: %u (%s)\n", resp->question.qclass,
	       dnslib_rrclass_to_string(resp->question.qclass));

	/*! \todo Dumping of Answer, Authority and Additional sections. */

	printf("\nEDNS - client:\n");
	printf("  Version: %u\n", resp->edns_query.version);
	printf("  Payload: %u\n", resp->edns_query.payload);
	printf("  Extended RCODE: %u\n", resp->edns_query.ext_rcode);

	printf("\n-------------------------------------\n");
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_response_t *dnslib_response_new_empty(const uint8_t *edns_wire,
                                             short edns_size)
{
	dnslib_response_t *resp = (dnslib_response_t *)malloc(PREALLOC_TOTAL);
	CHECK_ALLOC_LOG(resp);

	dnslib_response_init(resp, edns_wire, edns_size);

	return resp;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_parse_query(dnslib_response_t *resp,
                                 const uint8_t *query_wire, size_t query_size)
{
	int err = 0;

	const uint8_t *pos = query_wire;
	size_t remaining = query_size;

	if ((err = dnslib_response_parse_header(
	               &pos, &remaining, &resp->header))) {
		return err;
	}

	if ((err = dnslib_response_parse_question(
	               &pos, &remaining, &resp->question))) {
		return err;
	}

	if ((err = dnslib_response_parse_client_edns(
	               &pos, &remaining, &resp->edns_query))) {
		return err;
	}

	if (remaining > 0) {
		// some trailing garbage; ignore, but log
		log_info("%d bytes of trailing garbage in query.\n", remaining);
	}

	dnslib_response_dump(resp);

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_answer(dnslib_response_t *response,
                                     const dnslib_rrset_t *rrset, int tc)
{
	return -1;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_authority(dnslib_response_t *response,
                                        const dnslib_rrset_t *rrset, int tc)
{
	return -1;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_aditional(dnslib_response_t *response,
                                        const dnslib_rrset_t *rrset, int tc)
{
	return -1;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_to_wire(dnslib_response_t *response,
                            uint8_t **resp_wire, size_t *resp_size)
{
	return -1;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_free(dnslib_response_t **response)
{
	if (response == NULL || *response == NULL) {
		return;
	}

	// free temporary domain names
	dnslib_response_free_tmp_domains(*response);
	// check if some additional space was allocated for the response
	dnslib_response_free_allocated_space(*response);

	free(*response);
	*response = NULL;
}
