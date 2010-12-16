#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "response.h"
#include "rrset.h"
#include "common.h"
#include "packet.h"

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

void dnslib_response_parse_host_edns(dnslib_response_t *response,
                                     const uint8_t *edns_wire, short edns_size)
{

}

/*----------------------------------------------------------------------------*/

void dnslib_response_init_pointers(dnslib_response_t *resp)
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

void dnslib_response_init(dnslib_response_t *resp, const uint8_t *edns_wire,
                          short edns_size)
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

int dnslib_response_parse_header(const uint8_t **pos, size_t *remaining,
                                 dnslib_header_t *header)
{
	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_parse_question(const uint8_t **pos, size_t *remaining,
                                   dnslib_question_t *question)
{
	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_parse_client_edns(const uint8_t **pos, size_t *remaining,
                                      dnslib_edns_data_t *edns)
{
	return 0;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_free_tmp_domains(dnslib_response_t *resp)
{
	for (int i = 0; i < resp->tmp_dname_count; ++i) {
		dnslib_dname_free(&resp->tmp_dnames[i]);
	}
}

/*----------------------------------------------------------------------------*/

void dnslib_response_free_allocated_space(dnslib_response_t *resp)
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
