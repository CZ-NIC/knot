#include "dnslib/query.h"

#include "dnslib/error.h"
#include "dnslib/wire.h"

/*----------------------------------------------------------------------------*/

int dnslib_query_dnssec_requested(const dnslib_packet_t *query)
{
	return dnslib_edns_do(&query->opt_rr);
}

/*----------------------------------------------------------------------------*/

int dnslib_query_nsid_requested(const dnslib_packet_t *query)
{
	return dnslib_edns_has_option(&query->opt_rr, EDNS_OPTION_NSID);
}

/*----------------------------------------------------------------------------*/

int dnslib_query_init(dnslib_packet_t *query)
{
	// set the qr bit to 0
	dnslib_wire_flags_clear_qr(&query->header.flags1);

	uint8_t *pos = query->wireformat;
	dnslib_packet_header_to_wire(&query->header, &pos, &query->size);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_query_set_question(dnslib_packet_t *query,
                              const dnslib_question_t *question)
{
	if (query == NULL || question == NULL) {
		return DNSLIB_EBADARG;
	}

	query->question.qname = question->qname;
	query->question.qclass = question->qclass;
	query->question.qtype = question->qtype;
	query->header.qdcount = 1;

	// convert the Question to wire format right away
	dnslib_packet_question_to_wire(query);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_query_set_opcode(dnslib_packet_t *query, uint8_t opcode)
{
	if (query == NULL) {
		return DNSLIB_EBADARG;
	}
	// set the OPCODE in the structure
	dnslib_wire_flags_set_opcode(query->header.flags1, opcode);
	// set the OPCODE in the wire format
	dnslib_wire_set_opcode(query->wireformat, opcode);

	return DNSLIB_EOK;
}
