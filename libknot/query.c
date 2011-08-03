#include "query.h"

#include "error.h"
#include "wire.h"

/*----------------------------------------------------------------------------*/

int knot_query_dnssec_requested(const knot_packet_t *query)
{
	return ((knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED)
	        && knot_edns_do(&query->opt_rr));
}

/*----------------------------------------------------------------------------*/

int knot_query_nsid_requested(const knot_packet_t *query)
{
	return ((knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED)
	        && knot_edns_has_option(&query->opt_rr, EDNS_OPTION_NSID));
}

/*----------------------------------------------------------------------------*/

int knot_query_edns_supported(const knot_packet_t *query)
{
	return (knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED);
}

/*----------------------------------------------------------------------------*/

int knot_query_init(knot_packet_t *query)
{
	// set the qr bit to 0
	knot_wire_flags_clear_qr(&query->header.flags1);

	uint8_t *pos = query->wireformat;
	knot_packet_header_to_wire(&query->header, &pos, &query->size);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_query_set_question(knot_packet_t *query,
                              const knot_question_t *question)
{
	if (query == NULL || question == NULL) {
		return KNOT_EBADARG;
	}

	query->question.qname = question->qname;
	query->question.qclass = question->qclass;
	query->question.qtype = question->qtype;
	query->header.qdcount = 1;

	// convert the Question to wire format right away
	knot_packet_question_to_wire(query);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_query_set_opcode(knot_packet_t *query, uint8_t opcode)
{
	if (query == NULL) {
		return KNOT_EBADARG;
	}
	// set the OPCODE in the structure
	knot_wire_flags_set_opcode(&query->header.flags1, opcode);
	// set the OPCODE in the wire format
	knot_wire_set_opcode(query->wireformat, opcode);

	return KNOT_EOK;
}
