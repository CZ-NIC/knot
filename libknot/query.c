/*  Copyright (C) 2011 CZ.NIC Labs

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
