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

#include <config.h>
#include <stdlib.h>
#include "packet/query.h"
#include "util/wire.h"
#include "libknot/common.h"

/*----------------------------------------------------------------------------*/

int knot_query_dnssec_requested(const knot_packet_t *query)
{
	if (query == NULL) {
		return KNOT_EINVAL;
	}

	return ((knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED)
	        && knot_edns_do(&query->opt_rr));
}

/*----------------------------------------------------------------------------*/

int knot_query_nsid_requested(const knot_packet_t *query)
{
	if (query == NULL) {
		return KNOT_EINVAL;
	}

	return ((knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED)
	        && knot_edns_has_option(&query->opt_rr, EDNS_OPTION_NSID));
}

/*----------------------------------------------------------------------------*/

int knot_query_edns_supported(const knot_packet_t *query)
{
	if (query == NULL) {
		return KNOT_EINVAL;
	}

	return (knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED);
}

/*----------------------------------------------------------------------------*/

int knot_query_init(knot_packet_t *query)
{
	if (query == NULL) {
		return KNOT_EINVAL;
	}
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
		return KNOT_EINVAL;
	}

	query->question.qname = question->qname;
	query->question.qclass = question->qclass;
	query->question.qtype = question->qtype;
	query->header.qdcount = 1;

	// convert the Question to wire format right away
	return knot_packet_question_to_wire(query);
}

/*----------------------------------------------------------------------------*/

int knot_query_set_opcode(knot_packet_t *query, uint8_t opcode)
{
	if (query == NULL) {
		return KNOT_EINVAL;
	}
	// set the OPCODE in the structure
	knot_wire_flags_set_opcode(&query->header.flags1, opcode);
	// set the OPCODE in the wire format
	knot_wire_set_opcode(query->wireformat, opcode);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_query_add_rrset_authority(knot_packet_t *query,
				   const knot_rrset_t *rrset)
{
	if (query == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	if (query->ns_rrsets == query->max_ns_rrsets) {
		size_t oldsize = query->max_ns_rrsets * sizeof(knot_rrset_t *);
		++query->max_ns_rrsets;
		size_t newsize = query->max_ns_rrsets * sizeof(knot_rrset_t *);
		const knot_rrset_t ** na = malloc(newsize);
		if (na == 0) {
			query->max_ns_rrsets = 0;
			return KNOT_ENOMEM;
		} else {
			memcpy(na, query->authority, oldsize);
			free(query->authority);
			query->authority = na;
		}
	}

	/* Append to packet. */
	query->authority[query->ns_rrsets] = rrset;

	/* Write to wire. */
	uint8_t *startp = query->wireformat + query->size;
	uint8_t *endp = query->wireformat + query->max_size;

	assert(endp - startp > query->opt_rr.size + query->tsig_size);
	// reserve space for OPT RR
	/*! \todo Why here??? */
	endp -= query->opt_rr.size;
	/* Reserve space for TSIG RR */
	endp -= query->tsig_size;

	size_t written = 0;
	uint16_t rr_count = 0;
	int ret = knot_rrset_to_wire(rrset, startp, &written, query->max_size,
	                             &rr_count, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}
	query->size += written;
	++query->ns_rrsets;
	++query->header.nscount;

	return KNOT_EOK;
}
