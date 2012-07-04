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

#include <stdlib.h>
#include "packet/query.h"

#include "util/error.h"
#include "util/wire.h"

/*----------------------------------------------------------------------------*/

int knot_query_rr_to_wire(const knot_rrset_t *rrset, const knot_rdata_t *rdata,
			  uint8_t **wire, uint8_t *endp)
{
	/* Store owner. */
	knot_dname_t *owner = rrset->owner;
	if (*wire + owner->size > endp) {
		return KNOT_ENOMEM;
	}
	memcpy(*wire, owner->name, owner->size);
	*wire += owner->size;

	if (*wire + 10 > endp) {
		return KNOT_ENOMEM;
	}

	/* Write RR header. */
	knot_wire_write_u16(*wire, rrset->type); *wire += 2;
	knot_wire_write_u16(*wire, rrset->rclass); *wire += 2;
	knot_wire_write_u32(*wire, rrset->ttl); *wire += 4;
	knot_wire_write_u16(*wire, 0); *wire += 2; /* RDLENGTH reserve. */
	uint8_t *rdlength_p = *wire - 2;
	uint16_t rdlength = 0;

	/* Write data. */
	knot_dname_t *dname = 0;
	uint16_t *raw_data = 0;
	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(rrset->type);

	for (int i = 0; i < rdata->count; ++i) {
		switch (desc->wireformat[i]) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
		case KNOT_RDATA_WF_LITERAL_DNAME:

			/* Check space for dname. */
			dname = knot_rdata_item(rdata, i)->dname;
			if (*wire + dname->size > endp) {
				return KNOT_ESPACE;
			}

			/* Save domain name. */
			memcpy(*wire, dname->name, dname->size);
			*wire += dname->size;
			rdlength += dname->size;
			break;
		default:
			raw_data = knot_rdata_item(rdata, i)->raw_data;
			if (*wire + raw_data[0] > endp) {
				return KNOT_ESPACE;
			}

			/* Copy data. */
			memcpy(*wire, raw_data + 1, raw_data[0]);
			*wire += raw_data[0];
			rdlength += raw_data[0];
			break;

		}
	}

	/* Store rdlength. */
	knot_wire_write_u16(rdlength_p, rdlength);

	return KNOT_EOK;
}
/*----------------------------------------------------------------------------*/

int knot_query_dnssec_requested(const knot_packet_t *query)
{
	if (query == NULL) {
		return KNOT_EBADARG;
	}

	return ((knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED)
	        && knot_edns_do(&query->opt_rr));
}

/*----------------------------------------------------------------------------*/

int knot_query_nsid_requested(const knot_packet_t *query)
{
	if (query == NULL) {
		return KNOT_EBADARG;
	}

	return ((knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED)
	        && knot_edns_has_option(&query->opt_rr, EDNS_OPTION_NSID));
}

/*----------------------------------------------------------------------------*/

int knot_query_edns_supported(const knot_packet_t *query)
{
	if (query == NULL) {
		return KNOT_EBADARG;
	}

	return (knot_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED);
}

/*----------------------------------------------------------------------------*/

int knot_query_init(knot_packet_t *query)
{
	if (query == NULL) {
		return KNOT_EBADARG;
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

/*----------------------------------------------------------------------------*/

int knot_query_add_rrset_authority(knot_packet_t *query,
				   const knot_rrset_t *rrset)
{
	if (query == NULL || rrset == NULL) {
		return KNOT_EBADARG;
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
	
	uint8_t *pos = startp;

	const knot_rdata_t *rdata = 0;
	while ((rdata = knot_rrset_rdata_next(rrset, rdata))) {
		knot_query_rr_to_wire(rrset, rdata, &pos, endp);
	}

	size_t written = (pos - startp);
	query->size += written;
	++query->ns_rrsets;
	++query->header.nscount;

	return KNOT_EOK;
}

