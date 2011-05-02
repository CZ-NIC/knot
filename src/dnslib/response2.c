#include "dnslib/response2.h"

/*----------------------------------------------------------------------------*/

int dnslib_packet_response_from_query(dnslib_packet_t *response,
                                      dnslib_packet_t *query)
{
	/*! \todo Implement! */
	return DNSLIB_ERROR;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_opt(dnslib_packet_t *resp,
                            const dnslib_opt_rr_t *opt_rr,
                            int override_max_size)
{
	if (resp == NULL || opt_rr == NULL) {
		return DNSLIB_EBADARG;
	}

	// copy the OPT RR
	resp->edns_response.version = opt_rr->version;
	resp->edns_response.ext_rcode = opt_rr->ext_rcode;
	resp->edns_response.payload = opt_rr->payload;
	resp->edns_response.size = opt_rr->size;

	// if max size is set, it means there is some reason to be that way,
	// so we can't just set it to higher value

	if (override_max_size && resp->max_size > 0
	    && resp->max_size < opt_rr->payload) {
		return DNSLIB_EPAYLOAD;
	}

	// set max size (less is OK)
	if (override_max_size) {
		resp->max_size = resp->edns_response.payload;
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_set_max_size(dnslib_packet_t *resp, int max_size)
{
	if (resp == NULL || max_size <= 0) {
		return DNSLIB_EBADARG;
	}

	if (resp->max_size < max_size) {
		// reallocate space for the wire format (and copy anything
		// that might have been there before
		uint8_t *wire_new = (uint8_t *)malloc(max_size);
		if (wire_new == NULL) {
			return DNSLIB_ENOMEM;
		}

		memcpy(wire_new, resp->wireformat, resp->max_size);
		resp->wireformat = wire_new;
	}

	// set max size
	resp->max_size = max_size;

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_answer(dnslib_packet_t *response,
                                     const dnslib_rrset_t *rrset, int tc,
                                     int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return DNSLIB_EBADARG;
	}

	debug_dnslib_response("add_rrset_answer()\n");
	assert(response->header.arcount == 0);
	assert(response->header.nscount == 0);

	if (response->an_rrsets == response->max_an_rrsets
	    && dnslib_response_realloc_rrsets(&response->answer,
	          &response->max_an_rrsets, DEFAULT_ANCOUNT, STEP_ANCOUNT)
	       != DNSLIB_EOK) {
		return DNSLIB_ENOMEM;
	}

	if (check_duplicates && dnslib_response_contains(response, rrset)) {
		return DNSLIB_EOK;
	}

	debug_dnslib_response("Trying to add RRSet to Answer section.\n");
	debug_dnslib_response("RRset: %p\n", rrset);
	debug_dnslib_response("Owner: %p\n", rrset->owner);

	int rrs = dnslib_response_try_add_rrset(response->answer,
	                                        &response->an_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->edns_response.size,
	                                        rrset, tc, compr_cs);

	if (rrs >= 0) {
		response->header.ancount += rrs;
		return DNSLIB_EOK;
	}

	return DNSLIB_ESPACE;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_authority(dnslib_packet_t *response,
                                        const dnslib_rrset_t *rrset, int tc,
                                        int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return DNSLIB_EBADARG;
	}

	assert(response->header.arcount == 0);

	if (response->ns_rrsets == response->max_ns_rrsets
	    && dnslib_response_realloc_rrsets(&response->authority,
			&response->max_ns_rrsets, DEFAULT_NSCOUNT, STEP_NSCOUNT)
		!= 0) {
		return DNSLIB_ENOMEM;
	}

	if (check_duplicates && dnslib_response_contains(response, rrset)) {
		return DNSLIB_EOK;
	}

	debug_dnslib_response("Trying to add RRSet to Authority section.\n");

	int rrs = dnslib_response_try_add_rrset(response->authority,
	                                        &response->ns_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->edns_response.size,
	                                        rrset, tc, compr_cs);

	if (rrs >= 0) {
		response->header.nscount += rrs;
		return DNSLIB_EOK;
	}

	return DNSLIB_ESPACE;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_rrset_additional(dnslib_packet_t *response,
                                         const dnslib_rrset_t *rrset, int tc,
                                         int check_duplicates, int compr_cs)
{
	if (response == NULL || rrset == NULL) {
		return DNSLIB_EBADARG;
	}

	// if this is the first additional RRSet, add EDNS OPT RR first
	if (response->header.arcount == 0
	    && response->edns_response.version != EDNS_NOT_SUPPORTED) {
		dnslib_response_edns_to_wire(response);
	}

	if (response->ar_rrsets == response->max_ar_rrsets
	    && dnslib_response_realloc_rrsets(&response->additional,
			&response->max_ar_rrsets, DEFAULT_ARCOUNT, STEP_ARCOUNT)
		!= 0) {
		return DNSLIB_ENOMEM;
	}

	if (check_duplicates && dnslib_response_contains(response, rrset)) {
		return DNSLIB_EOK;
	}

	debug_dnslib_response("Trying to add RRSet to Additional section.\n");

	int rrs = dnslib_response_try_add_rrset(response->additional,
	                                        &response->ar_rrsets, response,
	                                        response->max_size
	                                        - response->size, rrset, tc,
	                                        compr_cs);

	if (rrs >= 0) {
		response->header.arcount += rrs;
		return DNSLIB_EOK;
	}

	return DNSLIB_ESPACE;
}

/*----------------------------------------------------------------------------*/

void dnslib_response_set_rcode(dnslib_packet_t *response, short rcode)
{
	dnslib_wire_flags_set_rcode(&response->header.flags2, rcode);
	dnslib_wire_set_rcode(response->wireformat, rcode);
}

/*----------------------------------------------------------------------------*/

void dnslib_response_set_aa(dnslib_packet_t *response)
{
	dnslib_wire_flags_set_aa(&response->header.flags1);
	dnslib_wire_set_aa(response->wireformat);
}

/*----------------------------------------------------------------------------*/

void dnslib_response_set_tc(dnslib_packet_t *response)
{
	dnslib_wire_flags_set_tc(&response->header.flags1);
	dnslib_wire_set_tc(response->wireformat);
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_tmp_rrset(dnslib_packet_t *response,
                                  dnslib_rrset_t *tmp_rrset)
{
	if (response->tmp_rrsets_count == response->tmp_rrsets_max
	    && dnslib_response_realloc_rrsets(&response->tmp_rrsets,
			&response->tmp_rrsets_max, DEFAULT_TMP_RRSETS,
			STEP_TMP_RRSETS) != DNSLIB_EOK) {
		return DNSLIB_ENOMEM;
	}

	response->tmp_rrsets[response->tmp_rrsets_count++] = tmp_rrset;

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_response_add_nsid(dnslib_packet_t *response, const uint8_t *data,
                             uint16_t length)
{
	return dnslib_edns_add_option(&response->edns_response,
	                              EDNS_OPTION_NSID, length, data);
}

/*----------------------------------------------------------------------------*/

int dnslib_response_to_wire(dnslib_packet_t *resp,
                            uint8_t **resp_wire, size_t *resp_size)
{
	if (resp == NULL || resp_wire == NULL || resp_size == NULL
	    || *resp_wire != NULL) {
		return DNSLIB_EBADARG;
	}

	assert(resp->size <= resp->max_size);

	// if there are no additional RRSets, add EDNS OPT RR
	if (resp->header.arcount == 0
	    && resp->edns_response.version != EDNS_NOT_SUPPORTED) {
	    dnslib_response_edns_to_wire(resp);
	}

	// set ANCOUNT to the packet
	dnslib_wire_set_ancount(resp->wireformat, resp->header.ancount);
	// set NSCOUNT to the packet
	dnslib_wire_set_nscount(resp->wireformat, resp->header.nscount);
	// set ARCOUNT to the packet
	dnslib_wire_set_arcount(resp->wireformat, resp->header.arcount);

	//assert(response->size == size);
	*resp_wire = resp->wireformat;
	*resp_size = resp->size;

	return DNSLIB_EOK;
}
