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
#include <stdint.h>

#include "libknot/packet/response.h"
#include "libknot/util/wire.h"
#include "libknot/common.h"
#include "libknot/util/debug.h"
#include "libknot/rrset.h"
#include "libknot/packet/packet.h"
#include "libknot/edns.h"

/*----------------------------------------------------------------------------*/

/*!
 * \brief Compare suffixes and calculate score (number of matching labels).
 *
 * Update current best score.
 */
static bool knot_response_compr_score(const uint8_t *n, const uint8_t *p,
                                      uint8_t labels,
                                      uint8_t *wire, knot_compr_ptr_t *match)
{
	uint16_t score = 0;
	uint16_t off = 0;
	while (*n != '\0') {
		/* Can't exceed current best coverage. */
		if (score + labels <= match->lbcount)
			return false; /* Early cut. */
		/* Keep track of contiguous matches. */
		if (*n == *p && memcmp(n + 1, p + 1, *n) == 0) {
			if (score == 0)
				off = (p - wire);
			++score;
		} else {
			score = 0; /* Non-contiguous match. */
		}
		n = knot_wire_next_label(n, wire);
		p = knot_wire_next_label(p, wire);
		--labels;
	}

	/* New best score. */
	if (score > match->lbcount && off <= KNOT_WIRE_PTR_MAX) {
		match->lbcount = score;
		match->off = off;
		return true;
	}

	return false;
}

int knot_response_compress_dname(const knot_dname_t *dname, knot_compr_t *compr,
                                 uint8_t *dst, size_t max)
{
	if (!dname || !compr || !dst) {
		return KNOT_EINVAL;
	}

	/* Do not compress small dnames. */
	int name_labels = knot_dname_labels(dname, NULL);
	if (name_labels < 0) {
		return name_labels; // error code
	}
	if (*dname == '\0') {
		if (max < 1)
			return KNOT_ESPACE;
		*dst = *dname;
		return 1;
	}

	assert(name_labels >= 0 && name_labels <= KNOT_DNAME_MAXLABELS);

	/* Align and compare name and pointer in the compression table. */
	unsigned i = 0;
	unsigned lbcount = 0;
	unsigned match_id = 0;
	knot_compr_ptr_t match = { 0, 0 };
	for (; i < COMPR_MAXLEN && compr->table[i].off > 0; ++i) {
		const uint8_t *sample = dname;
		const uint8_t *ref = compr->wire + compr->table[i].off;
		lbcount = knot_dname_align(&sample, name_labels,
		                           &ref, compr->table[i].lbcount,
		                           compr->wire);

		if (knot_response_compr_score(sample, ref, lbcount, compr->wire,
		                              &match)) {
			match_id = i;
			if (match.lbcount == name_labels)
				break; /* Best match, break. */
		}
	}

	/* Write non-matching prefix. */
	unsigned written = 0;
	for (unsigned j = match.lbcount; j < name_labels; ++j) {
		if (written + *dname + 1 > max)
			return KNOT_ESPACE;
		memcpy(dst + written, dname, *dname + 1);
		written += *dname + 1;
		dname = (knot_dname_t *)knot_wire_next_label(dname, compr->wire);
	}

	/* Write out pointer covering suffix. */
	if (*dname != '\0') {
		if (written + sizeof(uint16_t) > max)
			return KNOT_ESPACE;
		knot_wire_put_pointer(dst + written, match.off);
		written += sizeof(uint16_t);
	} else {
		/* Not covered by compression table, write terminal. */
		if (written + 1 > max)
			return KNOT_ESPACE;
		*(dst + written) = '\0';
		written += 1;
	}

	/* Promote good matches. */
	if (match_id > 1) {
		match = compr->table[match_id];
		compr->table[match_id] = compr->table[match_id - 1];
		compr->table[match_id - 1] = match;
	}

	/* Do not insert if exceeds bounds or full match. */
	if (match.lbcount == name_labels ||
	    compr->wire_pos > KNOT_WIRE_PTR_MAX)
		return written;

	/* If table is full, elect name from the lower 1/4 of the table
	 * and replace it. */
	if (i == COMPR_MAXLEN) {
		i = COMPR_FIXEDLEN + rand() % COMPR_VOLATILE;
		compr->table[i].off = 0;
	}

	/* Store in dname table. */
	if (compr->table[i].off == 0) {
		compr->table[i].off = (uint16_t)compr->wire_pos;
		compr->table[i].lbcount = name_labels;
	}

	return written;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tries to add RRSet to the response.
 *
 * This function tries to convert the RRSet to wire format and add it to the
 * wire format of the response and if successful, adds the RRSet to the given
 * list (and updates its size). If the RRSet did not fit into the available
 * space (\a max_size), it is omitted as a whole and the TC bit may be set
 * (according to \a tc).
 *
 * \param rrsets Lists of RRSets to which this RRSet should be added.
 * \param rrset_count Number of RRSets in the list.
 * \param resp Response structure where the RRSet should be added.
 * \param max_size Maximum available space in wire format of the response.
 * \param rrset RRSet to add.
 * \param tc Set to <> 0 if omitting the RRSet should cause the TC bit to be
 *           set in the response.
 *
 * \return Count of RRs added to the response or KNOT_ESPACE if the RRSet did
 *         not fit in the available space.
 */
static int knot_response_try_add_rrset(const knot_rrset_t **rrsets,
                                        short *rrset_count,
                                        knot_packet_t *resp,
                                        size_t max_size,
                                        const knot_rrset_t *rrset, uint32_t flags)
{
	//short size = knot_response_rrset_size(rrset, &resp->compression);

dbg_response_exec(
	char *name = knot_dname_to_str(rrset->owner);
	dbg_response_verb("\nAdding RRSet with owner %s and type %u: \n",
	                  name, rrset->type);
	free(name);
);
	uint8_t *pos = resp->wireformat + resp->size;
	size_t size = max_size;
	compression_param_t param;
	param.compressed_dnames = resp->compression;
	param.wire_pos = resp->size;
	param.wire = resp->wireformat;
	uint16_t rr_count = 0;
	int ret = knot_rrset_to_wire(rrset, pos, &size, max_size,
	                             &rr_count, &param);

	if (ret != KNOT_EOK) {
		dbg_response("Failed to convert RRSet to wire. (%s).\n,",
		             knot_strerror(ret));
	}

	if (rr_count > 0) {
		rrsets[(*rrset_count)++] = rrset;
		resp->size += size;
		dbg_response_verb("RRset added, size: %zu, RRs: %d, total "
		                  "size of response: %zu\n\n", size, rr_count,
		                  resp->size);
	} else if (!(flags & KNOT_PF_NOTRUNC)) {
		dbg_response_verb("Setting TC bit.\n");
		knot_wire_set_tc(resp->wireformat);
	}

	return rr_count > 0 ? rr_count : ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Reallocate space for Wildcard nodes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
static int knot_response_realloc_wc_nodes(const knot_node_t ***nodes,
                                          const knot_dname_t ***snames,
                                          short *max_count,
                                          mm_ctx_t *mm)
{

	short new_max_count = *max_count + RRSET_ALLOC_STEP;

	const knot_node_t **new_nodes = mm->alloc(mm->ctx,
		new_max_count * sizeof(knot_node_t *));
	CHECK_ALLOC_LOG(new_nodes, KNOT_ENOMEM);

	const knot_dname_t **new_snames = mm->alloc(mm->ctx,
	                        new_max_count * sizeof(knot_dname_t *));
	if (new_snames == NULL) {
		mm->free(new_nodes);
		return KNOT_ENOMEM;
	}

	memcpy(new_nodes, *nodes, (*max_count) * sizeof(knot_node_t *));
	memcpy(new_snames, *snames, (*max_count) * sizeof(knot_dname_t *));

	mm->free(*nodes);
	mm->free(*snames);

	*nodes = new_nodes;
	*snames = new_snames;
	*max_count = new_max_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int knot_response_init(knot_packet_t *response)
{
	if (response == NULL) {
		return KNOT_EINVAL;
	}

	if (response->max_size < KNOT_WIRE_HEADER_SIZE) {
		return KNOT_ESPACE;
	}

	/* Empty packet header. */
	memset(response->wireformat, 0, KNOT_WIRE_HEADER_SIZE);
	response->size = KNOT_WIRE_HEADER_SIZE;

	/* Set the qr bit to 1. */
	uint8_t flags = 0;
	knot_wire_flags_set_qr(&flags);
	knot_wire_set_flags1(response->wireformat, flags);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_response_init_from_query(knot_packet_t *response, knot_packet_t *query)
{
	if (response == NULL || query == NULL) {
		return KNOT_EINVAL;
	}

	/* Header + question size. */
	size_t to_copy = knot_packet_question_size(query);
	assert(to_copy <= response->max_size);
	if (response->wireformat != query->wireformat) {
		memcpy(response->wireformat, query->wireformat, to_copy);
	}

	/* Insert QNAME into compression table. */
	uint8_t *qname = response->wireformat + KNOT_WIRE_HEADER_SIZE;
	response->compression[0].off = KNOT_WIRE_HEADER_SIZE;
	response->compression[0].lbcount = knot_dname_labels(qname, NULL);

	/* Update size and flags. */
	knot_wire_set_qdcount(response->wireformat, 1);
	knot_wire_set_qr(response->wireformat);
	knot_wire_clear_tc(response->wireformat);
	knot_wire_clear_ad(response->wireformat);
	knot_wire_clear_ra(response->wireformat);

	/* Reset RR counts */
	knot_wire_set_ancount(response->wireformat, 0);
	knot_wire_set_nscount(response->wireformat, 0);
	knot_wire_set_arcount(response->wireformat, 0);

	response->query = query;
	response->size = to_copy;
	response->qname_size = query->qname_size;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_response_clear(knot_packet_t *resp)
{
	if (resp == NULL) {
		return;
	}

	/* Keep question. */
	resp->size = knot_packet_question_size(resp);
	resp->an_rrsets = 0;
	resp->ns_rrsets = 0;
	resp->ar_rrsets = 0;

	/* Clear compression table. */
	memset(resp->compression, 0, COMPR_MAXLEN * sizeof(knot_compr_ptr_t));

	/*! \todo Temporary RRSets are not deallocated, which may potentially
	 *        lead to memory leaks should this function be used in other
	 *        cases than with XFR-out.
	 */
	knot_packet_free_tmp_rrsets(resp);
	resp->tmp_rrsets_count = 0;

	/*! \todo If this function is used in other cases than with XFR-out,
	 *        the list of wildcard nodes should be cleared here.
	 */

	knot_wire_set_ancount(resp->wireformat, 0);
	knot_wire_set_nscount(resp->wireformat, 0);
	knot_wire_set_arcount(resp->wireformat, 0);
}

/*----------------------------------------------------------------------------*/

int knot_response_add_opt(knot_packet_t *resp,
                          const knot_opt_rr_t *opt_rr,
                          int add_nsid)
{
	if (resp == NULL || opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	// copy the OPT RR

	/*! \todo Change the way OPT RR is handled in response.
	 *        Pointer to nameserver->opt_rr should be enough.
	 */

	resp->opt_rr.version = opt_rr->version;
	resp->opt_rr.ext_rcode = opt_rr->ext_rcode;
	resp->opt_rr.payload = opt_rr->payload;

	/*
	 * Add options only if NSID is requested.
	 *
	 * This is a bit hack and should be resolved in other way before some
	 * other options are supported.
	 */

	if (add_nsid) {
		resp->opt_rr.option_count = opt_rr->option_count;
		assert(resp->opt_rr.options == NULL);
		resp->opt_rr.options = (knot_opt_option_t *)malloc(
				 resp->opt_rr.option_count * sizeof(knot_opt_option_t));
		CHECK_ALLOC_LOG(resp->opt_rr.options, KNOT_ENOMEM);

		memcpy(resp->opt_rr.options, opt_rr->options,
		       resp->opt_rr.option_count * sizeof(knot_opt_option_t));

		// copy all data
		for (int i = 0; i < opt_rr->option_count; i++) {
			resp->opt_rr.options[i].data = (uint8_t *)malloc(
						resp->opt_rr.options[i].length);
			CHECK_ALLOC_LOG(resp->opt_rr.options[i].data, KNOT_ENOMEM);

			memcpy(resp->opt_rr.options[i].data,
			       opt_rr->options[i].data,
			       resp->opt_rr.options[i].length);
		}
		resp->opt_rr.size = opt_rr->size;
	} else {
		resp->opt_rr.size = EDNS_MIN_SIZE;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_answer(knot_packet_t *response,
                                   knot_rrset_t *rrset, uint32_t flags)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	dbg_response_verb("add_rrset_answer()\n");
	assert(knot_wire_get_arcount(response->wireformat) == 0);
	assert(knot_wire_get_nscount(response->wireformat) == 0);

	if (response->an_rrsets == response->max_an_rrsets
	    && knot_packet_realloc_rrsets(&response->answer,
	          &response->max_an_rrsets, &response->mm)
	       != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	if ((flags & KNOT_PF_CHECKDUP) && knot_packet_contains(response, rrset,
	                                            KNOT_RRSET_COMPARE_PTR)) {
		return KNOT_EOK;
	}

	dbg_response_verb("Trying to add RRSet to Answer section.\n");
	dbg_response_detail("RRset: %p\n", rrset);
	dbg_response_detail("Owner: %p\n", rrset->owner);

	int rrs = knot_response_try_add_rrset(response->answer,
	                                        &response->an_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->opt_rr.size
	                                        - response->tsig_size,
	                                      rrset, flags);

	if (rrs >= 0) {
		knot_wire_add_ancount(response->wireformat, rrs);
		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_authority(knot_packet_t *response,
                                      knot_rrset_t *rrset, uint32_t flags)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	assert(knot_wire_get_arcount(response->wireformat) == 0);

	if (response->ns_rrsets == response->max_ns_rrsets
	    && knot_packet_realloc_rrsets(&response->authority,
			&response->max_ns_rrsets, &response->mm)
		!= 0) {
		return KNOT_ENOMEM;
	}

	if ((flags & KNOT_PF_CHECKDUP) && knot_packet_contains(response, rrset,
	                                           KNOT_RRSET_COMPARE_PTR)) {
		return KNOT_EOK;
	}

	dbg_response_verb("Trying to add RRSet to Authority section.\n");

	int rrs = knot_response_try_add_rrset(response->authority,
	                                        &response->ns_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->opt_rr.size
	                                        - response->tsig_size,
	                                        rrset, flags);

	if (rrs >= 0) {
		knot_wire_add_nscount(response->wireformat, rrs);
		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_additional(knot_packet_t *response,
                                       knot_rrset_t *rrset, uint32_t flags)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	// if this is the first additional RRSet, add EDNS OPT RR first
	if (knot_wire_get_arcount(response->wireformat) == 0
	    && response->opt_rr.version != EDNS_NOT_SUPPORTED
	    && (ret = knot_packet_edns_to_wire(response)) != KNOT_EOK) {
		return ret;
	}

	if (response->ar_rrsets == response->max_ar_rrsets
	    && knot_packet_realloc_rrsets(&response->additional,
			&response->max_ar_rrsets, &response->mm)
		!= 0) {
		return KNOT_ENOMEM;
	}

	if ((flags & KNOT_PF_CHECKDUP) && knot_packet_contains(response, rrset,
	                                            KNOT_RRSET_COMPARE_PTR)) {
		return KNOT_EOK;
	}

	dbg_response_verb("Trying to add RRSet to Additional section.\n");

	int rrs = knot_response_try_add_rrset(response->additional,
	                                        &response->ar_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->tsig_size, rrset,
	                                        flags);

	if (rrs >= 0) {
		knot_wire_add_arcount(response->wireformat, rrs);
		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

void knot_response_set_rcode(knot_packet_t *response, short rcode)
{
	if (response == NULL) {
		return;
	}

	uint8_t flags = knot_wire_get_flags2(response->wireformat);
	knot_wire_flags_set_rcode(&flags, rcode);
	knot_wire_set_flags2(response->wireformat, flags);
}

/*----------------------------------------------------------------------------*/

void knot_response_set_aa(knot_packet_t *response)
{
	if (response == NULL) {
		return;
	}

	knot_wire_set_aa(response->wireformat);
}

/*----------------------------------------------------------------------------*/

void knot_response_set_tc(knot_packet_t *response)
{
	if (response == NULL) {
		return;
	}

	knot_wire_set_tc(response->wireformat);
}

/*----------------------------------------------------------------------------*/

int knot_response_add_nsid(knot_packet_t *response, const uint8_t *data,
                             uint16_t length)
{
	if (response == NULL) {
		return KNOT_EINVAL;
	}

	return knot_edns_add_option(&response->opt_rr,
	                              EDNS_OPTION_NSID, length, data);
}

/*----------------------------------------------------------------------------*/

int knot_response_add_wildcard_node(knot_packet_t *response,
                                    const knot_node_t *node,
                                    const knot_dname_t *sname)
{
	if (response == NULL || node == NULL || sname == NULL) {
		return KNOT_EINVAL;
	}

	if (response->wildcard_nodes.count == response->wildcard_nodes.max
	    && knot_response_realloc_wc_nodes(&response->wildcard_nodes.nodes,
	                                      &response->wildcard_nodes.snames,
	                                      &response->wildcard_nodes.max,
	                                      &response->mm) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	response->wildcard_nodes.nodes[response->wildcard_nodes.count] = node;
	response->wildcard_nodes.snames[response->wildcard_nodes.count] = sname;
	++response->wildcard_nodes.count;

	dbg_response_verb("Current wildcard nodes count: %d, max count: %d\n",
	             response->wildcard_nodes.count,
	             response->wildcard_nodes.max);

	return KNOT_EOK;
}
