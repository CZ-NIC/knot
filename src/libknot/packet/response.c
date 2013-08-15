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

#include "packet/response.h"
#include "util/wire.h"
#include "common.h"
#include "util/debug.h"
#include "rrset.h"
#include "packet/packet.h"
#include "edns.h"

/*----------------------------------------------------------------------------*/

/*!
 * \brief Compare suffixes and calculate score (number of matching labels).
 *
 * Update current best score.
 */
static bool knot_response_compr_score(uint8_t *n, uint8_t *p, uint8_t labels,
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

/*!
 * \brief Align name and reference to a common number of suffix labels.
 */
static uint8_t knot_response_compr_align(uint8_t **name, uint8_t nlabels,
                                         uint8_t **ref, uint8_t reflabels,
                                         uint8_t *wire)
{
	for (unsigned j = nlabels; j < reflabels; ++j)
		*ref = knot_wire_next_label(*ref, wire);

	for (unsigned j = reflabels; j < nlabels; ++j)
		*name = knot_wire_next_label(*name, wire);

	return (nlabels < reflabels) ? nlabels : reflabels;
}

int knot_response_compress_dname(const knot_dname_t *dname, knot_compr_t *compr,
                                 uint8_t *dst, size_t max)
{
	if (!dname || !compr || !dst) {
		return KNOT_EINVAL;
	}

	/* Do not compress small dnames. */
	uint8_t *name = dname->name;
	if (dname->size <= 2) {
                if (dname->size > max)
                        return KNOT_ESPACE;
                memcpy(dst, name, dname->size);
                return dname->size;
	}

	/* Align and compare name and pointer in the compression table. */
	unsigned i = 0;
	unsigned lbcount = 0;
	unsigned match_id = 0;
	knot_compr_ptr_t match = { 0, 0 };
	for (; i < COMPR_MAXLEN && compr->table[i].off > 0; ++i) {
		uint8_t *name = dname->name;
		uint8_t *ref = compr->wire + compr->table[i].off;
		lbcount = knot_response_compr_align(&name, dname->label_count,
		                                    &ref, compr->table[i].lbcount,
		                                    compr->wire);

		if (knot_response_compr_score(name, ref, lbcount, compr->wire,
		                              &match)) {
			match_id = i;
			if (match.lbcount == dname->label_count)
				break; /* Best match, break. */
		}
	}

	/* Write non-matching prefix. */
	unsigned written = 0;
	for (unsigned j = match.lbcount; j < dname->label_count; ++j) {
		if (written + *name + 1 > max)
			return KNOT_ESPACE;
		memcpy(dst + written, name, *name + 1);
		written += *name + 1;
		name = knot_wire_next_label(name, compr->wire);
	}

	/* Write out pointer covering suffix. */
	if (*name != '\0') {
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
	if (match.lbcount == dname->label_count ||
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
		compr->table[i].lbcount = dname->label_count;
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
                                        const knot_rrset_t *rrset, int tc)
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
	} else if (tc) {
		dbg_response_verb("Setting TC bit.\n");
		knot_wire_flags_set_tc(&resp->header.flags1);
		knot_wire_set_tc(resp->wireformat);
	}

	return rr_count > 0 ? rr_count : ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Reallocate space for RRSets.
 *
 * \param rrsets Space for RRSets.
 * \param max_count Size of the space available for the RRSets.
 * \param default_max_count Size of the space pre-allocated for the RRSets when
 *        the response structure was initialized.
 * \param step How much the space should be increased.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
static int knot_response_realloc_rrsets(const knot_rrset_t ***rrsets,
                                          short *max_count,
                                          short default_max_count, short step)
{
	int free_old = (*max_count) != default_max_count;
	const knot_rrset_t **old = *rrsets;

	short new_max_count = *max_count + step;
	const knot_rrset_t **new_rrsets = (const knot_rrset_t **)malloc(
		new_max_count * sizeof(knot_rrset_t *));
	CHECK_ALLOC_LOG(new_rrsets, KNOT_ENOMEM);

	memcpy(new_rrsets, *rrsets, (*max_count) * sizeof(knot_rrset_t *));

	*rrsets = new_rrsets;
	*max_count = new_max_count;

	if (free_old) {
		free(old);
	}

	return KNOT_EOK;
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
                                          short default_max_count, short step)
{
	dbg_packet_detail("Max count: %d, default max count: %d\n",
	                  *max_count, default_max_count);
	int free_old = (*max_count) != default_max_count;

	const knot_node_t **old_nodes = *nodes;
	const knot_dname_t **old_snames = *snames;

	short new_max_count = *max_count + step;

	const knot_node_t **new_nodes = (const knot_node_t **)malloc(
		new_max_count * sizeof(knot_node_t *));
	CHECK_ALLOC_LOG(new_nodes, KNOT_ENOMEM);

	const knot_dname_t **new_snames = (const knot_dname_t **)malloc(
	                        new_max_count * sizeof(knot_dname_t *));
	if (new_snames == NULL) {
		free(new_nodes);
		return KNOT_ENOMEM;
	}

	memcpy(new_nodes, *nodes, (*max_count) * sizeof(knot_node_t *));
	memcpy(new_snames, *snames, (*max_count) * sizeof(knot_dname_t *));

	*nodes = new_nodes;
	*snames = new_snames;
	*max_count = new_max_count;

	if (free_old) {
		free(old_nodes);
		free(old_snames);
	}

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

	// set the qr bit to 1
	knot_wire_flags_set_qr(&response->header.flags1);

	uint8_t *pos = response->wireformat;
	knot_packet_header_to_wire(&response->header, &pos,
	                                &response->size);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_response_init_from_query(knot_packet_t *response,
                                  knot_packet_t *query,
                                  int copy_question)
{

	if (response == NULL || query == NULL) {
		return KNOT_EINVAL;
	}

	// copy the header from the query
	memcpy(&response->header, &query->header, sizeof(knot_header_t));

	/*! \todo Constant. */
	size_t to_copy = 12;

	if (copy_question) {
		// copy the Question section (but do not copy the QNAME)
		memcpy(&response->question, &query->question,
		       sizeof(knot_question_t));

		/* Insert QNAME into compression table. */
		response->compression[0].off = KNOT_WIRE_HEADER_SIZE;
		response->compression[0].lbcount = response->question.qname->label_count;


		/*! \todo Constant. */
		to_copy += 4 + knot_dname_size(response->question.qname);
	} else {
		response->header.qdcount = 0;
		knot_wire_set_qdcount(response->wireformat, 0);
	}

	assert(response->max_size >= to_copy);
	if (response->wireformat != query->wireformat) {
		memcpy(response->wireformat, query->wireformat, to_copy);
	}
	response->size = to_copy;

	// set the qr bit to 1
	knot_wire_flags_set_qr(&response->header.flags1);
	knot_wire_set_qr(response->wireformat);

	// clear TC flag
	knot_wire_flags_clear_tc(&response->header.flags1);
	knot_wire_clear_tc(response->wireformat);

	// clear AD flag
	knot_wire_flags_clear_ad(&response->header.flags2);
	knot_wire_clear_ad(response->wireformat);

	// clear RA flag
	knot_wire_flags_clear_ra(&response->header.flags2);
	knot_wire_clear_ad(response->wireformat);

	// set counts to 0
	response->header.ancount = 0;
	knot_wire_set_ancount(response->wireformat, 0);
	response->header.nscount = 0;
	knot_wire_set_nscount(response->wireformat, 0);
	response->header.arcount = 0;
	knot_wire_set_arcount(response->wireformat, 0);

	response->query = query;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_response_clear(knot_packet_t *resp, int clear_question)
{
	if (resp == NULL) {
		return;
	}

	resp->size = (clear_question) ? KNOT_WIRE_HEADER_SIZE
	              : KNOT_WIRE_HEADER_SIZE + 4
	                + knot_dname_size(resp->question.qname);
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

	resp->header.ancount = 0;
	resp->header.nscount = 0;
	resp->header.arcount = 0;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_opt(knot_packet_t *resp,
                          const knot_opt_rr_t *opt_rr,
                          int override_max_size,
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

	// if max size is set, it means there is some reason to be that way,
	// so we can't just set it to higher value

	if (override_max_size && resp->max_size > 0
	    && resp->max_size < opt_rr->payload) {
		return KNOT_EOK;
	}

	// set max size (less is OK)
	if (override_max_size) {
		dbg_response("Overriding max size to: %u\n",
		             resp->opt_rr.payload);
		return knot_packet_set_max_size(resp, resp->opt_rr.payload);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_answer(knot_packet_t *response,
                                   knot_rrset_t *rrset, int tc,
                                   int check_duplicates,
                                   int rotate)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	dbg_response_verb("add_rrset_answer()\n");
	assert(response->header.arcount == 0);
	assert(response->header.nscount == 0);

	if (response->an_rrsets == response->max_an_rrsets
	    && knot_response_realloc_rrsets(&response->answer,
	          &response->max_an_rrsets, DEFAULT_ANCOUNT, STEP_ANCOUNT)
	       != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_packet_contains(response, rrset,
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
	                                        rrset, tc);

	if (rrs >= 0) {
		response->header.ancount += rrs;

		if (rotate) {
			// do round-robin rotation of the RRSet
			knot_rrset_rotate(rrset);
		}

		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_authority(knot_packet_t *response,
                                      knot_rrset_t *rrset, int tc,
                                      int check_duplicates,
                                      int rotate)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	assert(response->header.arcount == 0);

	if (response->ns_rrsets == response->max_ns_rrsets
	    && knot_response_realloc_rrsets(&response->authority,
			&response->max_ns_rrsets, DEFAULT_NSCOUNT, STEP_NSCOUNT)
		!= 0) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_packet_contains(response, rrset,
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
	                                        rrset, tc);

	if (rrs >= 0) {
		response->header.nscount += rrs;

		if (rotate) {
			// do round-robin rotation of the RRSet
			knot_rrset_rotate(rrset);
		}

		return KNOT_EOK;
	}

	return KNOT_ESPACE;
}

/*----------------------------------------------------------------------------*/

int knot_response_add_rrset_additional(knot_packet_t *response,
                                       knot_rrset_t *rrset, int tc,
                                       int check_duplicates,
                                       int rotate)
{
	if (response == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	// if this is the first additional RRSet, add EDNS OPT RR first
	if (response->header.arcount == 0
	    && response->opt_rr.version != EDNS_NOT_SUPPORTED
	    && (ret = knot_packet_edns_to_wire(response)) != KNOT_EOK) {
		return ret;
	}

	if (response->ar_rrsets == response->max_ar_rrsets
	    && knot_response_realloc_rrsets(&response->additional,
			&response->max_ar_rrsets, DEFAULT_ARCOUNT, STEP_ARCOUNT)
		!= 0) {
		return KNOT_ENOMEM;
	}

	if (check_duplicates && knot_packet_contains(response, rrset,
	                                            KNOT_RRSET_COMPARE_PTR)) {
		return KNOT_EOK;
	}

	dbg_response_verb("Trying to add RRSet to Additional section.\n");

	int rrs = knot_response_try_add_rrset(response->additional,
	                                        &response->ar_rrsets, response,
	                                        response->max_size
	                                        - response->size
	                                        - response->tsig_size, rrset,
	                                        tc);

	if (rrs >= 0) {
		response->header.arcount += rrs;

		if (rotate) {
			// do round-robin rotation of the RRSet
			knot_rrset_rotate(rrset);
		}

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

	knot_wire_flags_set_rcode(&response->header.flags2, rcode);
	knot_wire_set_rcode(response->wireformat, rcode);
}

/*----------------------------------------------------------------------------*/

void knot_response_set_aa(knot_packet_t *response)
{
	if (response == NULL) {
		return;
	}

	knot_wire_flags_set_aa(&response->header.flags1);
	knot_wire_set_aa(response->wireformat);
}

/*----------------------------------------------------------------------------*/

void knot_response_set_tc(knot_packet_t *response)
{
	if (response == NULL) {
		return;
	}

	knot_wire_flags_set_tc(&response->header.flags1);
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
	                                      DEFAULT_WILDCARD_NODES,
	                                     STEP_WILDCARD_NODES) != KNOT_EOK) {
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
