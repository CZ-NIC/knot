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
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <urcu.h>

#include "libknot/nameserver/name-server.h"
#include "libknot/updates/xfr-in.h"

#include "libknot/libknot.h"
#include "common/errcode.h"
#include "libknot/common.h"
#include "common/lists.h"
#include "libknot/util/debug.h"
#include "libknot/packet/pkt.h"
#include "libknot/consts.h"
#include "common/descriptor.h"
#include "libknot/updates/changesets.h"
#include "libknot/updates/ddns.h"
#include "libknot/tsig-op.h"
#include "libknot/rdata.h"
#include "libknot/dnssec/zone-nsec.h"

/*----------------------------------------------------------------------------*/

/*! \brief Maximum UDP payload with EDNS disabled. */
static const uint16_t MAX_UDP_PAYLOAD      = 512;

/*! \brief TTL of a CNAME synthetized from a DNAME. */
static const uint32_t SYNTH_CNAME_TTL      = 0;

/*! \brief Determines whether DNSSEC is enabled. */
static const int      DNSSEC_ENABLED       = 1;

/*! \brief Internal error code to propagate need for SERVFAIL response. */
static const int      NS_ERR_SERVFAIL      = -999;

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Finds zone where to search for the QNAME.
 *
 * \note As QTYPE DS requires special handling, this function finds a zone for
 *       a direct predecessor of QNAME in such case.
 *
 * \param zdb Zone database where to search for the proper zone.
 * \param qname QNAME.
 * \param qtype QTYPE.
 *
 * \return Zone to which QNAME belongs (according to QTYPE), or NULL if no such
 *         zone was found.
 */
const knot_zone_t *ns_get_zone_for_qname(knot_zonedb_t *zdb,
                                                  const knot_dname_t *qname,
                                                  uint16_t qtype)
{
	const knot_zone_t *zone;
	/*
	 * Find a zone in which to search.
	 *
	 * In case of DS query, we strip the leftmost label when searching for
	 * the zone (but use whole qname in search for the record), as the DS
	 * records are only present in a parent zone.
	 */
	if (qtype == KNOT_RRTYPE_DS) {
		const knot_dname_t *parent = knot_wire_next_label(qname, NULL);
		zone = knot_zonedb_find_suffix(zdb, parent);
		/* If zone does not exist, search for its parent zone,
		   this will later result to NODATA answer. */
		if (zone == NULL) {
			zone = knot_zonedb_find_suffix(zdb, qname);
		}
	} else {
		zone = knot_zonedb_find_suffix(zdb, qname);
	}

	return zone;
}

/*----------------------------------------------------------------------------*/

int ns_response_to_wire(knot_pkt_t *resp, uint8_t *wire,
                        size_t *wire_size)
{
	if (resp->size > *wire_size) {
		dbg_ns("Reponse size (%zu) larger than allowed wire size "
		         "(%zu).\n", resp->size, *wire_size);
		return NS_ERR_SERVFAIL;
	}

	if (resp->wire != wire) {
		dbg_ns("Wire format reallocated, copying to place for "
		       "wire.\n");
		memcpy(wire, resp->wire, resp->size);
	} else {
		dbg_ns("Using the same space or wire format.\n");
	}

	*wire_size = resp->size;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_tsig_required(int packet_nr)
{
	/*! \bug This can overflow to negative numbers. Proper solution is to
	 *       count exactly at one place for each incoming/outgoing packet
	 *       with packet_nr = (packet_nr + 1) % FREQ and require TSIG on 0.
	 */
	dbg_ns_verb("ns_tsig_required(%d): %d\n", packet_nr,
	            (packet_nr % KNOT_NS_TSIG_FREQ == 0));
	return (packet_nr % KNOT_NS_TSIG_FREQ == 0);
}

/*----------------------------------------------------------------------------*/

static int ns_xfr_send_and_clear(knot_ns_xfr_t *xfr, int add_tsig)
{
	assert(xfr != NULL);
	assert(xfr->query != NULL);
	assert(xfr->response != NULL);
	assert(xfr->wire != NULL);
	assert(xfr->send != NULL);

	// Transform the packet into wire format
	dbg_ns_verb("Converting response to wire format..\n");
	size_t real_size = xfr->wire_size;
	if (ns_response_to_wire(xfr->response, xfr->wire, &real_size) != 0) {
		return NS_ERR_SERVFAIL;
	}

	int res = 0;

	size_t digest_real_size = xfr->digest_max_size;

	dbg_ns_detail("xfr->tsig_key=%p\n", xfr->tsig_key);
	dbg_ns_detail("xfr->tsig_rcode=%d\n", xfr->tsig_rcode);

	if (xfr->tsig_key) {
		// add the data to TSIG data
		assert(KNOT_NS_TSIG_DATA_MAX_SIZE - xfr->tsig_data_size
		       >= xfr->wire_size);
		memcpy(xfr->tsig_data + xfr->tsig_data_size,
		       xfr->wire, real_size);
		xfr->tsig_data_size += real_size;
	}

	if (xfr->tsig_key && add_tsig) {
		if (xfr->packet_nr == 0) {
			/* Add key, digest and digest length. */
			dbg_ns_detail("Calling tsig_sign(): %p, %zu, %zu, "
			              "%p, %zu, %p, %zu, %p\n",
			              xfr->wire, real_size, xfr->wire_size,
			              xfr->digest, xfr->digest_size, xfr->digest,
			              digest_real_size, xfr->tsig_key);
			res = knot_tsig_sign(xfr->wire, &real_size,
			               xfr->wire_size, xfr->digest,
			               xfr->digest_size, xfr->digest,
			               &digest_real_size,
			               xfr->tsig_key, xfr->tsig_rcode,
			               xfr->tsig_prev_time_signed);
		} else {
			/* Add key, digest and digest length. */
			dbg_ns_detail("Calling tsig_sign_next()\n");
			res = knot_tsig_sign_next(xfr->wire, &real_size,
			                          xfr->wire_size,
			                          xfr->digest,
			                          xfr->digest_size,
			                          xfr->digest,
			                          &digest_real_size,
			                          xfr->tsig_key, xfr->tsig_data,
			                          xfr->tsig_data_size);
		}

		dbg_ns_verb("Sign function returned: %s\n", knot_strerror(res));
		dbg_ns_detail("Real size of digest: %zu\n", digest_real_size);

		if (res != KNOT_EOK) {
			return res;
		}

		assert(digest_real_size > 0);
		// save the new previous digest size
		xfr->digest_size = digest_real_size;

		// clear the TSIG data
		xfr->tsig_data_size = 0;

	} else if (xfr->tsig_rcode != 0) {
		dbg_ns_verb("Adding TSIG without signing, TSIG RCODE: %d.\n",
		            xfr->tsig_rcode);
		assert(xfr->tsig_rcode != KNOT_RCODE_BADTIME);
		// add TSIG without signing
		assert(xfr->query != NULL);

		const knot_rrset_t *tsig = xfr->query->tsig_rr;
		res = knot_tsig_add(xfr->wire, &real_size, xfr->wire_size,
		                    xfr->tsig_rcode, tsig);
		if (res != KNOT_EOK) {
			return res;
		}
	}

	// Send the response
	dbg_ns("Sending response (size %zu)..\n", real_size);
	//dbg_ns_hex((const char *)xfr->wire, real_size);
	res = xfr->send(xfr->session, &xfr->addr, xfr->wire, real_size);
	if (res < 0) {
		dbg_ns("Send returned %d\n", res);
		return res;
	} else if (res != real_size) {
		dbg_ns("AXFR did not send right amount of bytes."
		       " Transfer size: %zu, sent: %d\n", real_size, res);
	}

	// Clean the response structure
	dbg_ns_verb("Clearing response structure..\n");
	knot_pkt_clear_payload(xfr->response);

	// increment the packet number
	++xfr->packet_nr;
	if ((xfr->tsig_key && knot_ns_tsig_required(xfr->packet_nr))
	     || xfr->tsig_rcode != 0) {
		knot_pkt_tsig_set(xfr->response, xfr->tsig_key);
	} else {
		knot_pkt_tsig_set(xfr->response, NULL);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ns_prepare_response(knot_pkt_t *query, knot_pkt_t **resp,
                                    size_t max_size)
{

	assert(max_size >= 500);

	// initialize response packet structure
	*resp = knot_pkt_new(NULL, max_size, &query->mm);
	if (*resp == NULL) {
		dbg_ns("Failed to create packet structure.\n");
		return KNOT_ENOMEM;
	}

	int ret = knot_pkt_init_response(*resp, query);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to init response structure.\n");
		knot_pkt_free(resp);
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int32_t ns_serial_difference(uint32_t s1, uint32_t s2)
{
	return (((int64_t)s1 - s2) % ((int64_t)1 << 32));
}

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

knot_nameserver_t *knot_ns_create()
{
	knot_nameserver_t *ns = malloc(sizeof(knot_nameserver_t));
	if (ns == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	ns->data = 0;

	// Create zone database structure
	dbg_ns("Creating Zone Database structure...\n");
	ns->zone_db = knot_zonedb_new(0);
	if (ns->zone_db == NULL) {
		ERR_ALLOC_FAILED;
		free(ns);
		return NULL;
	}

	/* Prepare empty response with SERVFAIL error. */
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_HEADER_SIZE, NULL);
	if (pkt == NULL) {
		ERR_ALLOC_FAILED;
		free(ns);
		return NULL;
	}

	/* QR bit set. */
	knot_wire_set_qr(pkt->wire);
	knot_wire_set_rcode(pkt->wire, KNOT_RCODE_SERVFAIL);

	/* Store packet. */
	ns->err_response = pkt;

	ns->opt_rr = NULL;
	ns->identity = NULL;
	ns->version = NULL;
	return ns;
}

/*----------------------------------------------------------------------------*/

int knot_ns_parse_packet(knot_pkt_t *packet, knot_packet_type_t *type)
{
	dbg_ns("%s(%p, %p)\n", __func__, packet, type);
	if (packet == NULL || type == NULL) {
		return KNOT_EINVAL;
	}

	// 1) create empty response
	int ret = KNOT_ERROR;
	*type = KNOT_QUERY_INVALID;
	if ((ret = knot_pkt_parse_question(packet)) != KNOT_EOK) {
		dbg_ns("%s: couldn't parse question = %d\n", __func__, ret);
		return KNOT_RCODE_FORMERR;
	}

	// 2) determine the query type
	*type = knot_pkt_type(packet);
	if (*type & KNOT_QUERY_INVALID) {
		return KNOT_RCODE_NOTIMPL;
	}

	return KNOT_RCODE_NOERROR;
}

/*----------------------------------------------------------------------------*/

static void knot_ns_error_response(const knot_nameserver_t *ns,
                                   uint16_t query_id, uint8_t *flags1_query,
                                   uint8_t rcode, uint8_t *response_wire,
                                   size_t *rsize)
{
	memcpy(response_wire, ns->err_response->wire, ns->err_response->size);

	// copy only the ID of the query
	knot_wire_set_id(response_wire, query_id);

	if (flags1_query != NULL) {
		if (knot_wire_flags_get_rd(*flags1_query) != 0) {
			knot_wire_set_rd(response_wire);
		}
		knot_wire_set_opcode(response_wire,
		                     knot_wire_flags_get_opcode(*flags1_query));
	}

	// set the RCODE
	knot_wire_set_rcode(response_wire, rcode);
	*rsize = ns->err_response->size;
}

/*----------------------------------------------------------------------------*/

int knot_ns_error_response_from_query_wire(const knot_nameserver_t *nameserver,
                                          const uint8_t *query, size_t size,
                                          uint8_t rcode,
                                          uint8_t *response_wire, size_t *rsize)
{
	if (size < 2) {
		// ignore packet
		return KNOT_EFEWDATA;
	}

	uint16_t pkt_id = knot_wire_get_id(query);

	uint8_t *flags1_ptr = NULL;
	uint8_t flags1;

	if (size > KNOT_WIRE_OFFSET_FLAGS1) {
		flags1 = knot_wire_get_flags1(query);
		flags1_ptr = &flags1;
	}
	knot_ns_error_response(nameserver, pkt_id, flags1_ptr,
	                       rcode, response_wire, rsize);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_error_response_from_query(const knot_nameserver_t *nameserver,
                                      const knot_pkt_t *query,
                                      uint8_t rcode, uint8_t *response_wire,
                                      size_t *rsize)
{
	if (query->parsed < 2) {
		// ignore packet
		return KNOT_EFEWDATA;
	}

	if (query->parsed < KNOT_WIRE_HEADER_SIZE) {
		return knot_ns_error_response_from_query_wire(nameserver,
			query->wire, query->size, rcode, response_wire,
			rsize);
	}

	size_t max_size = *rsize;
	uint8_t flags1 = knot_wire_get_flags1(query->wire);

	// prepare the generic error response
	knot_ns_error_response(nameserver, knot_wire_get_id(query->wire),
	                       &flags1, rcode, response_wire,
	                       rsize);

	/* Append question if parsed. */
	uint16_t header_len = KNOT_WIRE_HEADER_SIZE;
	uint16_t question_len = knot_pkt_question_size(query);
	if (question_len > header_len && question_len <= max_size) {

		/* Append question only (do not rewrite header). */
		uint16_t to_copy = question_len - header_len;
		if (response_wire != query->wire) {
			memcpy(response_wire + header_len,
			       query->wire + header_len,
			       to_copy);
		}
		*rsize += to_copy;
		knot_wire_set_qdcount(response_wire, 1);

	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_ns_error_response_full(knot_nameserver_t *nameserver,
                                 knot_pkt_t *response, uint8_t rcode,
                                 uint8_t *response_wire, size_t *rsize)
{
	knot_wire_set_rcode(response->wire, rcode);
	knot_ns_error_response_from_query(nameserver,
	                                  response->query,
	                                  KNOT_RCODE_SERVFAIL,
	                                  response_wire, rsize);

}

/*----------------------------------------------------------------------------*/

int knot_ns_prep_update_response(knot_nameserver_t *nameserver,
                                 knot_pkt_t *query, knot_pkt_t **resp,
                                 knot_zone_t **zone, size_t max_size)
{
	dbg_ns_verb("knot_ns_prep_update_response()\n");

	if (nameserver == NULL || query == NULL || resp == NULL
	    || zone == NULL) {
		return KNOT_EINVAL;
	}

	// first, parse the rest of the packet
	int ret = knot_pkt_parse_payload(query, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the query: %s.\n",
		       knot_strerror(ret));
		return ret;
	}

	/*
	 * Semantic checks
	 *
	 * Check the QDCOUNT and in case of anything but 1 send back
	 * FORMERR
	 */
	if (knot_wire_get_qdcount(query->wire) != 1) {
		dbg_ns("QDCOUNT != 1. Reply FORMERR.\n");
		return KNOT_EMALF;
	}

	/*
	 * Check what is in the Additional section. Only OPT and TSIG are
	 * allowed. TSIG must be the last record if present.
	 */
	bool ar_check = false;
	const knot_pktsection_t *additional = knot_pkt_section(query, KNOT_ADDITIONAL);

	switch(additional->count) {
	case 0: /* OK */
		ar_check = true;
		break;
	case 1: /* TSIG or OPT */
		ar_check = (knot_rrset_type(additional->rr[0]) == KNOT_RRTYPE_OPT
		           || knot_rrset_type(additional->rr[0]) == KNOT_RRTYPE_TSIG);
		break;
	case 2: /* OPT, TSIG */
		ar_check = (knot_rrset_type(additional->rr[0]) == KNOT_RRTYPE_OPT
		           && knot_rrset_type(additional->rr[1]) == KNOT_RRTYPE_TSIG);
		break;
	default: /* INVALID combination */
		break;
	}

	if (!ar_check) {
		dbg_ns("Additional section malformed. Reply FORMERR\n");
		return KNOT_EMALF;
	}

	size_t resp_max_size = 0;

	/*! \todo Put to separate function - used in prep_normal_response(). */
	if (max_size > 0) {
		// if TCP is used, buffer size is the only constraint
		assert(max_size > 0);
		resp_max_size = max_size;
	} else if (knot_pkt_have_edns(query)) {
		assert(max_size == 0);
		if (knot_edns_get_payload(&query->opt_rr) <
		    knot_edns_get_payload(nameserver->opt_rr)) {
			resp_max_size = knot_edns_get_payload(&query->opt_rr);
		} else {
			resp_max_size = knot_edns_get_payload(
						nameserver->opt_rr);
		}
	}

	if (resp_max_size < MAX_UDP_PAYLOAD) {
		resp_max_size = MAX_UDP_PAYLOAD;
	}

	ret = knot_ns_prepare_response(query, resp, resp_max_size);
	if (ret != KNOT_EOK) {
		return KNOT_ERROR;
	}

	dbg_ns_verb("Query - parsed: %zu, total wire size: %zu\n",
	            query->parsed, query->size);
	dbg_ns_detail("Opt RR: version: %d, payload: %d\n",
	              query->opt_rr.version, query->opt_rr.payload);

	// get the answer for the query
	knot_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);

	dbg_ns_detail("EDNS supported in query: %d\n",
	              knot_pkt_have_edns(query));

	// set the OPT RR to the response
	if (knot_pkt_have_edns(query)) {
		ret = knot_pkt_add_opt(*resp, nameserver->opt_rr,
		                            knot_pkt_have_nsid(query));
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to set OPT RR to the response"
			       ": %s\n", knot_strerror(ret));
		} else {
			// copy the DO bit from the query
			if (knot_pkt_have_dnssec(query)) {
				knot_edns_set_do(&(*resp)->opt_rr);
			}
		}
	}

	dbg_ns_verb("Response max size: %zu\n", (*resp)->max_size);

	const knot_dname_t *qname = knot_pkt_qname((*resp)->query);
	assert(qname != NULL);

//	uint16_t qtype = knot_packet_qtype(*resp);
dbg_ns_exec_verb(
	char *name_str = knot_dname_to_str(qname);
	dbg_ns_verb("Trying to find zone %s\n", name_str);
	free(name_str);
);
	// find zone
	*zone = knot_zonedb_find(zonedb, qname);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_ixfr_udp(knot_nameserver_t *nameserver,
                            const knot_zone_t *zone, knot_pkt_t *resp,
                            uint8_t *response_wire, size_t *rsize)
{
	dbg_ns("ns_answer_ixfr_udp()\n");

	const knot_zone_contents_t *contents = knot_zone_contents(zone);

	// if no zone found, return REFUSED
	if (zone == NULL) {
		dbg_ns("No zone found.\n");
		knot_wire_set_rcode(resp->wire, KNOT_RCODE_REFUSED);
		return KNOT_EOK;
	} else if (contents == NULL) {
		dbg_ns("Zone expired or not bootstrapped. Reply SERVFAIL.\n");
		knot_wire_set_rcode(resp->wire, KNOT_RCODE_SERVFAIL);
		return KNOT_EOK;
	}

	const knot_node_t *apex = knot_zone_contents_apex(contents);
	assert(apex != NULL);
	knot_rrset_t *soa = knot_node_get_rrset(apex, KNOT_RRTYPE_SOA);

	// just put the SOA to the Answer section of the response and send back
	assert(KNOT_PKT_IN_AN(resp));
	int ret = knot_pkt_put(resp, 0, soa, 0);
	if (ret != KNOT_EOK) {
		knot_ns_error_response_full(nameserver, resp,
		                            KNOT_RCODE_SERVFAIL,
		                            response_wire, rsize);
	}

	dbg_ns("Created response packet.\n");

	// Transform the packet into wire format
	if (ns_response_to_wire(resp, response_wire, rsize) != 0) {
		// send back SERVFAIL (as this is our problem)
		knot_ns_error_response_full(nameserver, resp,
		                            KNOT_RCODE_SERVFAIL,
		                            response_wire, rsize);
	}

	dbg_ns("Returning response with wire size %zu\n", *rsize);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_init_xfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	dbg_ns("knot_ns_init_xfr()\n");

	int ret = 0;

	if (nameserver == NULL || xfr == NULL) {
		dbg_ns("Wrong parameters given to function ns_init_xfr()\n");
		/* Sending error was totally wrong. If nameserver or xfr were
		 * NULL, the ns_error_response() function would crash.
		 */
		return ret;
	}

	ret = knot_pkt_parse_payload(xfr->query, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the query: %s\n",
		       knot_strerror(ret));
		xfr->rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
		                                 : KNOT_RCODE_SERVFAIL;
		return ret;
	}

	knot_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);
	const knot_dname_t *qname = knot_pkt_qname(xfr->query);

dbg_ns_exec_verb(
	char *name_str = knot_dname_to_str(qname);
	dbg_ns_verb("Trying to find zone with name %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	knot_zone_t *zone = knot_zonedb_find(zonedb, qname);

	// if no zone found, return NotAuth
	if (zone == NULL) {
		dbg_ns("No zone found.\n");
		xfr->rcode = KNOT_RCODE_NOTAUTH;
		return KNOT_ENOZONE;
	}

dbg_ns_exec(
	char *name2_str = knot_dname_to_str(qname);
	dbg_ns("Found zone for name %s\n", name2_str);
	free(name2_str);
);
	knot_zone_retain(zone);
	xfr->zone = zone;


	return KNOT_EOK;
}

int knot_ns_init_xfr_resp(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	int ret = KNOT_EOK;
	knot_pkt_t *resp = knot_pkt_new(xfr->wire, xfr->wire_size, &xfr->query->mm);
	if (resp == NULL) {
		dbg_ns("Failed to create packet structure.\n");
		/*! \todo xfr->wire is not NULL, will fail on assert! */
		knot_ns_error_response_from_query(nameserver, xfr->query,
		                                  KNOT_RCODE_SERVFAIL,
		                                  xfr->wire, &xfr->wire_size);
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire,
		                xfr->wire_size);
		return ret;
	}

	ret = knot_pkt_init_response(resp, xfr->query);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to init response structure.\n");
		/*! \todo xfr->wire is not NULL, will fail on assert! */
		knot_ns_error_response_from_query(nameserver, xfr->query,
		                                  KNOT_RCODE_SERVFAIL,
		                                  xfr->wire, &xfr->wire_size);
		int res = xfr->send(xfr->session, &xfr->addr, xfr->wire,
		                    xfr->wire_size);
		knot_pkt_free(&resp);
		return res;
	}

	xfr->response = resp;

	assert(knot_pkt_qtype(xfr->response) == KNOT_RRTYPE_AXFR ||
	       knot_pkt_qtype(xfr->response) == KNOT_RRTYPE_IXFR);
	return ret;
}

/*----------------------------------------------------------------------------*/

int ns_serial_compare(uint32_t s1, uint32_t s2)
{
	int32_t diff = ns_serial_difference(s1, s2);
	return (s1 == s2) /* s1 equal to s2 */
	        ? 0
	        :((diff >= 1 && diff < ((uint32_t)1 << 31))
	           ? 1	/* s1 larger than s2 */
	           : -1); /* s1 less than s2 */
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_axfrin(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	/*
	 * Here we assume that 'xfr' contains TSIG information
	 * and the digest of the query sent to the master or the previous
	 * digest.
	 */

	dbg_ns("ns_process_axfrin: incoming packet, wire size: %zu\n",
	       xfr->wire_size);
	int ret = xfrin_process_axfr_packet(xfr);

	if (ret > 0) { // transfer finished
		dbg_ns("ns_process_axfrin: AXFR finished, zone created.\n");

		gettimeofday(&xfr->t_end, NULL);

		/*
		 * Adjust zone so that node count is set properly and nodes are
		 * marked authoritative / delegation point.
		 */
		xfrin_constructed_zone_t *constr_zone =
				(xfrin_constructed_zone_t *)xfr->data;
		knot_zone_contents_t *zone = constr_zone->contents;
		assert(zone != NULL);
		log_zone_info("%s Serial %u -> %u\n", xfr->msg,
		              knot_zone_serial(knot_zone_contents(xfr->zone)),
		              knot_zone_serial(zone));

		dbg_ns_verb("ns_process_axfrin: adjusting zone.\n");
		int rc = knot_zone_contents_adjust(zone, NULL, NULL, 0);
		if (rc != KNOT_EOK) {
			return rc;
		}

		// save the zone contents to the xfr->data
		xfr->new_contents = zone;
		xfr->flags |= XFR_FLAG_AXFR_FINISHED;

		assert(zone->nsec3_nodes != NULL);

		// free the structure used for processing XFR
		assert(constr_zone->rrsigs == NULL);
		free(constr_zone);

		// check zone integrity
dbg_ns_exec_verb(
		int errs = knot_zone_contents_integrity_check(zone);
		dbg_ns_verb("Zone integrity check: %d errors.\n", errs);
);
	}

	/*! \todo In case of error, shouldn't the zone be destroyed here? */

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_switch_zone(knot_nameserver_t *nameserver,
                          knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || nameserver == NULL || xfr->new_contents == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_contents_t *zone = (knot_zone_contents_t *)xfr->new_contents;

	dbg_ns("Replacing zone by new one: %p\n", zone);
	if (zone == NULL) {
		dbg_ns("No new zone!\n");
		return KNOT_ENOZONE;
	}

	/* Zone must not be looked-up from server, as it may be a different zone if
	 * a reload occurs when transfer is pending. */
	knot_zone_t *z = xfr->zone;
	if (z == NULL) {
		char *name = knot_dname_to_str(knot_node_owner(
				knot_zone_contents_apex(zone)));
		dbg_ns("Failed to replace zone %s, old zone "
		       "not found\n", name);
		free(name);

		return KNOT_ENOZONE;
	} else {
		zone->zone = z;
	}

	rcu_read_unlock();
	int ret = xfrin_switch_zone(z, zone, xfr->type);
	rcu_read_lock();

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_ixfrin(knot_nameserver_t *nameserver,
                             knot_ns_xfr_t *xfr)
{
	dbg_ns("ns_process_ixfrin: incoming packet\n");

	/*
	 * [TSIG] Here we assume that 'xfr' contains TSIG information
	 * and the digest of the query sent to the master or the previous
	 * digest.
	 */
	int ret = xfrin_process_ixfr_packet(xfr);

	if (ret == XFRIN_RES_FALLBACK) {
		dbg_ns("ns_process_ixfrin: Fallback to AXFR.\n");
		ret = KNOT_ENOIXFR;
	}

	if (ret < 0) {
		knot_pkt_free(&xfr->query);
		return ret;
	} else if (ret > 0) {
		dbg_ns("ns_process_ixfrin: IXFR finished\n");
		gettimeofday(&xfr->t_end, NULL);

		knot_changesets_t *chgsets = (knot_changesets_t *)xfr->data;
		if (chgsets == NULL || chgsets->first_soa == NULL) {
			// nothing to be done??
			dbg_ns("No changesets created for incoming IXFR!\n");
			return ret;
		}

		// find zone associated with the changesets
		/* Must not search for the zone in zonedb as it may fetch a
		 * different zone than the one the transfer started on. */
		knot_zone_t *zone = xfr->zone;
		if (zone == NULL) {
			dbg_ns("No zone found for incoming IXFR!\n");
			knot_changesets_free(
				(knot_changesets_t **)(&xfr->data));
			return KNOT_ENOZONE;
		}

		switch (ret) {
		case XFRIN_RES_COMPLETE:
			break;
		case XFRIN_RES_SOA_ONLY: {
			// compare the SERIAL from the changeset with the zone's
			// serial
			const knot_node_t *apex = knot_zone_contents_apex(
					knot_zone_contents(zone));
			if (apex == NULL) {
				return KNOT_ERROR;
			}

			const knot_rrset_t *zone_soa = knot_node_rrset(
					apex, KNOT_RRTYPE_SOA);
			if (zone_soa == NULL) {
				return KNOT_ERROR;
			}

			if (ns_serial_compare(
			      knot_rdata_soa_serial(chgsets->first_soa),
			      knot_rdata_soa_serial(zone_soa))
			    > 0) {
				if ((xfr->flags & XFR_FLAG_UDP) != 0) {
					// IXFR over UDP
					dbg_ns("Update did not fit.\n");
					return KNOT_EIXFRSPACE;
				} else {
					// fallback to AXFR
					dbg_ns("ns_process_ixfrin: "
					       "Fallback to AXFR.\n");
					knot_changesets_free(
					      (knot_changesets_t **)&xfr->data);
					knot_pkt_free(&xfr->query);
					return KNOT_ENOIXFR;
				}

			} else {
				// free changesets
				dbg_ns("No update needed.\n");
				knot_changesets_free(
					(knot_changesets_t **)(&xfr->data));
				return KNOT_ENOXFR;
			}
		} break;
		}
	}

	/*! \todo In case of error, shouldn't the zone be destroyed here? */

	return ret;
}

/*----------------------------------------------------------------------------*/
/*
 * This function should:
 * 1) Create zone shallow copy and the changes structure.
 * 2) Call knot_ddns_process_update().
 *    - If something went bad, call xfrin_rollback_update() and return an error.
 *    - If everything went OK, continue.
 * 3) Finalize the updated zone.
 *
 * NOTE: Mostly copied from xfrin_apply_changesets(). Should be refactored in
 *       order to get rid of duplicate code.
 */
int knot_ns_process_update(const knot_pkt_t *query,
                            knot_zone_contents_t *old_contents,
                            knot_zone_contents_t **new_contents,
                            knot_changesets_t *chgs, knot_rcode_t *rcode)
{
	if (query == NULL || old_contents == NULL || chgs == NULL ||
	    EMPTY_LIST(chgs->sets) || new_contents == NULL || rcode == NULL) {
		return KNOT_EINVAL;
	}

	dbg_ns("Applying UPDATE to zone...\n");

	// 1) Create zone shallow copy.
	dbg_ns_verb("Creating shallow copy of the zone...\n");
	knot_zone_contents_t *contents_copy = NULL;
	int ret = xfrin_prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to prepare zone copy: %s\n",
		          knot_strerror(ret));
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	// 2) Apply the UPDATE and create changesets.
	dbg_ns_verb("Applying the UPDATE and creating changeset...\n");
	ret = knot_ddns_process_update(contents_copy, query,
	                               knot_changesets_get_last(chgs),
	                               chgs->changes, rcode);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to apply UPDATE to the zone copy or no update"
		       " made: %s\n", (ret < 0) ? knot_strerror(ret)
		                                : "No change made.");
		xfrin_rollback_update(old_contents, &contents_copy,
		                      chgs->changes);
		return ret;
	}

	// 3) Finalize zone
	dbg_ns_verb("Finalizing updated zone...\n");
	ret = xfrin_finalize_updated_zone(contents_copy, chgs->changes);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to finalize updated zone: %s\n",
		       knot_strerror(ret));
		xfrin_rollback_update(old_contents, &contents_copy,
		                      chgs->changes);
		*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
		                             : KNOT_RCODE_SERVFAIL;
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_create_forward_query(const knot_pkt_t *query,
                                 uint8_t *query_wire, size_t *size)
{
	/* Forward UPDATE query:
	 * assign a new packet id
	 */
	int ret = KNOT_EOK;
	if (query->size > *size) {
		return KNOT_ESPACE;
	}

	assert(query_wire != query->wire); /* #10 I suspect below is wrong */
	memcpy(query_wire, query->wire, query->size);
	*size = query->size;
	knot_wire_set_id(query_wire, knot_random_id());

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_forward_response(const knot_pkt_t *response,
                                     uint16_t original_id,
                                     uint8_t *response_wire, size_t *size)
{
	// copy the wireformat of the response and set the original ID
	if (response->size > *size) {
		return KNOT_ESPACE;
	}

	memcpy(response_wire, response->wire, response->size);
	*size = response->size;

	knot_wire_set_id(response_wire, original_id);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void *knot_ns_data(knot_nameserver_t *nameserver)
{
	return nameserver->data;
}

/*----------------------------------------------------------------------------*/

void *knot_ns_get_data(knot_nameserver_t *nameserver)
{
	return nameserver->data;
}

/*----------------------------------------------------------------------------*/

void knot_ns_set_data(knot_nameserver_t *nameserver, void *data)
{
	nameserver->data = data;
}

/*----------------------------------------------------------------------------*/

void knot_ns_destroy(knot_nameserver_t **nameserver)
{
	synchronize_rcu();

	if ((*nameserver)->opt_rr != NULL) {
		knot_edns_free(&(*nameserver)->opt_rr);
	}

	// destroy the zone db
	knot_zonedb_deep_free(&(*nameserver)->zone_db);

	/* Free error response. */
	knot_pkt_free(&(*nameserver)->err_response);

	free(*nameserver);
	*nameserver = NULL;
}

/* #10 <<< Next-gen API. */


int ns_proc_begin(ns_proc_context_t *ctx, const ns_proc_module_t *module)
{
	/* Only in inoperable state. */
	if (ctx->state != NS_PROC_NOOP) {
		return NS_PROC_NOOP;
	}

#ifdef KNOT_NS_DEBUG
	/* Check module API. */
	assert(module->begin);
	assert(module->in);
	assert(module->out);
	assert(module->err);
	assert(module->reset);
	assert(module->finish);
#endif /* KNOT_NS_DEBUG */

	ctx->module = module;
	ctx->state = module->begin(ctx);

	dbg_ns("%s -> %d\n", __func__, ctx->state);
	return ctx->state;
}

int ns_proc_reset(ns_proc_context_t *ctx)
{
	/* Only in operable state. */
	if (ctx->state == NS_PROC_NOOP) {
		return NS_PROC_NOOP;
	}

	/* #10 implement */
	ctx->state = ctx->module->reset(ctx);

	dbg_ns("%s -> %d\n", __func__, ctx->state);
	return ctx->state;
}

int ns_proc_finish(ns_proc_context_t *ctx)
{
	/* Only in operable state. */
	if (ctx->state == NS_PROC_NOOP) {
		return NS_PROC_NOOP;
	}

	/* #10 implement */
	ctx->state = ctx->module->finish(ctx);

	dbg_ns("%s -> %d\n", __func__, ctx->state);
	return ctx->state;
}

int ns_proc_in(const uint8_t *wire, uint16_t wire_len, ns_proc_context_t *ctx)
{
	/* Only if expecting data. */
	if (ctx->state != NS_PROC_MORE) {
		return NS_PROC_NOOP;
	}

	knot_pkt_t *pkt = knot_pkt_new((uint8_t *)wire, wire_len, &ctx->mm);
	knot_pkt_parse(pkt, 0);

	ctx->state = ctx->module->in(pkt, ctx);

	dbg_ns("%s -> %d\n", __func__, ctx->state);
	return ctx->state;
}

int ns_proc_out(uint8_t *wire, uint16_t *wire_len, ns_proc_context_t *ctx)
{
	knot_pkt_t *pkt = knot_pkt_new(wire, *wire_len, &ctx->mm);
	dbg_ns("%s: new TX packet %p\n", __func__, pkt);

	switch(ctx->state) {
	case NS_PROC_FULL: ctx->state = ctx->module->out(pkt, ctx); break;
	case NS_PROC_FAIL: ctx->state = ctx->module->err(pkt, ctx); break;
	default:
		assert(0); /* Improper use. */
		knot_pkt_free(&pkt);
		return NS_PROC_NOOP;
	}

	*wire_len = pkt->size;
	knot_pkt_free(&pkt);

	dbg_ns("%s -> %d\n", __func__, ctx->state);
	return ctx->state;
}

/* #10 >>> Next-gen API. */
