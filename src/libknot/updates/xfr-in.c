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
#include <assert.h>
#include <urcu.h>

#include "knot/server/journal.h"

#include "libknot/updates/xfr-in.h"

#include "libknot/nameserver/name-server.h"
#include "libknot/util/wire.h"
#include "libknot/util/debug.h"
#include "libknot/packet/packet.h"
#include "libknot/dname.h"
#include "libknot/zone/zone.h"
#include "libknot/dnssec/zone-nsec.h"
#include "libknot/packet/query.h"
#include "libknot/common.h"
#include "libknot/updates/changesets.h"
#include "libknot/tsig.h"
#include "libknot/tsig-op.h"
#include "knot/zone/semantic-check.h"
#include "common/lists.h"
#include "common/descriptor.h"
#include "libknot/rdata.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int xfrin_create_query(knot_dname_t *qname, uint16_t qtype,
			      uint16_t qclass, knot_ns_xfr_t *xfr, size_t *size,
			      const knot_rrset_t *soa, int use_tsig)
{
	knot_packet_t *pkt = knot_packet_new();
	CHECK_ALLOC_LOG(pkt, KNOT_ENOMEM);

	/*! \todo Get rid of the numeric constant. */
	int rc = knot_packet_set_max_size(pkt, 512);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOT_ERROR;
	}

	rc = knot_query_init(pkt);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOT_ERROR;
	}

	/* Set random query ID. */
	knot_packet_set_random_id(pkt);
	rc = knot_query_set_question(pkt, qname, qclass, qtype);
	if (rc != KNOT_EOK) {
		knot_packet_free(&pkt);
		return KNOT_ERROR;
	}

	/* Reserve space for TSIG. */
	if (use_tsig && xfr->tsig_key) {
		dbg_xfrin_detail("xfrin: setting packet TSIG size to %zu\n",
				 xfr->tsig_size);
		knot_packet_set_tsig_size(pkt, xfr->tsig_size);
	}

	/* Add SOA RR to authority section for IXFR. */
	if (qtype == KNOT_RRTYPE_IXFR && soa) {
		knot_query_add_rrset_authority(pkt, soa);
	}

	/*! \todo OPT RR ?? */

	uint8_t *wire = NULL;
	size_t wire_size = 0;
	rc = knot_packet_to_wire(pkt, &wire, &wire_size);
	if (rc != KNOT_EOK) {
		dbg_xfrin("Failed to write packet to wire.\n");
		knot_packet_free(&pkt);
		return KNOT_ERROR;
	}

	if (wire_size > *size) {
		dbg_xfrin("Not enough space provided for the wire "
			  "format of the query.\n");
		knot_packet_free(&pkt);
		return KNOT_ESPACE;
	}

	// wire format created, sign it with TSIG if required
	if (use_tsig && xfr->tsig_key) {
		char *name = knot_dname_to_str(xfr->tsig_key->name);
		dbg_xfrin_detail("Signing XFR query with key (name %s): \n",
				  name);
		free(name);

		xfr->digest_size = xfr->digest_max_size;
		rc = knot_tsig_sign(wire, &wire_size, *size, NULL, 0,
			       xfr->digest, &xfr->digest_size, xfr->tsig_key,
			       0, 0);
		if (rc != KNOT_EOK) {
			/*! \todo [TSIG] Handle TSIG errors. */
			knot_packet_free(&pkt);
			return rc;
		}

		dbg_xfrin_detail("Signed XFR query, new wire size: %zu, digest:"
				 "\n", wire_size);
		dbg_xfrin_hex_detail((const char*)xfr->digest, xfr->digest_size);
	}

	memcpy(xfr->wire, wire, wire_size);
	*size = wire_size;

	dbg_xfrin("Created query of size %zu.\n", *size);
	knot_packet_dump(pkt);

	knot_packet_free(&pkt);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int xfrin_create_soa_query(knot_dname_t *owner, knot_ns_xfr_t *xfr,
                           size_t *size)
{
	return xfrin_create_query(owner, KNOT_RRTYPE_SOA,
				  KNOT_CLASS_IN, xfr, size, 0,
				  xfr->tsig_key != NULL);
}

/*----------------------------------------------------------------------------*/

int xfrin_transfer_needed(const knot_zone_contents_t *zone,
                          knot_packet_t *soa_response)
{
	// first, parse the rest of the packet
	assert(!knot_packet_is_query(soa_response));
	dbg_xfrin_verb("Response - parsed: %zu, total wire size: %zu\n",
		       soa_response->parsed, soa_response->size);
	int ret;

	if (soa_response->parsed < soa_response->size) {
		ret = knot_packet_parse_rest(soa_response, 0);
		if (ret != KNOT_EOK) {
			dbg_xfrin_verb("knot_packet_parse_rest() returned %s\n",
				       knot_strerror(ret));
			return KNOT_EMALF;
		}
	}

	/*
	 * Retrieve the local Serial
	 */
	const knot_rrset_t *soa_rrset =
		knot_node_rrset(knot_zone_contents_apex(zone),
				KNOT_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		char *name = knot_dname_to_str(knot_node_owner(
				knot_zone_contents_apex(zone)));
		dbg_xfrin("SOA RRSet missing in the zone %s!\n", name);
		free(name);
		return KNOT_ERROR;
	}

	int64_t local_serial = knot_rdata_soa_serial(soa_rrset);
	if (local_serial < 0) {
dbg_xfrin_exec(
		char *name = knot_dname_to_str(knot_rrset_owner(soa_rrset));
		dbg_xfrin("Malformed data in SOA of zone %s\n", name);
		free(name);
);
		return KNOT_EMALF;  // maybe some other error
	}

	/*
	 * Retrieve the remote Serial
	 */
	// the SOA should be the first (and only) RRSet in the response
	soa_rrset = knot_packet_answer_rrset(soa_response, 0);
	if (soa_rrset == NULL
	    || knot_rrset_type(soa_rrset) != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	int64_t remote_serial = knot_rdata_soa_serial(soa_rrset);
	if (remote_serial < 0) {
		return KNOT_EMALF;	// maybe some other error
	}

	return (ns_serial_compare(local_serial, remote_serial) < 0);
}

/*----------------------------------------------------------------------------*/

int xfrin_create_axfr_query(knot_dname_t *owner, knot_ns_xfr_t *xfr,
                            size_t *size, int use_tsig)
{
	return xfrin_create_query(owner, KNOT_RRTYPE_AXFR,
				  KNOT_CLASS_IN, xfr, size, 0, use_tsig);
}

/*----------------------------------------------------------------------------*/

int xfrin_create_ixfr_query(const knot_zone_contents_t *zone,
                            knot_ns_xfr_t *xfr, size_t *size, int use_tsig)
{
	/*!
	 *  \todo Implement properly.
	 */
	knot_node_t *apex = knot_zone_contents_get_apex(zone);
	const knot_rrset_t *soa = knot_node_rrset(apex, KNOT_RRTYPE_SOA);

	return xfrin_create_query(knot_node_get_owner(apex), KNOT_RRTYPE_IXFR,
				  KNOT_CLASS_IN, xfr, size, soa, use_tsig);
}

/*----------------------------------------------------------------------------*/

static int xfrin_add_orphan_rrsig(xfrin_orphan_rrsig_t **rrsigs,
                                  knot_rrset_t *rr)
{
	assert(knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG);

	xfrin_orphan_rrsig_t *new_item = malloc(sizeof(xfrin_orphan_rrsig_t));
	CHECK_ALLOC_LOG(new_item, KNOT_ENOMEM);
	new_item->rrsig = rr;
	new_item->next = *rrsigs;

	*rrsigs = new_item;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_process_orphan_rrsigs(knot_zone_contents_t *zone,
                                       xfrin_orphan_rrsig_t *rrsigs)
{
	xfrin_orphan_rrsig_t **last = &rrsigs;
	int ret = 0;
	while (*last != NULL) {
		knot_rrset_t *rrset = NULL;
		knot_node_t *node = NULL;
		ret = knot_zone_contents_add_rrsigs(zone, (*last)->rrsig,
						    &rrset, &node,
						    KNOT_RRSET_DUPL_MERGE);
		if (ret > 0) {
			knot_rrset_deep_free(&(*last)->rrsig, 1);
		} else if (ret == KNOT_ENONODE) {
			// Nothing to cover - print warning
			char *name = knot_dname_to_str((*last)->rrsig->owner);
			char type[16];
			knot_rrtype_to_string(
			    knot_rdata_rrsig_type_covered((*last)->rrsig, 0),
			    type, 16);

			log_zone_warning("No RRSet for RRSIG: "
			                 "%s, covering type %s",
			                 name, type);
			free(name);

			// discard RRSIG
			knot_rrset_deep_free(&(*last)->rrsig, 1);
		} else if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to add orphan RRSIG to zone.\n");
			return ret;
		} else {
			(*last)->rrsig = NULL;
		}
		last = &((*last)->next);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static void xfrin_log_error(const knot_dname_t *zone_owner,
                            const knot_rrset_t *rr,
                            int ret)
{
	char *zonename = knot_dname_to_str(zone_owner);
	char *rrname = knot_dname_to_str(rr->owner);
	if (ret == KNOT_EOUTOFZONE) {
		// Out-of-zone data, ignore
		log_zone_warning("Zone %s: Ignoring "
		                 "out-of-zone RR owned by %s\n",
		                 zonename, rrname);
	} if (ret == KNOT_EMALF) {
		// Fatal semantic error
		char rrstr[16] = { '\0' };
		knot_rrtype_to_string(rr->type, rrstr, 16);
		log_zone_error("Zone %s: Semantic error for RR owned by %s, "
		               "type %s.\n", zonename, rrname, rrstr);
	} else {
	        log_zone_error("Zone %s: Failed to process "
	                       "incoming RR, Transfer failed (Reason: %s)\n",
	                        zonename, knot_strerror(ret));
	}
	free(rrname);
	free(zonename);
}

void xfrin_free_orphan_rrsigs(xfrin_orphan_rrsig_t **rrsigs)
{
	xfrin_orphan_rrsig_t *r = *rrsigs;
	while (r != NULL) {
		xfrin_orphan_rrsig_t *prev = r;
		r = r->next;
		if (prev->rrsig != NULL) {
			knot_rrset_deep_free(&prev->rrsig, 1);
		}
		free(prev);
	}

	*rrsigs = NULL;
}

/*----------------------------------------------------------------------------*/

static int xfrin_check_tsig(knot_packet_t *packet, knot_ns_xfr_t *xfr,
                            int tsig_req)
{
	assert(packet != NULL);
	assert(xfr != NULL);

	dbg_xfrin_verb("xfrin_check_tsig(): packet nr: %d, required: %d\n",
		       xfr->packet_nr, tsig_req);

	/*
	 * If we are expecting it (i.e. xfr->prev_digest_size > 0)
	 *   a) it should be there (first, last or each 100th packet) and it
	 *      is not
	 *        Then we should discard the changes and close the connection.
	 *   b) it should be there and it is or it may not be there (other
	 *      packets) and it is
	 *        We validate the TSIG and reset packet number counting and
	 *        data aggregation.
	 *
	 * If we are not expecting it (i.e. xfr->prev_digest_size <= 0) and
	 * it is there => it should probably be considered an error
	 */
	knot_rrset_t *tsig = NULL;
	int ret = knot_packet_parse_next_rr_additional(packet, &tsig);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (xfr->tsig_key) {
		// just append the wireformat to the TSIG data
		assert(KNOT_NS_TSIG_DATA_MAX_SIZE - xfr->tsig_data_size
		       >= xfr->wire_size);
		uint8_t *wire_buf = xfr->tsig_data + xfr->tsig_data_size;
		memcpy(wire_buf, xfr->wire, xfr->wire_size);
		xfr->tsig_data_size += xfr->wire_size;

		/* Strip TSIG RR from wire and restore message ID. */
		if (tsig) {
			knot_tsig_check_prep(wire_buf, &xfr->tsig_data_size, tsig);
		}
	}

	if (xfr->tsig_key) {
		if (tsig_req && tsig == NULL) {
			// TSIG missing!!
			return KNOT_ENOTSIG;
		} else if (tsig != NULL) {
			// TSIG there, either required or not, process
			if (xfr->packet_nr == 0) {
				ret = knot_tsig_client_check(tsig,
					xfr->wire, xfr->wire_size,
					xfr->digest, xfr->digest_size,
					xfr->tsig_key,
					xfr->tsig_prev_time_signed);
			} else {
				ret = knot_tsig_client_check_next(tsig,
					xfr->tsig_data, xfr->tsig_data_size,
					xfr->digest, xfr->digest_size,
					xfr->tsig_key,
					xfr->tsig_prev_time_signed);
			}

			if (ret != KNOT_EOK) {
				/* No need to check TSIG error
				 * here, propagate and check elsewhere.*/
				knot_rrset_deep_free(&tsig, 1);
				return ret;
			}

			// and reset the data storage
			//xfr->packet_nr = 1;
			xfr->tsig_data_size = 0;

			// Extract the digest from the TSIG RDATA and store it.
			if (xfr->digest_max_size < tsig_rdata_mac_length(tsig)) {
				knot_rrset_deep_free(&tsig, 1);
				return KNOT_ESPACE;
			}
			memcpy(xfr->digest, tsig_rdata_mac(tsig),
			       tsig_rdata_mac_length(tsig));
			xfr->digest_size = tsig_rdata_mac_length(tsig);

			// Extract the time signed from the TSIG and store it
			// We may rewrite the tsig_req_time_signed field
			xfr->tsig_prev_time_signed =
					tsig_rdata_time_signed(tsig);


		}
	} else if (tsig != NULL) {
		// TSIG where it should not be
		knot_rrset_deep_free(&tsig, 1);
		return KNOT_EMALF;
	}

	knot_rrset_deep_free(&tsig, 1);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static bool semantic_check_passed(const knot_zone_contents_t *z,
                                  const knot_node_t *node)
{
	assert(node && z);
	err_handler_t err_handler;
	err_handler_init(&err_handler);
	bool fatal = false;
	sem_check_node_plain(z, node, &err_handler, true, &fatal);
	return !fatal;
}

int xfrin_process_axfr_packet(knot_ns_xfr_t *xfr)
{
	const uint8_t *pkt = xfr->wire;
	size_t size = xfr->wire_size;
	xfrin_constructed_zone_t **constr =
			(xfrin_constructed_zone_t **)(&xfr->data);

	if (pkt == NULL || constr == NULL) {
		return KNOT_EINVAL;
	}

	/* Init semantic error handler - used for CNAME/DNAME checks. */
	err_handler_t err_handler;
	err_handler_init(&err_handler);

	dbg_xfrin_verb("Processing AXFR packet of size %zu.\n", size);

	// check if the response is OK
	if (knot_wire_get_rcode(pkt) != KNOT_RCODE_NOERROR) {
		return KNOT_EXFRREFUSED;
	}

	/*! \todo Should TC bit be checked? */

	knot_packet_t *packet = knot_packet_new();
	if (packet == NULL) {
		dbg_xfrin("Could not create packet structure.\n");
		return KNOT_ENOMEM;
	}

	int ret = knot_packet_parse_from_wire(packet, pkt, size, 1, 0);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Could not parse packet: %s.\n", knot_strerror(ret));
		knot_packet_free(&packet);
		/*! \todo Cleanup. */
		return KNOT_EMALF;
	}

	/*! \todo [TSIG] If packet RCODE is NOTAUTH(9), process as TSIG error. */

	knot_rrset_t *rr = NULL;
	ret = knot_packet_parse_next_rr_answer(packet, &rr);

	if (ret != KNOT_EOK) {
		dbg_xfrin("Could not parse first Answer RR: %s.\n",
			       knot_strerror(ret));
		knot_packet_free(&packet);
		/*! \todo Cleanup. */
		return KNOT_EMALF;
	}

	if (rr == NULL) {
		dbg_xfrin("No RRs in the packet.\n");
		knot_packet_free(&packet);
		/*! \todo Cleanup. */
		return KNOT_EMALF;
	}

	/*! \todo We should probably test whether the Question of the first
	 *        message corresponds to the SOA RR.
	 */

	/* RR parsed - sort out DNAME duplications. */
	/*! \todo Replace with RRSet duplicate checking. */
//	xfrin_insert_rrset_dnames_to_table(rr, xfr->lookup_tree);

	knot_node_t *node = NULL;
	int in_zone = 0;
	knot_zone_contents_t *zone = NULL;

	if (*constr == NULL) {
		// this should be the first packet
		/*! Packet number for checking TSIG validation. */
		xfr->packet_nr = 0;

		// create new zone
		/*! \todo Ensure that the packet is the first one. */
		if (knot_rrset_type(rr) != KNOT_RRTYPE_SOA) {
			dbg_xfrin("No zone created, but the first RR in "
				  "Answer is not a SOA RR.\n");
			knot_packet_free(&packet);
			knot_node_free(&node);
			knot_rrset_deep_free(&rr, 1);
			/*! \todo Cleanup. */
			return KNOT_EMALF;
		}


		/* Check for SOA name and type. */
		if (knot_packet_qname(packet) == NULL) {
			dbg_xfrin("Invalid packet in sequence, ignoring.\n");
			knot_packet_free(&packet);
			knot_node_free(&node);
			knot_rrset_deep_free(&rr, 1);
			return KNOT_EOK;
		}

		const knot_dname_t *qname = knot_packet_qname(packet);
		if (!knot_dname_is_equal(knot_rrset_owner(rr), qname)) {
dbg_xfrin_exec(
			char *rr_owner =
				knot_dname_to_str(knot_rrset_owner(rr));
			char *qname = knot_dname_to_str(
				knot_packet_qname(packet));

			dbg_xfrin("Owner of the first SOA RR (%s) does not"
				  " match QNAME (%s).\n", rr_owner, qname);

			free(rr_owner);
			free(qname);
);
			/*! \todo Cleanup. */
			knot_packet_free(&packet);
			knot_node_free(&node);
			knot_rrset_deep_free(&rr, 1);
			return KNOT_EMALF;
		}

		node = knot_node_new(rr->owner, NULL, 0);
		if (node == NULL) {
			dbg_xfrin("Failed to create new node.\n");
			knot_packet_free(&packet);
			knot_rrset_deep_free(&rr, 1);
			return KNOT_ENOMEM;
		}

		// the first RR is SOA and its owner and QNAME are the same
		// create the zone

		*constr = (xfrin_constructed_zone_t *)malloc(
				sizeof(xfrin_constructed_zone_t));
		if (*constr == NULL) {
			dbg_xfrin("Failed to create new constr. zone.\n");
			knot_packet_free(&packet);
			knot_node_free(&node);
			knot_rrset_deep_free(&rr, 1);
			return KNOT_ENOMEM;
		}

		memset(*constr, 0, sizeof(xfrin_constructed_zone_t));

		dbg_xfrin_verb("Creating new zone contents.\n");
		(*constr)->contents = knot_zone_contents_new(node, xfr->zone);
		if ((*constr)->contents== NULL) {
			dbg_xfrin("Failed to create new zone.\n");
			knot_packet_free(&packet);
			knot_node_free(&node);
			knot_rrset_deep_free(&rr, 1);
			/*! \todo Cleanup. */
			return KNOT_ENOMEM;
		}

		in_zone = 1;
		zone = (*constr)->contents;
		assert(zone->apex == node);
		// add the RRSet to the node
		ret = knot_zone_contents_add_rrset(zone, rr, &node,
		                                   KNOT_RRSET_DUPL_MERGE);
		if (ret < 0) {
			dbg_xfrin("Failed to add RRSet to zone node: %s.\n",
				  knot_strerror(ret));
			knot_packet_free(&packet);
			knot_node_free(&node);
			knot_rrset_deep_free(&rr, 1);
			/*! \todo Cleanup. */
			return KNOT_ERROR;
		} else if (ret > 0) {
			dbg_xfrin("Merged SOA RRSet.\n");
			// merged, free the RRSet
			knot_rrset_deep_free(&rr, 1);
		}

		// take next RR
		ret = knot_packet_parse_next_rr_answer(packet, &rr);
	} else {
		zone = (*constr)->contents;
		++xfr->packet_nr;
	}

	assert(zone != NULL);

	while (ret == KNOT_EOK && rr != NULL) {
		// process the parsed RR
		if (!knot_dname_is_sub(rr->owner, xfr->zone->name) &&
		    !knot_dname_is_equal(rr->owner, xfr->zone->name)) {
			// Out-of-zone data
			xfrin_log_error(xfr->zone->name, rr,
			                KNOT_EOUTOFZONE);
			knot_rrset_deep_free(&rr, 1);
			ret = knot_packet_parse_next_rr_answer(packet, &rr);
			continue;
		}		

		dbg_rrset_detail("\nNext RR:\n\n");
		knot_rrset_dump(rr);
		/*! \todo Replace with RRSet duplicate checking. */
//		xfrin_insert_rrset_dnames_to_table(rr, xfr->lookup_tree);

		if (node != NULL && !knot_dname_is_equal(rr->owner, node->owner)) {
dbg_xfrin_exec_detail(
			char *name = knot_dname_to_str(node->owner);
			dbg_xfrin_detail("Node owner: %s\n", name);
			free(name);
);
			if (!in_zone) {
				// this should not happen
				assert(0);
				// the node is not in the zone and the RR has
				// other owner, so a new node must be created
				// insert the old node to the zone
			}

			node = NULL;
		}

		if (knot_rrset_type(rr) == KNOT_RRTYPE_SOA) {
			// this must be the last SOA, do not do anything more
			// discard the RR
			assert(knot_zone_contents_apex((zone)) != NULL);
			assert(knot_node_rrset(knot_zone_contents_apex((zone)),
					       KNOT_RRTYPE_SOA) != NULL);
			dbg_xfrin_verb("Found last SOA, transfer finished.\n");

			dbg_xfrin_verb("Verifying TSIG...\n");
			/*! \note [TSIG] Now check if there is not a TSIG record
			 *               at the end of the packet.
			 */
			ret = xfrin_check_tsig(packet, xfr, 1);

			dbg_xfrin_verb("xfrin_check_tsig() returned %d\n", ret);

			knot_packet_free(&packet);
			knot_rrset_deep_free(&rr, 1);

			if (ret != KNOT_EOK) {
				/*! \todo [TSIG] Handle TSIG errors. */
				return ret;
			}

			// we must now find place for all orphan RRSIGs
			ret = xfrin_process_orphan_rrsigs(zone,
							  (*constr)->rrsigs);
			xfrin_free_orphan_rrsigs(&(*constr)->rrsigs);

			if (ret != KNOT_EOK) {
				dbg_xfrin("Failed to process orphan RRSIGs\n");
				return ret;
			}

			return 1;
		}

		if (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG) {
			// RRSIGs require special handling, as there are no
			// nodes for them
			knot_rrset_t *tmp_rrset = NULL;
			ret = knot_zone_contents_add_rrsigs(zone, rr,
				 &tmp_rrset, &node, KNOT_RRSET_DUPL_MERGE);
			if (ret == KNOT_ENONODE || ret == KNOT_ENORRSET) {
				dbg_xfrin_verb("No node or RRSet for RRSIGs\n");
				dbg_xfrin_verb("Saving for later insertion.\n");

				if (ret == KNOT_ENORRSET) {
					in_zone = 1;
				}

				ret = xfrin_add_orphan_rrsig(&(*constr)->rrsigs,
							     rr);

				if (ret > 0) {
					dbg_xfrin_detail("Merged RRSIGs.\n");
					knot_rrset_deep_free(&rr, 1);
				} else if (ret != KNOT_EOK) {
					dbg_xfrin("Failed to save orphan"
						  " RRSIGs.\n");
					knot_packet_free(&packet);
					knot_rrset_deep_free(&rr, 1);
					return ret;
				}
			} else if (ret < 0) {
				dbg_xfrin("Failed to add RRSIGs (%s).\n",
					       knot_strerror(ret));
				knot_packet_free(&packet);
				knot_rrset_deep_free(&rr, 1);
				return KNOT_ERROR;  /*! \todo Other error code. */
			} else if (ret == 1) {
				assert(node != NULL);
dbg_xfrin_exec_verb(
				char *name = knot_dname_to_str(node->owner);
				dbg_xfrin_detail("Found node for the record in "
						 "zone: %s. Merged.\n", name);
				free(name);
);
				in_zone = 1;
				knot_rrset_deep_free(&rr, 1);
			} else if (ret == 2) {
				// should not happen
				assert(0);
			} else {
				assert(node != NULL);
dbg_xfrin_exec_verb(
				char *name = knot_dname_to_str(node->owner);
				dbg_xfrin_detail("Found node for the record in "
						 "zone: %s.\n", name);
				free(name);
);
				in_zone = 1;
				assert(tmp_rrset->rrsigs == rr);
			}

			// parse next RR
			ret = knot_packet_parse_next_rr_answer(packet, &rr);

			continue;
		}

		/* TSIG where it should not be - in Answer section.*/
		if (knot_rrset_type(rr) == KNOT_RRTYPE_TSIG) {
			// not allowed here
			dbg_xfrin("TSIG in Answer section.\n");
			knot_packet_free(&packet);
			knot_node_free(&node); // ???
			knot_rrset_deep_free(&rr, 1);
			return KNOT_EMALF;
		}
		
		knot_node_t *(*get_node)(const knot_zone_contents_t *,
					 const knot_dname_t *) = NULL;
		int (*add_node)(knot_zone_contents_t *, knot_node_t *, int,
				uint8_t) = NULL;

		if (knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3) {
			get_node = knot_zone_contents_get_nsec3_node;
			add_node = knot_zone_contents_add_nsec3_node;
		} else {
			get_node = knot_zone_contents_get_node;
			add_node = knot_zone_contents_add_node;
		}

		if (node == NULL && (node = get_node(zone,
					       knot_rrset_owner(rr))) != NULL) {
			// the node for this RR was found in the zone
			dbg_xfrin_detail("Found node for the record in zone\n");
			in_zone = 1;
		}

		if (node == NULL) {
			// a new node for the RR is required but it is not
			// in the zone
			node = knot_node_new(rr->owner, NULL, 0);
			if (node == NULL) {
				dbg_xfrin("Failed to create new node.\n");
				knot_packet_free(&packet);
				knot_rrset_deep_free(&rr, 1);
				return KNOT_ENOMEM;
			}
			dbg_xfrin_detail("Created new node for the record.\n");

			// insert the RRSet to the node
			ret = knot_node_add_rrset(node, rr);
			if (ret < 0) {
				dbg_xfrin("Failed to add RRSet to node (%s)\n",
					  knot_strerror(ret));
				knot_packet_free(&packet);
				knot_node_free(&node);
				knot_rrset_deep_free(&rr, 1);
				return KNOT_ERROR;
			} else if (ret > 0) {
				// should not happen, this is new node
				assert(0);
			}

			// insert the node into the zone
			ret = add_node(zone, node, 1, 0);
			if (ret != KNOT_EOK) {
				// Fatal error, free packet
				knot_packet_free(&packet);
				knot_rrset_deep_free(&rr, 1);
				knot_node_free(&node);
				return ret;
			}
			
			if (!semantic_check_passed(zone, node)) {
				xfrin_log_error(xfr->zone->name,
				                rr,
				                KNOT_EMALF);
				knot_packet_free(&packet);
				return KNOT_EMALF;
			}

			in_zone = 1;
		} else {
			assert(in_zone);
			const uint16_t rrtype = rr->type;
			ret = knot_zone_contents_add_rrset(zone, rr, &node,
						    KNOT_RRSET_DUPL_MERGE);
			if (ret < 0) {
				knot_packet_free(&packet);
				dbg_xfrin("Failed to add RRSet to zone :%s.\n",
					  knot_strerror(ret));
				return KNOT_ERROR;
			} else if (ret > 0) {
				// merged, free the RRSet
				knot_rrset_deep_free(&rr, 1);
			}
			if (!semantic_check_passed(zone, node)) {
				xfrin_log_error(xfr->zone->name,
				                knot_node_rrset(node, rrtype),
				                KNOT_EMALF);
				knot_packet_free(&packet);
				return KNOT_EMALF;
			}
		}

		rr = NULL;

		// parse next RR
		ret = knot_packet_parse_next_rr_answer(packet, &rr);
	}

	assert(ret != KNOT_EOK || rr == NULL);

	if (ret < 0) {
		// some error in parsing
		dbg_xfrin("Could not parse next RR: %s.\n", knot_strerror(ret));
		knot_packet_free(&packet);

		if (!in_zone) {
			knot_node_free(&node);
		}

		knot_rrset_deep_free(&rr, 1);
		return KNOT_EMALF;
	}

	assert(ret == KNOT_EOK);
	assert(rr == NULL);

	// if the last node is not yet in the zone, insert
	if (!in_zone && node) {
		ret = knot_zone_contents_add_node(zone, node, 1, 0);
		if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to add last node into zone (%s).\n",
				  knot_strerror(ret));
				knot_packet_free(&packet);
				knot_node_free(&node);
				knot_rrset_deep_free(&rr, 1);
				return ret;
		}
	}

	/* Now check if there is not a TSIG record at the end of the packet. */
	ret = xfrin_check_tsig(packet, xfr,
			       knot_ns_tsig_required(xfr->packet_nr));
	//++xfr->packet_nr;

	knot_packet_free(&packet);
	dbg_xfrin_verb("Processed one AXFR packet successfully.\n");

	/* TSIG errors are propagated and reported in a standard
	 * manner, as we're in response processing, no further error response
	 * should be sent.
	 */

	return ret;
}

/*----------------------------------------------------------------------------*/

static int xfrin_parse_first_rr(knot_packet_t **packet, const uint8_t *pkt,
                                size_t size, knot_rrset_t **rr)
{
	assert(packet != NULL);
	assert(rr != NULL);

	*packet = knot_packet_new();
	if (*packet == NULL) {
		dbg_xfrin("Could not create packet structure.\n");
		return KNOT_ENOMEM;
	}

	int ret = knot_packet_parse_from_wire(*packet, pkt, size, 1, 0);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Could not parse packet: %s.\n", knot_strerror(ret));
		knot_packet_free(packet);
		return KNOT_EMALF;
	}

	// check if the TC bit is set (it must not be)
	if (knot_wire_get_tc(pkt)) {
		dbg_xfrin("IXFR response has TC bit set.\n");
		knot_packet_free(packet);
		return KNOT_EMALF;
	}

	ret = knot_packet_parse_next_rr_answer(*packet, rr);

	if (ret != KNOT_EOK) {
		dbg_xfrin("Could not parse first Answer RR: %s.\n",
			  knot_strerror(ret));
		knot_packet_free(packet);
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_process_ixfr_packet(knot_ns_xfr_t *xfr)
{
	size_t size = xfr->wire_size;
	const uint8_t *pkt = xfr->wire;
	knot_changesets_t **chs = (knot_changesets_t **)(&xfr->data);

	if (pkt == NULL || chs == NULL) {
		dbg_xfrin("Wrong parameters supported.\n");
		return KNOT_EINVAL;
	}

	// check if the response is OK
	if (knot_wire_get_rcode(pkt) != KNOT_RCODE_NOERROR) {
		return KNOT_EXFRREFUSED;
	}

	knot_packet_t *packet = NULL;
	knot_rrset_t *rr = NULL;

	int ret;

	if ((ret = xfrin_parse_first_rr(&packet, pkt, size, &rr)) != KNOT_EOK) {
		return ret;
	}

	assert(packet != NULL);

	// state of the transfer
	// -1 .. a SOA is expected to create a new changeset
	int state = 0;

	if (rr == NULL) {
		dbg_xfrin("No RRs in the packet.\n");
		knot_packet_free(&packet);
		/*! \todo Some other action??? */
		return KNOT_EMALF;
	}

	/*! \todo Replace with RRSet duplicate checking. */
//	xfrin_insert_rrset_dnames_to_table(rr, xfr->lookup_tree);

	if (*chs == NULL) {
		dbg_xfrin_verb("Changesets empty, creating new.\n");

		ret = knot_changesets_init(chs);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&rr, 1);
			knot_packet_free(&packet);
			return ret;
		}

		// the first RR must be a SOA
		if (knot_rrset_type(rr) != KNOT_RRTYPE_SOA) {
			dbg_xfrin("First RR is not a SOA RR!\n");
			knot_rrset_deep_free(&rr, 1);
			ret = KNOT_EMALF;
			goto cleanup;
		}

		// just store the first SOA for later use
		(*chs)->first_soa = rr;
		state = -1;

		dbg_xfrin_verb("First SOA of IXFR saved, state set to -1.\n");

		// parse the next one
		ret = knot_packet_parse_next_rr_answer(packet, &rr);
		if (ret != KNOT_EOK) {
			knot_packet_free(&packet);
			return ret;
		}

		/*
		 * If there is no other records in the response than the SOA, it
		 * means one of these three cases:
		 *
		 * 1) The server does not have newer zone than ours.
		 *    This is indicated by serial equal to the one of our zone.
		 * 2) The server wants to send the transfer but is unable to fit
		 *    it in the packet. This is indicated by serial different
		 *    (newer) from the one of our zone, but applies only for
		 *    IXFR/UDP.
		 * 3) The master is weird and sends only SOA in the first packet
		 *    of a fallback to AXFR answer (PowerDNS does this).
		 *
		 * The serials must be compared in other parts of the server, so
		 * just indicate that the answer contains only one SOA.
		 */
		if (rr == NULL) {
			dbg_xfrin("Response containing only SOA,\n");
			knot_packet_free(&packet);
			return XFRIN_RES_SOA_ONLY;
		} else if (knot_rrset_type(rr) != KNOT_RRTYPE_SOA) {
			knot_rrset_deep_free(&rr, 1);
			knot_packet_free(&packet);
			dbg_xfrin("Fallback to AXFR.\n");
			ret = XFRIN_RES_FALLBACK;
			return ret;
		}
	} else {
		if ((*chs)->first_soa == NULL) {
			dbg_xfrin("Changesets don't contain SOA first!\n");
			knot_rrset_deep_free(&rr, 1);
			ret = KNOT_EINVAL;
			goto cleanup;
		}
		dbg_xfrin_detail("Changesets present.\n");
	}

	/*
	 * Process the next RR. Different requirements are in place in
	 * different cases:
	 *
	 * 1) Last changeset has both soa_from and soa_to.
	 *    a) The next RR is a SOA.
	 *      i) The next RR is equal to the first_soa saved in changesets.
	 *         This denotes the end of the transfer. It may be dropped and
	 *         the end should be signalised by returning positive value.
	 *
	 *      ii) The next RR is some other SOA.
	 *          This means a start of new changeset - create it and add it
	 *          to the list.
	 *
	 *    b) The next RR is not a SOA.
	 *       Put the RR into the ADD part of the last changeset as this is
	 *       not finished yet. Continue while SOA is not encountered. Then
	 *       jump to 1-a.
	 *
	 * 2) Last changeset has only the soa_from and does not have soa_to.
	 *    a) The next RR is a SOA.
	 *       This means start of the ADD section. Put the SOA to the
	 *       changeset. Continue adding RRs to the ADD section while SOA
	 *       is not encountered. This is identical to 1-b.
	 *
	 *    b) The next RR is not a SOA.
	 *       This means the REMOVE part is not finished yet. Add the RR to
	 *       the REMOVE part. Continue adding next RRs until a SOA is
	 *       encountered. Then jump to 2-a.
	 */

	// first, find out in what state we are
	/*! \todo It would be more elegant to store the state in the
	 *        changesets structure, or in some place persistent between
	 *        calls to this function.
	 */
	knot_changeset_t *cur = knot_changesets_get_last(*chs);
	if (state != -1) {
		dbg_xfrin_detail("State is not -1, deciding...\n");
		// there should be at least one started changeset right now
		if (EMPTY_LIST((*chs)->sets)) {
			knot_rrset_deep_free(&rr, 1);
			ret = KNOT_EMALF;
			goto cleanup;
		}

		// a changeset should be created only when there is a SOA
		assert(cur->soa_from != NULL);

		if (cur->soa_to == NULL) {
			state = KNOT_CHANGESET_REMOVE;
		} else {
			state = KNOT_CHANGESET_ADD;
		}
	}

	dbg_xfrin_detail("State before the loop: %d\n", state);

	/*! \todo This may be implemented with much less IFs! */

	while (ret == KNOT_EOK && rr != NULL) {
dbg_xfrin_exec_verb(
		dbg_xfrin_detail("Next loop, state: %d\n", state);
		char *name = knot_dname_to_str(knot_rrset_owner(rr));
		dbg_xfrin_detail("Actual RR: %s, type %u.\n", name,
				 knot_rrset_type(rr));
		free(name);
);
		if (!knot_dname_is_sub(rr->owner, xfr->zone->name) &&
		    !knot_dname_is_equal(rr->owner, xfr->zone->name)) {
			// out-of-zone domain
			xfrin_log_error(xfr->zone->name, rr, KNOT_EOUTOFZONE);
			knot_rrset_deep_free(&rr, 1);
			// Skip this rr
			ret = knot_packet_parse_next_rr_answer(packet, &rr);
			continue;
		}
		
		switch (state) {
		case -1:
			// a SOA is expected
			// this may be either a start of a changeset or the
			// last SOA (in case the transfer was empty, but that
			// is quite weird in fact
			if (knot_rrset_type(rr) != KNOT_RRTYPE_SOA) {
				dbg_xfrin("First RR is not a SOA RR!\n");
				dbg_xfrin_verb("RR type: %u\n",
					       knot_rrset_type(rr));
				ret = KNOT_EMALF;
				knot_rrset_deep_free(&rr, 1);
				goto cleanup;
			}

			if (knot_rdata_soa_serial(rr)
			    == knot_rdata_soa_serial((*chs)->first_soa)) {

				/*! \note [TSIG] Check TSIG, we're at the end of
				 *               transfer.
				 */
				ret = xfrin_check_tsig(packet, xfr, 1);

				// last SOA, discard and end
				knot_rrset_deep_free(&rr, 1);
				knot_packet_free(&packet);

				/*! \note [TSIG] If TSIG validates, consider
				 *        transfer complete. */
				if (ret == KNOT_EOK) {
					ret = XFRIN_RES_COMPLETE;
				}

				return ret;
			} else {
				// normal SOA, start new changeset
				/* Check changesets for maximum count (so they fit into journal). */
				if ((*chs)->count + 1 > JOURNAL_NCOUNT)
					ret = KNOT_ESPACE;

				if (ret != KNOT_EOK) {
					knot_rrset_deep_free(&rr, 1);
					goto cleanup;
				}

				cur = knot_changesets_create_changeset(*chs);
				if (cur == NULL) {
					knot_rrset_deep_free(&rr, 1);
					goto cleanup;
				}
				knot_changeset_add_soa(cur, rr, KNOT_CHANGESET_REMOVE);

				// change state to REMOVE
				state = KNOT_CHANGESET_REMOVE;
			}
			break;
		case KNOT_CHANGESET_REMOVE:
			// if the next RR is SOA, store it and change state to
			// ADD
			if (knot_rrset_type(rr) == KNOT_RRTYPE_SOA) {
				// we should not be here if soa_from is not set
				assert(cur->soa_from != NULL);

				knot_changeset_add_soa(cur, rr, KNOT_CHANGESET_ADD);

				state = KNOT_CHANGESET_ADD;
			} else {
				// just add the RR to the REMOVE part and
				// continue
				ret = knot_changeset_add_rr(cur, rr,
				                            KNOT_CHANGESET_REMOVE);
				if (ret != KNOT_EOK) {
					knot_rrset_deep_free(&rr, 1);
					goto cleanup;
				}
			}
			break;
		case KNOT_CHANGESET_ADD:
			// if the next RR is SOA change to state -1 and do not
			// parse next RR
			if (knot_rrset_type(rr) == KNOT_RRTYPE_SOA) {
				log_zone_info("%s Serial %u -> %u.\n",
					      xfr->msg,
					      knot_rdata_soa_serial(cur->soa_from),
					      knot_rdata_soa_serial(cur->soa_to));
				state = -1;
				continue;
			} else {

				// just add the RR to the ADD part and continue
				ret = knot_changeset_add_rr(cur, rr,
				                            KNOT_CHANGESET_ADD);
				if (ret != KNOT_EOK) {
					knot_rrset_deep_free(&rr, 1);
					goto cleanup;
				}
			}
			break;
		}

		// parse the next RR
		dbg_xfrin_detail("Parsing next RR..\n");
		ret = knot_packet_parse_next_rr_answer(packet, &rr);
		dbg_xfrin_detail("Returned %d, %p.\n", ret, rr);
	}

	/*! \note Check TSIG, we're at the end of packet. It may not be
	 *        required.
	 */
	ret = xfrin_check_tsig(packet, xfr,
			       knot_ns_tsig_required(xfr->packet_nr));
	dbg_xfrin_verb("xfrin_check_tsig() returned %d\n", ret);
	++xfr->packet_nr;

	/*! \note [TSIG] Cleanup and propagate error if TSIG validation fails.*/
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	// here no RRs remain in the packet but the transfer is not finished
	// yet, return EOK
	knot_packet_free(&packet);
	return KNOT_EOK;

cleanup:
	/* We should go here only if some error occured. */
	assert(ret < 0);

	dbg_xfrin_detail("Cleanup after processing IXFR/IN packet.\n");
	knot_changesets_free(chs);
	knot_packet_free(&packet);
	xfr->data = 0;
	return ret;
}

/*----------------------------------------------------------------------------*/
/* Applying changesets to zone                                                */
/*----------------------------------------------------------------------------*/

void xfrin_zone_contents_free(knot_zone_contents_t **contents)
{
	/*! \todo This should be all in some API!! */

	// free the zone tree with nodes
	dbg_zone("Destroying zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nodes);
	dbg_zone("Destroying NSEC3 zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nsec3_nodes);

	knot_nsec3_params_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

int xfrin_copy_old_rrset(knot_rrset_t *old, knot_rrset_t **copy,
                         knot_changes_t *changes, int save_new)
{
	dbg_xfrin_detail("Copying old RRSet: %p\n", old);
	// create new RRSet by copying the old one
	int ret = knot_rrset_deep_copy(old, copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to create RRSet copy.\n");
		return KNOT_ENOMEM;
	}

	// add the RRSet to the list of new RRSets, RRSIG as well
	if (save_new) {
		ret = knot_changes_add_rrset(changes, *copy, KNOT_CHANGES_NEW);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(copy, 1);
			return ret;
		}
		if ((*copy)->rrsigs != NULL) {
			assert(old->rrsigs != NULL);
			ret = knot_changes_add_rrset(changes, (*copy)->rrsigs,
			      KNOT_CHANGES_NEW);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&((*copy)->rrsigs), 1);
				return ret;
			}
		}
	}

	ret = knot_changes_add_rrset(changes, old, KNOT_CHANGES_OLD);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (old->rrsigs != NULL) {
		ret = knot_changes_add_rrset(changes, old->rrsigs,
		                             KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_copy_rrset(knot_node_t *node, uint16_t type,
                     knot_rrset_t **rrset, knot_changes_t *changes,
                     int save_new)
{
dbg_xfrin_exec_detail(
	char *name = knot_dname_to_str(knot_node_owner(node));
	dbg_xfrin_detail("Removing RRSet of type %u from node %s (%p)\n",
			 type, name, node);
	free(name);
);
	knot_rrset_t *old = knot_node_remove_rrset(node, type);

	dbg_xfrin_detail("Removed RRSet: %p\n", old);
	dbg_xfrin_detail("Other RRSet of the same type in the node: %p\n",
			 knot_node_rrset(node, type));

	if (old == NULL) {
		dbg_xfrin_verb("RRSet not found for RR to be removed.\n");
		return 1;
	}

	int ret = xfrin_copy_old_rrset(old, rrset, changes, save_new);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_xfrin_detail("Copied old rrset %p to new %p.\n", old, *rrset);

	// replace the RRSet in the node copy by the new one
	ret = knot_node_add_rrset_replace(node, *rrset);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(rrset, 1);
		dbg_xfrin("Failed to add RRSet copy to node\n");
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_remove_rrsigs(knot_changes_t *changes,
                                     const knot_rrset_t *remove,
                                     knot_node_t *node,
                                     knot_rrset_t **rrset,
                                     knot_rrset_t **rrsigs_old)
{
	assert(changes != NULL);
	assert(remove != NULL);
	assert(node != NULL);
	assert(rrset != NULL);
	assert(knot_rrset_type(remove) == KNOT_RRTYPE_RRSIG);

	/*! \todo These optimalizations may be useless as there may be only
	 *        one RRSet of each type and owner in the changeset.
	 */

	int ret = KNOT_EOK;

	int copied = 0;

	if (*rrset
	    && knot_dname_is_equal(knot_rrset_owner(*rrset), knot_node_owner(node))
	    && knot_rrset_type(*rrset) == knot_rdata_rrsig_type_covered(remove, 0)) {
		// this RRSet should be the already copied RRSet so we may
		// update it right away
		/*! \todo Does this case even occur? */
		dbg_xfrin_verb("Using RRSet from previous iteration.\n");
	} else {
		// find RRSet based on the Type Covered
		uint16_t type = knot_rdata_rrsig_type_covered(remove, 0);

		// copy the rrset
		dbg_xfrin_detail("Copying RRSet that carries the RRSIGs.\n");
		ret = xfrin_copy_rrset(node, type, rrset, changes, 1);
		if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to copy rrset from changeset.\n");
			return ret;
		}
		dbg_xfrin_detail("Copied RRSet:\n");
		knot_rrset_dump(*rrset);
		copied = 1;
	}

	// get the old rrsigs
	knot_rrset_t *old = knot_rrset_get_rrsigs(*rrset);
	dbg_xfrin_detail("Old RRSIGs from RRSet: %p\n", old);
	if (old == NULL) {
		return 1;
	}

	// copy the RRSIGs
	knot_rrset_t *rrsigs = NULL;
	if (!copied) {
		// check if the stored RRSIGs are not the right ones
		if (*rrsigs_old && *rrsigs_old == (*rrset)->rrsigs) {
			dbg_xfrin_verb("Using RRSIG from previous iteration\n");
			rrsigs = *rrsigs_old;
		} else {
			ret = xfrin_copy_old_rrset(old, &rrsigs, changes, 1);
			if (ret != KNOT_EOK) {
				return ret;
			}
			dbg_xfrin_detail("Copied RRSIGs: %p\n", rrsigs);
			dbg_xfrin_detail("Copied RRSet:\n");
			knot_rrset_dump(rrsigs);
		}
	} else {
		rrsigs = old;
		dbg_xfrin_detail("Using old RRSIGs: %p\n", rrsigs);
	}

	// set the RRSIGs to the new RRSet copy
	if (knot_rrset_set_rrsigs(*rrset, rrsigs) != KNOT_EOK) {
		dbg_xfrin("Failed to set rrsigs.\n");
		return KNOT_ERROR;
	}

	*rrsigs_old = rrsigs;

	// now in '*rrset' we have a copy of the RRSet which holds the RRSIGs
	// and in 'rrsigs' we have the copy of the RRSIGs

	knot_rrset_t *rr_removed = NULL;
	ret = knot_rrset_remove_rr_using_rrset(rrsigs, remove, &rr_removed);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to remove RDATA from RRSet: %s.\n",
			  knot_strerror(ret));
		return 1;
	}
	/* This RRSet will be created even when nothing was removed. */
	assert(rr_removed);

	// connect the RDATA to the list of old RDATA
	ret = knot_changes_add_rrset(changes, rr_removed, KNOT_CHANGES_OLD);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&rr_removed, 1);
		return ret;
	}

	// if the RRSet is empty, remove from node and add to old RRSets
	// check if there is no RRSIGs; if there are, leave the RRSet
	// there; it may be eventually removed when the RRSIGs are removed
	if (knot_rrset_rdata_rr_count(rrsigs) == 0) {
		// remove the RRSIGs from the RRSet
		knot_rrset_set_rrsigs(*rrset, NULL);

		// add RRSet to the list of old RRSets
		ret = knot_changes_add_rrset(changes, rrsigs, KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to add empty RRSet to the "
				  "list of old RRSets.");
			// delete the RRSet right away
			knot_rrset_free(&rrsigs);
			return ret;
		}

		// now check if the RRSet is not totally empty
		if (knot_rrset_rdata_rr_count(*rrset) == 0) {
			assert(knot_rrset_rrsigs(*rrset) == NULL);
			// remove the whole RRSet from the node
			knot_rrset_t *tmp = knot_node_remove_rrset(node,
						     knot_rrset_type(*rrset));
			assert(tmp == *rrset);
			int ret = knot_changes_add_rrset(changes, *rrset,
			                                 KNOT_CHANGES_OLD);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_remove_normal(knot_changes_t *changes,
                                     const knot_rrset_t *remove,
                                     knot_node_t *node,
                                     knot_rrset_t **rrset)
{
	assert(changes != NULL);
	assert(remove != NULL);
	assert(node != NULL);
	assert(rrset != NULL);

	int ret;

	dbg_xfrin_detail("Removing RRSet: \n");
	knot_rrset_dump(remove);

	// now we have the copy of the node, so lets get the right RRSet
	// check if we do not already have it
	if (*rrset
	    && knot_dname_cmp(knot_rrset_owner(*rrset),
				  knot_node_owner(node)) == 0
	    && knot_rrset_type(*rrset) == knot_rrset_type(remove)) {
		/*! \todo Does some other case even occur? */
		dbg_xfrin_verb("Using RRSet from previous loop.\n");
	} else {
		/*!
		 * \todo This may happen also with already
		 *       copied RRSet. In that case it would be
		 *       an unnecesary overhead but will
		 *       probably not cause problems. TEST!!
		 */
		ret = xfrin_copy_rrset(node,
			knot_rrset_type(remove), rrset, changes, 1);
		if (ret != KNOT_EOK) {
			return ret;
		}
		dbg_xfrin_detail("Copied RRSet:\n");
		knot_rrset_dump(*rrset);
	}

	if (*rrset == NULL) {
		dbg_xfrin_verb("RRSet not found for RR to be removed.\n");
		return 1;
	}

dbg_xfrin_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(*rrset));
	dbg_xfrin_detail("Updating RRSet with owner %s, type %u\n", name,
			 knot_rrset_type(*rrset));
	free(name);
);

	// remove the specified RRs from the RRSet (de facto difference of sets)
	knot_rrset_t *rr_remove = NULL;
	ret = knot_rrset_remove_rr_using_rrset(*rrset, remove, &rr_remove);
	if (ret != KNOT_EOK) {
		dbg_xfrin("xfr: remove_normal: Could not remove RR (%s).\n",
			  knot_strerror(ret));
		return ret;
	}
	/*!< \todo either one of these checks should be enough. */
	if (knot_rrset_rdata_rr_count(rr_remove) == 0) {
		/* No RDATA, no need to deep free. */
		knot_rrset_free(&rr_remove);
		dbg_xfrin_verb("Failed to remove RDATA from RRSet\n");
		// In this case, the RDATA was not found in the RRSet
		return 1;
	}

	if (rr_remove->rdata_count != 0) {
		ret = knot_changes_add_rrset(changes, rr_remove, KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&rr_remove);
			return ret;
		}
	} else {
		/* Discard empty RRSet. */
		knot_rrset_free(&rr_remove);
	}

	// if the RRSet is empty, remove from node and add to old RRSets
	// check if there is no RRSIGs; if there are, leave the RRSet
	// there; it may be eventually removed when the RRSIGs are removed
	if (knot_rrset_rdata_rr_count(*rrset) == 0
	    && knot_rrset_rrsigs(*rrset) == NULL) {
		knot_rrset_t *tmp = knot_node_remove_rrset(node,
						     knot_rrset_type(*rrset));
		dbg_xfrin_detail("Removed whole RRSet (%p). Node rr count=%d\n",
				 tmp, knot_node_rrset_count(node));

		// add the removed RRSet to list of old RRSets

		assert(tmp == *rrset);
		ret = knot_changes_add_rrset(changes, *rrset, KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to add empty RRSet to the "
				  "list of old RRSets.");
			// delete the RRSet right away
			knot_rrset_free(rrset);
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static knot_node_t *xfrin_add_new_node(knot_zone_contents_t *contents,
                                       knot_rrset_t *rrset, int is_nsec3)
{
	knot_node_t *node = knot_node_new(knot_rrset_get_owner(rrset),
					  NULL, 0);
	if (node == NULL) {
		dbg_xfrin("Failed to create a new node.\n");
		return NULL;
	}

	int ret = 0;

	// insert the node into zone structures and create parents if
	// necessary
	if (is_nsec3) {
		ret = knot_zone_contents_add_nsec3_node(contents, node, 1, 0);
	} else {
		ret = knot_zone_contents_add_node(contents, node, 1, 0);
	}
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to add new node to zone contents.\n");
		knot_node_free(&node);
		return NULL;
	}

	return node;
}

/*----------------------------------------------------------------------------*/

int xfrin_replace_rrset_in_node(knot_node_t *node,
                                       knot_rrset_t *rrset_new,
                                       knot_changes_t *changes,
                                       knot_zone_contents_t *contents)
{
	if (node == NULL || rrset_new == NULL || changes == NULL
	    || contents == NULL) {
		return KNOT_EINVAL;
	}

	uint16_t type = knot_rrset_type(rrset_new);
	// remove RRSet of the proper type from the node
	dbg_xfrin_verb("Removing RRSet of type: %u.\n", type);
	knot_rrset_t *rrset_old = knot_node_remove_rrset(node, type);
	assert(rrset_old != NULL);

	// save also the RDATA, because RDATA are not deleted with the RRSet
	// save the new RRSet to the new RRSet, so that it is deleted if the
	// apply fails
	int ret = knot_changes_add_rrset(changes, rrset_old, KNOT_CHANGES_OLD);
	if (ret != KNOT_EOK) {
		return ret;
	}
	// store RRSIGs from the old RRSet to the new
	knot_rrset_set_rrsigs(rrset_new, knot_rrset_get_rrsigs(rrset_old));

	// insert the new RRSet to the node
	dbg_xfrin_verb("Adding new RRSet.\n");
	ret = knot_zone_contents_add_rrset(contents, rrset_new, &node,
	                                   KNOT_RRSET_DUPL_SKIP);

	if (ret < 0) {
		dbg_xfrin("Failed to add RRSet to node.\n");
		return KNOT_ERROR;
	}
	assert(ret == 0);

	ret = knot_changes_add_rrset(changes, rrset_new, KNOT_CHANGES_NEW);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_add_normal(knot_changes_t *changes,
                                  knot_rrset_t *add,
                                  knot_node_t *node,
                                  knot_rrset_t **rrset,
                                  knot_zone_contents_t *contents)
{
	assert(changes != NULL);
	assert(add != NULL);
	assert(node != NULL);
	assert(rrset != NULL);
	assert(contents != NULL);

	int ret;

dbg_xfrin_exec_detail(
	dbg_xfrin_detail("applying rrset:\n");
	knot_rrset_dump(add);
);

	int copied = 0;
	/*! \note Reusing RRSet from previous function caused it not to be
	 *        removed from the node.
	 *        Maybe modification of the code would allow reusing the RRSet
	 *        as in apply_add_rrsigs() - the RRSet should not be copied
	 *        in such case.
	 */
	if (*rrset
	    && knot_dname_cmp(knot_rrset_owner(*rrset),
				  knot_node_owner(node)) == 0
	    && knot_rrset_type(*rrset) == knot_rrset_type(add)) {
		dbg_xfrin_verb("Using RRSet from previous iteration.\n");
	} else {
		dbg_xfrin_detail("Removing rrset!\n");
		*rrset = knot_node_remove_rrset(node, knot_rrset_type(add));

		knot_rrset_t *old = *rrset;

		if (*rrset != NULL) {
			ret = xfrin_copy_old_rrset(old, rrset, changes, 1);
			if (ret != KNOT_EOK) {
				return ret;
			}

			dbg_xfrin_detail("Copied RRSet: %p\n", *rrset);
			dbg_xfrin_detail("Copied RRSet:\n");
			knot_rrset_dump(*rrset);
			copied = 1;
		}
	}

dbg_xfrin_exec_detail(
	dbg_xfrin_detail("Removed RRSet: \n");
	knot_rrset_dump(*rrset);
);

	if (*rrset == NULL) {
dbg_xfrin_exec_detail(
		char *name = knot_dname_to_str(add->owner);
		dbg_xfrin_detail("RRSet to be added not found in zone.\n");
		dbg_xfrin_detail("owner: %s type: %u\n", name, add->type);
		free(name);
);
		// add the RRSet from the changeset to the node
		/*!
		 * \note The new zone must be adjusted nevertheless, so it
		 *       doesn't matter whether there are some extra dnames to
		 *       be added to the table or not.
		 */
		ret = knot_zone_contents_add_rrset(contents, add, &node,
						   KNOT_RRSET_DUPL_SKIP);

		if (ret < 0) {
			dbg_xfrin("Failed to add RRSet to node.\n");
			return ret;
		}

		assert(ret == 0);

		return 1; // return 1 to indicate the add RRSet was used
	}

dbg_xfrin_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(*rrset));
	dbg_xfrin_detail("Found RRSet with owner %s, type %u\n", name,
			 knot_rrset_type(*rrset));
	free(name);
);

	// merge the changeset RRSet to the copy
	/* What if the update fails?
	 * The changesets will be destroyed - that will destroy 'add',
	 * and the copied RRSet will be destroyed because it is in the new
	 * rrsets list.
	 *
	 * If the update is successfull, the old RRSet will be destroyed,
	 * but the one from the changeset will be not!!
	 *
	 * TODO: add the 'add' rrset to list of old RRSets?
	 */

	dbg_xfrin_detail("Merging RRSets with owners: %s, %s types: %u, %u\n",
			 (*rrset)->owner, add->owner,
			 (*rrset)->type,
			 add->type);
	dbg_xfrin_detail("RDATA in RRSet1: %p, RDATA in RRSet2: %p\n",
			 (*rrset)->rdata, add->rdata);

	/* In case the RRSet is empty (and only remained there because of the
	 * RRSIGs) it may happen that the TTL may be different than that of
	 * the new RRs. Update the TTL according to the first RR.
	 */

	if (knot_rrset_rdata_rr_count(*rrset) == 0
	    && knot_rrset_ttl(*rrset) != knot_rrset_ttl(add)) {
		knot_rrset_set_ttl(*rrset, knot_rrset_ttl(add));
	}

	int merged, deleted_rrs;
	ret = knot_rrset_merge_sort(*rrset, add, &merged, &deleted_rrs);
	if (ret < 0) {
		dbg_xfrin("Failed to merge changeset RRSet.\n");
		return ret;
	}
	dbg_xfrin_detail("Merge returned: %d\n", ret);
	knot_rrset_dump(*rrset);

	if (copied) {
		ret = knot_node_add_rrset_no_merge(node, *rrset);

		if (ret < 0) {
			dbg_xfrin("Failed to add merged RRSet to the node.\n");
			return ret;
		}
	}

	// return 2 so that the add RRSet is removed from
	// the changeset (and thus not deleted)
	// and put to list of new RRSets (is this ok?)
	// and deleted
	return 2;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_add_rrsig(knot_changes_t *changes,
                                  knot_rrset_t *add,
                                  knot_node_t *node,
                                  knot_rrset_t **rrset,
                                  knot_rrset_t **rrsigs_old,
                                  knot_zone_contents_t *contents)
{
	assert(changes != NULL);
	assert(add != NULL);
	assert(node != NULL);
	assert(rrset != NULL);
	assert(knot_rrset_type(add) == KNOT_RRTYPE_RRSIG);
	assert(contents != NULL);

	int ret;

	uint16_t type = knot_rdata_rrsig_type_covered(add, 0);

dbg_xfrin_exec_verb(
	char *name = knot_dname_to_str(knot_rrset_owner(add));
	dbg_xfrin_verb("Adding RRSIG: Owner %s, type covered %u.\n",
		       name, type);
	free(name);
);

	int copied = 0;

	/*! \note Here the check is OK, because if we aready have the RRSet,
	 *        it's a copied one, so it is OK to modify it right away.
	 */
	if (*rrset
	    && knot_dname_cmp(knot_rrset_owner(*rrset),
				  knot_node_owner(node)) == 0
	    && knot_rrset_type(*rrset) == type) {
		dbg_xfrin_verb("Using RRSet from previous iteration.\n");
	} else {
		// copy the rrset
		ret = xfrin_copy_rrset(node, type, rrset, changes, 1);
		if (ret < 0) {
			return ret;
		} else if (ret != KNOT_EOK) {
			*rrset = NULL;
		}
		copied = 1;
		dbg_xfrin_detail("Copied RRSet:\n");
		knot_rrset_dump(*rrset);
	}

	if (*rrset == NULL) {
		dbg_xfrin_detail("RRSet to be added not found in zone.\n");

		// create a new RRSet to add the RRSIGs into
		knot_dname_t *owner_copy = knot_dname_copy(knot_node_get_owner(node));
		*rrset = knot_rrset_new(owner_copy, type,
					knot_rrset_class(add),
					knot_rrset_ttl(add));
		if (*rrset == NULL) {
			knot_dname_free(&owner_copy);
			dbg_xfrin("Failed to create new RRSet for RRSIGs.\n");
			return KNOT_ENOMEM;
		}
		dbg_xfrin_detail("Created new RRSet for RRSIG: %p.\n", *rrset);

		// add the RRset to the list of new RRsets
		// add the new RRSet to the node
		// not needed to insert it through the zone_contents() function,
		// as the owner is already in the dname table
		ret = knot_node_add_rrset_no_merge(node, *rrset);
		if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to add RRSet to node.\n");
			knot_rrset_free(rrset);
			return KNOT_ERROR;
		}

		ret = knot_changes_add_rrset(changes, *rrset, KNOT_CHANGES_NEW);
		if (ret != KNOT_EOK) {
			knot_rrset_free(rrset);
			return ret;
		}
	}

dbg_xfrin_exec_detail(
		char *name = knot_dname_to_str(knot_rrset_owner(*rrset));
		dbg_xfrin_detail("Found RRSet with owner %s, type %u\n", name,
				 knot_rrset_type(*rrset));
		free(name);
);

	if (knot_rrset_rrsigs(*rrset) == NULL) {

		dbg_xfrin_detail("Adding new RRSIGs to RRSet.\n");
		ret = knot_zone_contents_add_rrsigs(contents, add, rrset, &node,
						    KNOT_RRSET_DUPL_SKIP);

		if (ret < 0) {
			dbg_xfrin("Failed to add RRSIGs to the RRSet.\n");
			return KNOT_ERROR;
		}

		dbg_xfrin_detail("RRSet after added RRSIG:\n");
		knot_rrset_dump(*rrset);

		assert(ret == 0);

		return 1;
	} else {
		knot_rrset_t *old = knot_rrset_get_rrsigs(*rrset);
		assert(old != NULL);
		knot_rrset_t *rrsig;

		if (!copied) {
			// check if the stored RRSIGs are not the right ones
			if (*rrsigs_old && *rrsigs_old == old) {
				dbg_xfrin_verb("Using RRSIG from previous iteration\n");
				rrsig = *rrsigs_old;
			} else {
				ret = xfrin_copy_old_rrset(old, &rrsig, changes,
							   1);
				if (ret != KNOT_EOK) {
					return ret;
				}
				dbg_xfrin_detail("Copied RRSIGs: %p\n", rrsig);
				dbg_xfrin_detail("Copied RRSet:\n");
				knot_rrset_dump(rrsig);
			}
		} else {
			rrsig = old;
			dbg_xfrin_verb("Using old RRSIGs: %p\n", rrsig);
		}

		// replace the old RRSIGs with the new ones
		knot_rrset_set_rrsigs(*rrset, rrsig);

		// merge the changeset RRSet to the copy
		dbg_xfrin_detail("Merging RRSIG to the one in the RRSet.\n");
		int merged, deleted_rrs;
		ret = knot_rrset_merge_sort(rrsig, add, &merged, &deleted_rrs);
		if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to merge changeset RRSIG to copy: %s"
				  ".\n", knot_strerror(ret));
			return KNOT_ERROR;
		}

		return 2;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void xfrin_cleanup_successful_update(knot_changes_t *changes)
{
	if (changes == NULL) {
		return;
	}
	// Free old RRSets
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, changes->old_rrsets) {
		knot_rrset_t *rrset = rr_node->rr;
		knot_rrset_deep_free_no_sig(&rrset, 1);
	}
}

/*----------------------------------------------------------------------------*/
/* New changeset applying                                                     */
/*----------------------------------------------------------------------------*/

static int xfrin_switch_nodes_in_node(knot_node_t **node, void *data)
{
	UNUSED(data);

	assert(node && *node);
	assert(knot_node_new_node(*node) == NULL);

	knot_node_update_refs(*node);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_switch_nodes(knot_zone_contents_t *contents_copy)
{
	assert(contents_copy != NULL);

	// Traverse the trees and for each node check every reference
	// stored in that node. The node itself should be new.
	int ret = knot_zone_tree_apply(contents_copy->nodes,
	                               xfrin_switch_nodes_in_node, NULL);
	if (ret == KNOT_EOK) {
		ret = knot_zone_tree_apply(contents_copy->nsec3_nodes,
		                           xfrin_switch_nodes_in_node, NULL);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static void xfrin_zone_contents_free2(knot_zone_contents_t **contents)
{
	/*! \todo This should be all in some API!! */

	// free the zone tree, but only the structure
	// (nodes are already destroyed)
	dbg_zone("Destroying zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nodes);
	dbg_zone("Destroying NSEC3 zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nsec3_nodes);

	knot_nsec3_params_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

static int xfrin_cleanup_old_nodes(knot_node_t **node, void *data)
{
	UNUSED(data);
	assert(node && *node);

	knot_node_set_new_node(*node, NULL);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static void xfrin_cleanup_failed_update(knot_zone_contents_t *old_contents,
                                        knot_zone_contents_t **new_contents)
{
	if (old_contents == NULL && new_contents == NULL) {
		return;
	}

	if (*new_contents != NULL) {
		// destroy the shallow copy of zone
		xfrin_zone_contents_free2(new_contents);
	}

	if (old_contents != NULL) {
		// cleanup old zone tree - reset pointers to new node to NULL
		knot_zone_tree_apply(old_contents->nodes, xfrin_cleanup_old_nodes,
				     NULL);

		knot_zone_tree_apply(old_contents->nsec3_nodes, xfrin_cleanup_old_nodes,
				     NULL);
	}
}

/*----------------------------------------------------------------------------*/

void xfrin_rollback_update(knot_zone_contents_t *old_contents,
                           knot_zone_contents_t **new_contents,
                           knot_changes_t *changes)
{
	if (changes == NULL) {
		return;
	}

	dbg_xfrin("Rolling back changeset application.\n");
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, changes->new_rrsets) {
		knot_rrset_t *rrset = rr_node->rr;
		knot_rrset_deep_free_no_sig(&rrset, 1);
	}

	xfrin_cleanup_failed_update(old_contents, new_contents);
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_remove(knot_zone_contents_t *contents,
                              knot_changeset_t *chset,
                              knot_changes_t *changes)
{
	/*
	 * Iterate over removed RRSets, and remove them from the new nodes
	 * in 'contents'. By default, the RRSet should be copied so that
	 * RDATA may be removed from it.
	 */
	int ret = 0;
	knot_node_t *last_node = NULL;
	knot_rrset_t *rrset = NULL;
	knot_rrset_t *rrsigs = NULL;
	int is_nsec3 = 0;

	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chset->remove) {
		knot_rrset_t *rr = rr_node->rr;
		assert(rr); // No malformed changesets should get here
dbg_xfrin_exec_verb(
		char *name = knot_dname_to_str(
			knot_rrset_owner(rr));
		dbg_xfrin_verb("Removing RRSet: %s, type %u\n", name,
			       knot_rrset_type(rr));
		free(name);
);
dbg_xfrin_exec_detail(
		knot_rrset_dump(rr);
);

		is_nsec3 = 0;

		// check if the RRSet belongs to the NSEC3 tree
		if ((knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3)
		    || (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG
			&& knot_rdata_rrsig_type_covered(rr, 0)
			    == KNOT_RRTYPE_NSEC3))
		{
			dbg_xfrin_verb("Removed RRSet belongs to NSEC3 tree.\n");
			is_nsec3 = 1;
		}

		// check if the old node is not the one we should use
		dbg_xfrin_verb("Node:%p Owner: %p Node owner: %p\n",
			       last_node, knot_rrset_owner(rr),
			       knot_node_owner(last_node));
		if (!last_node || knot_rrset_owner(rr)
			     != knot_node_owner(last_node)) {
			if (is_nsec3) {
				last_node = knot_zone_contents_get_nsec3_node(
					    contents,
					    knot_rrset_owner(rr));
			} else {
				last_node = knot_zone_contents_get_node(contents,
					    knot_rrset_owner(rr));
			}
			if (last_node == NULL) {
				dbg_xfrin_verb("Node not found for RR to be "
					       "removed!\n");
				continue;
			}
		}

		assert(last_node != NULL);

		// The CLASS should not be ANY, we do not accept such chgsets
		dbg_xfrin_verb("RRSet class to be removed=%u\n",
			       knot_rrset_class(rr));
		if (knot_rrset_type(rr)
			   == KNOT_RRTYPE_RRSIG) {
			// this should work also for UPDATE
			ret = xfrin_apply_remove_rrsigs(changes, rr, last_node,
			                                &rrset, &rrsigs);
		} else {
			// this should work also for UPDATE
			ret = xfrin_apply_remove_normal(changes, rr, last_node,
			                                &rrset);
		}

		dbg_xfrin_detail("xfrin_apply_remove() ret = %d\n", ret);

		if (ret > 0) {
			continue;
		} else if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_add(knot_zone_contents_t *contents,
                           knot_changeset_t *chset,
                           knot_changes_t *changes)
{
	int ret = KNOT_EOK;
	knot_node_t *last_node = NULL;
	knot_rrset_t *rrset = NULL;
	knot_rrset_t *rrsigs = NULL;
	int is_nsec3 = 0;

	knot_rr_ln_t *rr_node = NULL;
	node_t *tmp_node;
	WALK_LIST_DELSAFE(rr_node, tmp_node, chset->add) {
		knot_rrset_t *rr = rr_node->rr;
		assert(rr); // No malformed changesets should get here
dbg_xfrin_exec_verb(
		char *name = knot_dname_to_str(
			knot_rrset_owner(rr));
		dbg_xfrin_verb("Adding RRSet: %s, type: %u\n", name,
			       knot_rrset_type(rr));
		free(name);
);
dbg_xfrin_exec_detail(
		knot_rrset_dump(rr);
);

		is_nsec3 = 0;

		// check if the RRSet belongs to the NSEC3 tree
		if ((knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3)
		    || (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG
			&& knot_rdata_rrsig_type_covered(rr, 0)
			    == KNOT_RRTYPE_NSEC3))
		{
			dbg_xfrin_detail("This is NSEC3-related RRSet.\n");
			is_nsec3 = 1;
		}

		// check if the old node is not the one we should use
		if (!last_node || knot_rrset_owner(rr)
			     != knot_node_owner(last_node)) {
			dbg_xfrin_detail("Searching for node...\n");
			if (is_nsec3) {
				last_node = knot_zone_contents_get_nsec3_node(
				            contents,
				            knot_rrset_owner(rr));
			} else {
				last_node = knot_zone_contents_get_node(contents,
				            knot_rrset_owner(rr));
			}
			if (last_node == NULL) {
				// create new node, connect it properly to the
				// zone nodes
				dbg_xfrin_detail("Node not found. Creating new."
						 "\n");
				last_node = xfrin_add_new_node(contents,
							  rr,
							  is_nsec3);
				if (last_node == NULL) {
					dbg_xfrin("Failed to create new node "
						  "in zone.\n");
					return KNOT_ERROR;
				}
			}
		}

		assert(last_node != NULL);

		if (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG) {
			ret = xfrin_apply_add_rrsig(changes, rr, last_node,
			                            &rrset, &rrsigs, contents);
			assert(ret != KNOT_EOK);
		} else {
			ret = xfrin_apply_add_normal(changes, rr, last_node,
			                             &rrset, contents);
			assert(ret <= 3);
		}

		// Not correct anymore, add_normal() returns KNOT_EOK if the
		// changeset RR should be removed
		//assert(ret != KNOT_EOK);

		dbg_xfrin_detail("xfrin_apply_..() returned %d, rrset: %p\n",
				 ret, rrset);

		if (ret > 0) {
			if (ret == 1) {
				// the ADD RRSet was used, i.e. it should be
				// removed from the changeset and saved in the
				// list of new RRSets
				ret = knot_changes_add_rrset(changes, rr,
				                             KNOT_CHANGES_NEW);
				if (ret != KNOT_EOK) {
					dbg_xfrin("Failed to add old RRSet to "
						  "list.\n");
					return ret;
				}

				rem_node((node_t *)rr_node);
			} else if (ret == 2) {
				// the copy of the RRSet was used, but it was
				// already stored in the new RRSets list
				// just delete the add RRSet, but without RDATA
				// DNAMES as these were merged to the copied RRSet
				knot_rrset_deep_free(&rr, 1);
				rem_node((node_t *)rr_node);
			} else if (ret == 3) {
				// the RRSet was used and both RRSet and RDATA
				// were properly stored. Just clear the place
				// in the changeset
				rem_node((node_t *)rr_node);
			} else {
				assert(0);
			}

		} else if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_replace_soa(knot_zone_contents_t *contents,
                                   knot_changes_t *changes,
                                   knot_changeset_t *chset)
{
	dbg_xfrin("Replacing SOA record.\n");
	knot_node_t *node = knot_zone_contents_get_apex(contents);
	assert(node != NULL);

	assert(node != NULL);


	int ret = xfrin_replace_rrset_in_node(node, chset->soa_to, changes,
					      contents);
	if (ret == KNOT_EOK) {
		// remove the SOA from the changeset, so it will not be deleted
		// after successful apply
		chset->soa_to = NULL;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_changeset(knot_zone_contents_t *contents,
                                 knot_changes_t *changes,
                                 knot_changeset_t *chset)
{
	/*
	 * Applies one changeset to the zone. Checks if the changeset may be
	 * applied (i.e. the origin SOA (soa_from) has the same serial as
	 * SOA in the zone apex.
	 */

	dbg_xfrin("APPLYING CHANGESET: from serial %u to serial %u\n",
		  chset->serial_from, chset->serial_to);

	// check if serial matches
	/*! \todo Only if SOA is present? */
	const knot_rrset_t *soa = knot_node_rrset(contents->apex,
						  KNOT_RRTYPE_SOA);
	if (soa == NULL || knot_rdata_soa_serial(soa)
			   != chset->serial_from) {
		dbg_xfrin("SOA serials do not match!!\n");
		return KNOT_ERROR;
	}

	int ret = xfrin_apply_remove(contents, chset, changes);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = xfrin_apply_add(contents, chset, changes);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return xfrin_apply_replace_soa(contents, changes, chset);
}

/*----------------------------------------------------------------------------*/

/*! \brief Wrapper for BIRD lists. Storing: Node. */
typedef struct knot_node_ln {
	node_t n; /*!< List node. */
	knot_node_t *node; /*!< Actual usable data. */
} knot_node_ln_t;

static int add_node_to_list(knot_node_t *node, list_t *l)
{
	assert(node && l);
	knot_node_ln_t *data = malloc(sizeof(knot_node_ln_t));
	if (data == NULL) {
		return KNOT_ENOMEM;
	}
	data->node = node;
	add_head(l, (node_t *)data);
	return KNOT_EOK;
}

static int xfrin_mark_empty(knot_node_t **node_p, void *data)
{
	assert(node_p && *node_p);
	knot_node_t *node = *node_p;
	list_t *l = (list_t *)data;
	assert(data);
	if (node->rrset_count == 0 && node->children == 0 &&
	    !knot_node_is_empty(node)) {
		/*!
		 * Mark this node and all parent nodes that have 0 RRSets and
		 * no children for removal.
		 */
		int ret = add_node_to_list(node, l);
		if (ret != KNOT_EOK) {
			return ret;
		}
		knot_node_set_empty(node);
		if (node->parent) {
			if (node->parent->wildcard_child == node) {
				node->parent->wildcard_child = NULL;
			}
			node->parent->children--;
			// Recurse using the parent node
			return xfrin_mark_empty(&node->parent, data);
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_remove_empty_nodes(knot_zone_contents_t *z)
{
	dbg_xfrin("Removing empty nodes from zone.\n");

	list_t l;
	init_list(&l);
	// walk through the zone and select nodes to be removed
	int ret = knot_zone_tree_apply(z->nodes,
	                               xfrin_mark_empty, &l);
	if (ret != KNOT_EOK) {
		return ret;
	}

	node_t *n = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, l) {
		knot_node_ln_t *list_node = (knot_node_ln_t *)n;
		ret = knot_zone_contents_remove_node(z, list_node->node->owner);
		if (ret != KNOT_EOK) {
			return ret;
		}
		knot_node_free(&list_node->node);
		free(n);
	}

	init_list(&l);
	// Do the same with NSEC3 nodes.
	ret = knot_zone_tree_apply(z->nsec3_nodes,
	                           xfrin_mark_empty, &l);
	if (ret != KNOT_EOK) {
		return ret;
	}

	WALK_LIST_DELSAFE(n, nxt, l) {
		knot_node_ln_t *list_node = (knot_node_ln_t *)n;
		ret = knot_zone_contents_remove_nsec3_node(z, list_node->node->owner);
		if (ret != KNOT_EOK) {
			return ret;
		}
		knot_node_free(&list_node->node);
		free(n);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_prepare_zone_copy(knot_zone_contents_t *old_contents,
                            knot_zone_contents_t **new_contents)
{
	if (old_contents == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	dbg_xfrin("Preparing zone copy...\n");

	/*
	 * Ensure that the zone generation is set to 0.
	 */
	if (!knot_zone_contents_gen_is_old(old_contents)) {
		// this would mean that a previous update was not completed
		// abort
		dbg_zone("Trying to apply changesets to zone that is "
				  "being updated. Aborting.\n");
		return KNOT_EAGAIN;
	}

	/*
	 * Create a shallow copy of the zone, so that the structures may be
	 * updated.
	 *
	 * This will create new zone contents structures (normal nodes' tree,
	 * NSEC3 tree, hash table, domain name table), and copy all nodes.
	 * The data in the nodes (RRSets) remain the same though.
	 */
	knot_zone_contents_t *contents_copy = NULL;

	dbg_xfrin("Copying zone contents.\n");
	int ret = knot_zone_contents_shallow_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to create shallow copy of zone: %s\n",
			  knot_strerror(ret));
		return ret;
	}

	assert(knot_zone_contents_apex(contents_copy) != NULL);

	/*
	 * Fix references to new nodes. Some references in new nodes may point
	 * to old nodes. Hash table contains only old nodes.
	 */
	dbg_xfrin("Switching ptrs pointing to old nodes to the new nodes.\n");
	ret = xfrin_switch_nodes(contents_copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to switch pointers in nodes.\n");
		knot_zone_contents_free(&contents_copy);
		return ret;
	}
	assert(knot_zone_contents_apex(contents_copy) != NULL);

	*new_contents = contents_copy;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_finalize_updated_zone(knot_zone_contents_t *contents_copy,
                                knot_changes_t *changes)
{
	if (contents_copy == NULL || changes == NULL) {
		return KNOT_EINVAL;
	}

	/*
	 * Finalize the new zone contents:
	 * - delete empty nodes
	 * - parse NSEC3PARAM
	 * - do adjusting of nodes and RDATA
	 * - ???
	 * - PROFIT
	 */

	/*
	 * Select and remove empty nodes from zone trees. Do not free them right
	 * away as they may be referenced by some domain names.
	 */
	int ret = xfrin_remove_empty_nodes(contents_copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to remove empty nodes: %s\n",
			  knot_strerror(ret));
		return ret;
	}

	dbg_xfrin("Adjusting zone contents.\n");
	ret = knot_zone_contents_adjust(contents_copy, NULL, NULL, 1);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to finalize zone contents: %s\n",
			  knot_strerror(ret));
		return ret;
	}

	assert(knot_zone_contents_apex(contents_copy) != NULL);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_apply_changesets(knot_zone_t *zone,
                           knot_changesets_t *chsets,
                           knot_zone_contents_t **new_contents)
{
	if (zone == NULL || chsets == NULL || EMPTY_LIST(chsets->sets)
	    || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_contents_t *old_contents = knot_zone_get_contents(zone);
	if (!old_contents) {
		dbg_xfrin("Cannot apply changesets to empty zone.\n");
		return KNOT_EINVAL;
	}

	dbg_xfrin("Applying changesets to zone...\n");

	dbg_xfrin_verb("Creating shallow copy of the zone...\n");
	knot_zone_contents_t *contents_copy = NULL;
	int ret = xfrin_prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to prepare zone copy: %s\n",
			  knot_strerror(ret));
		return ret;
	}

	/*
	 * Apply the changesets.
	 */
	dbg_xfrin("Applying changesets.\n");
	dbg_xfrin_verb("Old contents apex: %p, new apex: %p\n",
		       old_contents->apex, contents_copy->apex);
	knot_changeset_t *set = NULL;
	WALK_LIST(set, chsets->sets) {
		ret = xfrin_apply_changeset(contents_copy, chsets->changes, set);
		if (ret != KNOT_EOK) {
			xfrin_rollback_update(old_contents,
					       &contents_copy, chsets->changes);
			dbg_xfrin("Failed to apply changesets to zone: "
				  "%s\n", knot_strerror(ret));
			return ret;
		}
	}
	assert(knot_zone_contents_apex(contents_copy) != NULL);

	/*!
	 * \todo Test failure of IXFR.
	 */

	dbg_xfrin_verb("Finalizing updated zone...\n");
	ret = xfrin_finalize_updated_zone(contents_copy, chsets->changes);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to finalize updated zone: %s\n",
			  knot_strerror(ret));
		xfrin_rollback_update(old_contents, &contents_copy, chsets->changes);
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_switch_zone(knot_zone_t *zone,
                      knot_zone_contents_t *new_contents,
                      int transfer_type)
{
	if (zone == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	dbg_xfrin("Switching zone contents.\n");
	dbg_xfrin_verb("Old contents: %p, apex: %p, new apex: %p\n",
		       zone->contents, (zone->contents)
		       ? zone->contents->apex : NULL, new_contents->apex);

	knot_zone_contents_t *old =
		knot_zone_switch_contents(zone, new_contents);

	dbg_xfrin_verb("Old contents: %p, apex: %p, new apex: %p\n",
		       old, (old) ? old->apex : NULL, new_contents->apex);

	// set generation to old, so that the flags may be used in next transfer
	// and we do not search for new nodes anymore
	knot_zone_contents_set_gen_old(new_contents);

	// wait for readers to finish
	dbg_xfrin_verb("Waiting for readers to finish...\n");
	synchronize_rcu();

	// destroy the old zone
	dbg_xfrin_verb("Freeing old zone: %p\n", old);

	if (transfer_type == XFR_TYPE_AIN) {
		knot_zone_contents_deep_free(&old);
	} else {
		assert(old != NULL);
		xfrin_zone_contents_free(&old);
	}

	return KNOT_EOK;
}
