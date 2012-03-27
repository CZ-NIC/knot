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

#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <urcu.h>

#include "nameserver/name-server.h"
#include "updates/xfr-in.h"

#include "util/error.h"
#include "libknot.h"
#include "util/debug.h"
#include "packet/packet.h"
#include "packet/response.h"
#include "packet/query.h"
#include "consts.h"
#include "updates/changesets.h"
#include "updates/ddns.h"
#include "tsig-op.h"

/*----------------------------------------------------------------------------*/

/*! \brief Maximum UDP payload with EDNS enabled. */
static const uint16_t MAX_UDP_PAYLOAD_EDNS = 4096;
/*! \brief Maximum UDP payload with EDNS disabled. */
static const uint16_t MAX_UDP_PAYLOAD      = 504; // 512 - 8B header
/*! \brief Maximum size of one AXFR response packet. */
static const uint16_t MAX_AXFR_PAYLOAD     = 65535;
/*! \brief Supported EDNS version. */
static const uint8_t  EDNS_VERSION         = 0;
/*! \brief Determines whether EDNS is enabled. */
static const int      EDNS_ENABLED         = 1;

/*! \brief TTL of a CNAME synthetized from a DNAME. */
static const uint32_t SYNTH_CNAME_TTL      = 0;

/*! \brief Determines whether DNSSEC is enabled. */
static const int      DNSSEC_ENABLED       = 1;

/*! \brief Determines whether NSID is enabled. */
static const int      NSID_ENABLED         = 1;

/*! \brief Length of NSID option data. */
static const uint16_t NSID_LENGTH          = 6;
/*! \brief NSID option data. */
static const uint8_t  NSID_DATA[6] = {0x46, 0x6f, 0x6f, 0x42, 0x61, 0x72};

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
static const knot_zone_t *ns_get_zone_for_qname(knot_zonedb_t *zdb,
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
		/*! \todo Optimize, do not deep copy dname. */
		knot_dname_t *name = knot_dname_left_chop(qname);
		zone = knot_zonedb_find_zone_for_name(zdb, name);
		/* Directly discard. */
		knot_dname_free(&name);
		/* If zone does not exist, search for its parent zone,
		   this will later result to NODATA answer. */
		if (zone == NULL) {
			zone = knot_zonedb_find_zone_for_name(zdb, qname);
		}
	} else {
		zone = knot_zonedb_find_zone_for_name(zdb, qname);
	}

	return zone;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Synthetizes RRSet from a wildcard RRSet using the given QNAME.
 *
 * The synthetized RRSet is identical to the wildcard RRSets, except that the
 * owner name is replaced by \a qname.
 *
 * \param wildcard_rrset Wildcard RRSet to synthetize from.
 * \param qname Domain name to be used as the owner of the synthetized RRset.
 *
 * \return The synthetized RRSet (this is a newly created RRSet, remember to
 *         free it).
 */
static knot_rrset_t *ns_synth_from_wildcard(
	const knot_rrset_t *wildcard_rrset, const knot_dname_t *qname)
{
	dbg_ns("Synthetizing RRSet from wildcard...\n");

	knot_dname_t *owner = knot_dname_deep_copy(qname);
//	printf("Copied owner ptr: %p\n", owner);

	knot_rrset_t *synth_rrset = knot_rrset_new(
			owner, knot_rrset_type(wildcard_rrset),
			knot_rrset_class(wildcard_rrset),
			knot_rrset_ttl(wildcard_rrset));

	/* Release owner, as it's retained in rrset. */
	knot_dname_release(owner);

	if (synth_rrset == NULL) {
		return NULL;
	}

	dbg_ns("Created RRSet header:\n");
	knot_rrset_dump(synth_rrset, 1);

	// copy all RDATA
	const knot_rdata_t *rdata = knot_rrset_rdata(wildcard_rrset);
	while (rdata != NULL) {
		// we could use the RDATA from the wildcard rrset
		// but there is no way to distinguish it when deleting
		// temporary RRSets
		knot_rdata_t *rdata_copy = knot_rdata_deep_copy(rdata,
		                               knot_rrset_type(synth_rrset), 0);
		if (rdata_copy == NULL) {
			knot_rrset_deep_free(&synth_rrset, 1, 1, 0);
			return NULL;
		}

		dbg_ns("Copied RDATA:\n");
		knot_rdata_dump(rdata_copy,
		                  knot_rrset_type(synth_rrset), 1);

		knot_rrset_add_rdata(synth_rrset, rdata_copy);
		rdata = knot_rrset_rdata_next(wildcard_rrset, rdata);
	}

//	printf("Synthetized RRSet pointer: %p\n", synth_rrset);
	return synth_rrset;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if the given RRSet is a wildcard RRSet and replaces it with
 *        a synthetized RRSet if required.
 *
 * \param name Domain name to be used as the owner of the possibly synthetized
 *             RRSet
 * \param resp Response to which the synthetized RRSet should be stored (as a
 *             temporary RRSet).
 * \param rrset RRSet to check (and possibly replace).
 */
static void ns_check_wildcard(const knot_dname_t *name, knot_packet_t *resp,
                              knot_rrset_t **rrset)
{
	assert(name != NULL);
	assert(resp != NULL);
	assert(rrset != NULL);
	assert(*rrset != NULL);

	if (knot_dname_is_wildcard((*rrset)->owner)) {
		knot_rrset_t *synth_rrset =
			ns_synth_from_wildcard(*rrset, name);
		dbg_ns("Synthetized RRSet:\n");
		knot_rrset_dump(synth_rrset, 1);
		knot_packet_add_tmp_rrset(resp, synth_rrset);
		*rrset = synth_rrset;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds signatures (RRSIGs) for the given RRSet to the response.
 *
 * This function first checks if DNSSEC is enabled and if it was requested in
 * the response (DO bit set). If not, it does nothing and returns 0. If yes,
 * it retrieves RRSIGs stored in the RRSet, deals with possible wildcard owner
 * and adds the RRSIGs to response using the given function (that determines
 * to which section of the response they will be added).
 *
 * \param rrset RRSet to get the RRSIGs from.
 * \param resp Response where to add the RRSIGs.
 * \param name Actual name to be used as owner in case of wildcard RRSet.
 * \param add_rrset_to_resp Function for adding the RRSIG RRset to the response.
 * \param tc Set to 1 if omitting the RRSIG RRSet should result in setting the
 *           TC bit in the response.
 *
 * \return KNOT_EOK
 * \return KNOT_ENOMEM
 * \return KNOT_ESPACE
 */
static int ns_add_rrsigs(knot_rrset_t *rrset, knot_packet_t *resp,
                         const knot_dname_t *name,
                         int (*add_rrset_to_resp)(knot_packet_t *,
                                                   knot_rrset_t *,
                                                   int, int, int, int),
                         int tc)
{
	knot_rrset_t *rrsigs;

	dbg_ns("Adding RRSIGs for RRSet, type: %s.\n",
		 knot_rrtype_to_string(knot_rrset_type(rrset)));

	assert(resp != NULL);
	assert(add_rrset_to_resp != NULL);

	dbg_ns("DNSSEC requested: %d\n",
	         knot_query_dnssec_requested(knot_packet_query(resp)));
	dbg_ns("RRSIGS: %p\n", knot_rrset_rrsigs(rrset));

	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))
	    && (rrsigs = knot_rrset_get_rrsigs(rrset)) != NULL) {
		if (name != NULL) {
			ns_check_wildcard(name, resp, &rrsigs);
		}
		return add_rrset_to_resp(resp, rrsigs, tc, 0, 0, 1);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Resolves CNAME chain starting in \a node, stores all the CNAMEs in the
 *        response and updates \a node and \a qname to the last node in the
 *        chain.
 *
 * \param node Node (possibly) containing a CNAME RR.
 * \param qname Searched name. Will be updated to the canonical name.
 * \param resp Response where to add the CNAME RRs.
 * \param add_rrset_to_resp Function for adding the CNAME RRs to the response.
 * \param tc Set to 1 if omitting the RRSIG RRSet should result in setting the
 *           TC bit in the response.
 */
static void ns_follow_cname(const knot_node_t **node,
                            const knot_dname_t **qname,
                            knot_packet_t *resp,
                            int (*add_rrset_to_resp)(knot_packet_t *,
                                                     knot_rrset_t *,
                                                     int, int, int, int),
                            int tc)
{
	dbg_ns("Resolving CNAME chain...\n");
	knot_rrset_t *cname_rrset;

	while (*node != NULL
	       && (cname_rrset = knot_node_get_rrset(*node, KNOT_RRTYPE_CNAME))
	          != NULL) {
		/* put the CNAME record to answer, but replace the possible
		   wildcard name with qname */

		assert(cname_rrset != NULL);
		
		dbg_ns("CNAME RRSet: %p, owner: %p\n", cname_rrset,
			      cname_rrset->owner);

		knot_rrset_t *rrset = cname_rrset;

		// ignoring other than the first record
		if (knot_dname_is_wildcard(knot_node_owner(*node))) {
			/* if wildcard node, we must copy the RRSet and
			   replace its owner */
			rrset = ns_synth_from_wildcard(cname_rrset, *qname);
			knot_packet_add_tmp_rrset(resp, rrset);
			add_rrset_to_resp(resp, rrset, tc, 0, 0, 1);
			ns_add_rrsigs(cname_rrset, resp, *qname, 
			              add_rrset_to_resp, tc);
		} else {
			add_rrset_to_resp(resp, rrset, tc, 0, 0, 1);
			ns_add_rrsigs(rrset, resp, *qname, add_rrset_to_resp, 
			              tc);
		}
		
		dbg_ns("Using RRSet: %p, owner: %p\n", rrset, rrset->owner);
		
dbg_ns_exec(
		char *name = knot_dname_to_str(knot_rrset_owner(rrset));
		dbg_ns("CNAME record for owner %s put to response.\n", name);
		free(name);
);

		// get the name from the CNAME RDATA
		const knot_dname_t *cname = knot_rdata_cname_name(
				knot_rrset_rdata(cname_rrset));
		dbg_ns("CNAME name from RDATA: %p\n", cname);
		// change the node to the node of that name
		*node = knot_dname_node(cname);
		dbg_ns("This name's node: %p\n", *node);
//		// it is not an old node and if yes, skip it
//		if (knot_node_is_old(*node)) {
//			*node = knot_node_new_node(*node);
//		}

		// save the new name which should be used for replacing wildcard
		*qname = cname;
	};
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Retrieves RRSet(s) of given type from the given node and adds them to
 *        the response's Answer section.
 *
 * \param node Node where to take the RRSet from.
 * \param name Actual searched name (used in case of wildcard RRSet(s)).
 * \param type Type of the RRSet(s). If set to KNOT_RRTYPE_ANY, all RRSets
 *             from the node will be added to the answer.
 * \param resp Response where to add the RRSets.
 *
 * \return Number of RRSets added.
 */
static int ns_put_answer(const knot_node_t *node, const knot_dname_t *name,
                          uint16_t type, knot_packet_t *resp)
{
	int added = 0;
dbg_ns_exec(
	char *name_str = knot_dname_to_str(node->owner);
	dbg_ns("Putting answers from node %s.\n", name_str);
	free(name_str);
);

	switch (type) {
	case KNOT_RRTYPE_ANY: {
		dbg_ns("Returning all RRTYPES.\n");
		knot_rrset_t **rrsets = knot_node_get_rrsets(node);
		if (rrsets == NULL) {
			break;
		}
		int i = 0;
		int ret = 0;
		knot_rrset_t *rrset;
		while (i < knot_node_rrset_count(node)) {
			assert(rrsets[i] != NULL);
			rrset = rrsets[i];

			dbg_ns("  Type: %s\n",
			     knot_rrtype_to_string(knot_rrset_type(rrset)));

			ns_check_wildcard(name, resp, &rrset);
			ret = knot_response_add_rrset_answer(resp, rrset, 1,
			                                     0, 0, 1);
			if (ret >= 0 && (added += 1)
			    && (ret = ns_add_rrsigs(rrset, resp, name,
			           knot_response_add_rrset_answer, 1))
			            >=0 ) {
				added += 1;
			} else {
				free(rrsets);
				rrsets = NULL;
				break;
			}

			++i;
		}
		if (rrsets != NULL) {
			free(rrsets);
		}
		break;
	}
	case KNOT_RRTYPE_RRSIG: {
		dbg_ns("Returning all RRSIGs.\n");
		knot_rrset_t **rrsets = knot_node_get_rrsets(node);
		if (rrsets == NULL) {
			break;
		}
		int i = 0;
		int ret = 0;
		knot_rrset_t *rrset;
		while (i < knot_node_rrset_count(node)) {
			assert(rrsets[i] != NULL);
			rrset = knot_rrset_get_rrsigs(rrsets[i]);

			if (rrset == NULL) {
				++i;
				continue;
			}

			ns_check_wildcard(name, resp, &rrset);
			ret = knot_response_add_rrset_answer(resp, rrset, 1,
			                                     0, 0, 1);

			if (ret < 0) {
				break;
			}

			added += 1;
			++i;
		}
		free(rrsets);
		break;
	}
	default: {
		int ret = 0;
		knot_rrset_t *rrset = knot_node_get_rrset(node, type);
		knot_rrset_t *rrset2 = rrset;
		if (rrset != NULL) {
			dbg_ns("Found RRSet of type %s\n",
				 knot_rrtype_to_string(type));
			ns_check_wildcard(name, resp, &rrset2);
			ret = knot_response_add_rrset_answer(resp, rrset2, 1,
			                                     0, 0, 1);
			if (ret >= 0 && (added += 1)
			    && (ret = ns_add_rrsigs(rrset, resp, name,
			           knot_response_add_rrset_answer, 1)) > 0) {
				added += 1;
			}
		}
	    }
	}

	knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);
	return added;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds RRSets to Additional section of the response.
 *
 * This function uses knot_rdata_get_name() to get the domain name from the
 * RDATA of the RRSet according to its type. It also does not search for the
 * retrieved domain name, but just uses its node field. Thus to work correctly,
 * the zone where the RRSet is from should be adjusted using
 * knot_zone_adjust_dnames().
 *
 * A and AAAA RRSets (and possible CNAMEs) for the found domain names are added.
 *
 * \warning Use this function only with types containing some domain name,
 *          otherwise it will crash (or behave strangely).
 *
 * \param resp Response where to add the Additional data.
 * \param rrset RRSet to get the Additional data for.
 */
static void ns_put_additional_for_rrset(knot_packet_t *resp,
                                        const knot_rrset_t *rrset)
{
	const knot_node_t *node = NULL;
	const knot_rdata_t *rdata = NULL;
	const knot_dname_t *dname = NULL;

	// for all RRs in the RRset
	rdata = knot_rrset_rdata(rrset);
	while (rdata != NULL) {
		dbg_ns("Getting name from RDATA, type %s..\n",
			 knot_rrtype_to_string(knot_rrset_type(rrset)));
		dname = knot_rdata_get_name(rdata, knot_rrset_type(rrset));
		assert(dname != NULL);
		node = knot_dname_node(dname);
		
//		dbg_ns_detail("Node saved in RDATA dname: %p\n", node);
//		char *name = knot_dname_to_str(dname);
//		dbg_ns_detail("Owner of the node: %p, dname: %p (%s)\n",
//		              node->owner, dname, name);
//		free(name);
//		knot_node_dump((knot_node_t *)node, (void *)1);

		if (node != NULL && node->owner != dname) {
			// the stored node should be the closest encloser
			assert(knot_dname_is_subdomain(dname, node->owner));
			// try the wildcard child, if any
			node = knot_node_wildcard_child(node);
		}

		knot_rrset_t *rrset_add;

		if (node != NULL) {
dbg_ns_exec(
			char *name = knot_dname_to_str(node->owner);
			dbg_ns("Putting additional from node %s\n", name);
			free(name);
);
			dbg_ns("Checking CNAMEs...\n");
			if (knot_node_rrset(node, KNOT_RRTYPE_CNAME)
			    != NULL) {
				dbg_ns("Found CNAME in node, following...\n");
				const knot_dname_t *dname
						= knot_node_owner(node);
				ns_follow_cname(&node, &dname, resp,
				    knot_response_add_rrset_additional, 0);
			}

			// A RRSet
			dbg_ns("A RRSets...\n");
			rrset_add = knot_node_get_rrset(node, KNOT_RRTYPE_A);
			if (rrset_add != NULL) {
				dbg_ns("Found A RRsets.\n");
				knot_rrset_t *rrset_add2 = rrset_add;
				ns_check_wildcard(dname, resp, &rrset_add2);
				knot_response_add_rrset_additional(
					resp, rrset_add2, 0, 1, 0, 1);
				ns_add_rrsigs(rrset_add, resp, dname,
				      knot_response_add_rrset_additional, 0);
			}

			// AAAA RRSet
			dbg_ns("AAAA RRSets...\n");
			rrset_add = knot_node_get_rrset(node, KNOT_RRTYPE_AAAA);
			if (rrset_add != NULL) {
				dbg_ns("Found AAAA RRsets.\n");
				knot_rrset_t *rrset_add2 = rrset_add;
				ns_check_wildcard(dname, resp, &rrset_add2);
				knot_response_add_rrset_additional(
					resp, rrset_add2, 0, 1, 0, 1);
				ns_add_rrsigs(rrset_add, resp, dname,
				      knot_response_add_rrset_additional, 0);
			}
		}

		assert(rrset != NULL);
		assert(rdata != NULL);
		rdata = knot_rrset_rdata_next(rrset, rdata);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks whether the given type requires additional processing.
 *
 * Only MX, NS and SRV types require additional processing.
 *
 * \param qtype Type to check.
 *
 * \retval <> 0 if additional processing is needed for \a qtype.
 * \retval 0 otherwise.
 */
static int ns_additional_needed(uint16_t qtype)
{
	return (qtype == KNOT_RRTYPE_MX ||
	        qtype == KNOT_RRTYPE_NS ||
		qtype == KNOT_RRTYPE_SRV);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds whatever Additional RRSets are required for the response.
 *
 * For each RRSet in Answer and Authority sections this function checks if
 * additional processing is needed and if yes, it puts any Additional RRSets
 * available to the Additional section of the response.
 *
 * \param resp Response to process.
 */
static void ns_put_additional(knot_packet_t *resp)
{
	dbg_ns("ADDITIONAL SECTION PROCESSING\n");

	const knot_rrset_t *rrset = NULL;

	for (int i = 0; i < knot_packet_answer_rrset_count(resp); ++i) {
		rrset = knot_packet_answer_rrset(resp, i);
		assert(rrset != NULL);
		if (ns_additional_needed(knot_rrset_type(rrset))) {
			ns_put_additional_for_rrset(resp, rrset);
		}
	}

	for (int i = 0; i < knot_packet_authority_rrset_count(resp); ++i) {
		rrset = knot_packet_authority_rrset(resp, i);
		if (ns_additional_needed(knot_rrset_type(rrset))) {
			ns_put_additional_for_rrset(resp, rrset);
		}
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts authority NS RRSet to the Auhority section of the response.
 *
 * \param zone Zone to take the authority NS RRSet from.
 * \param resp Response where to add the RRSet.
 */
static void ns_put_authority_ns(const knot_zone_contents_t *zone,
                                knot_packet_t *resp)
{
	knot_rrset_t *ns_rrset = knot_node_get_rrset(
			knot_zone_contents_apex(zone), KNOT_RRTYPE_NS);

	if (ns_rrset != NULL) {
		knot_response_add_rrset_authority(resp, ns_rrset, 0, 1, 0, 1);
		ns_add_rrsigs(ns_rrset, resp, knot_node_owner(
		              knot_zone_contents_apex(zone)),
	                      knot_response_add_rrset_authority, 1);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts SOA RRSet to the Auhority section of the response.
 *
 * \param zone Zone to take the SOA RRSet from.
 * \param resp Response where to add the RRSet.
 */
static int ns_put_authority_soa(const knot_zone_contents_t *zone,
                                 knot_packet_t *resp)
{
	int ret;

	knot_rrset_t *soa_rrset = knot_node_get_rrset(
			knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	assert(soa_rrset != NULL);

	// if SOA's TTL is larger than MINIMUM, copy the RRSet and set
	// MINIMUM as TTL
	uint32_t min = knot_rdata_soa_minimum(knot_rrset_rdata(soa_rrset));
	if (min < knot_rrset_ttl(soa_rrset)) {
		knot_rrset_t *soa_copy = NULL;
		ret = knot_rrset_deep_copy(soa_rrset, &soa_copy);

		if (ret != KNOT_EOK) {
			return ret;
		}

		CHECK_ALLOC_LOG(soa_copy, KNOT_ENOMEM);

		knot_rrset_set_ttl(soa_copy, min);
		soa_rrset = soa_copy;
		/* Need to add it as temporary, so it get's freed. */
		knot_packet_add_tmp_rrset(resp, soa_copy);
	}

	assert(soa_rrset != NULL);

	ret = knot_response_add_rrset_authority(resp, soa_rrset, 0, 0, 0, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = ns_add_rrsigs(soa_rrset, resp,
			    knot_node_owner(knot_zone_contents_apex(zone)),
			    knot_response_add_rrset_authority, 1);

	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates a 'next closer name' to the given domain name.
 *
 * For definition of 'next closer name', see RFC5155, Page 6.
 *
 * \param closest_encloser Closest encloser of \a name.
 * \param name Domain name to create the 'next closer' name to.
 *
 * \return 'Next closer name' to the given domain name or NULL if an error
 *         occured.
 */
static knot_dname_t *ns_next_closer(const knot_dname_t *closest_encloser,
                                      const knot_dname_t *name)
{
	int ce_labels = knot_dname_label_count(closest_encloser);
	int qname_labels = knot_dname_label_count(name);

	assert(ce_labels < qname_labels);

	// the common labels should match
	assert(knot_dname_matched_labels(closest_encloser, name)
	       == ce_labels);

	// chop some labels from the qname
	knot_dname_t *next_closer = knot_dname_deep_copy(name);
	if (next_closer == NULL) {
		return NULL;
	}

	for (int i = 0; i < (qname_labels - ce_labels - 1); ++i) {
		knot_dname_left_chop_no_copy(next_closer);
	}

	return next_closer;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds NSEC3 RRSet (together with corresponding RRSIGs) from the given
 *        node into the response.
 *
 * \param node Node to get the NSEC3 RRSet from.
 * \param resp Response where to add the RRSets.
 */
static void ns_put_nsec3_from_node(const knot_node_t *node,
                                   knot_packet_t *resp)
{
	assert(DNSSEC_ENABLED
	       && knot_query_dnssec_requested(knot_packet_query(resp)));

	 knot_rrset_t *rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NSEC3);
	assert(rrset != NULL);

	int res = knot_response_add_rrset_authority(resp, rrset, 1, 1, 0, 1);
	// add RRSIG for the RRSet
	if (res == 0 && (rrset = knot_rrset_get_rrsigs(rrset)) != NULL) {
		knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Finds and adds NSEC3 covering the given domain name (and their
 *        associated RRSIGs) to the response.
 *
 * \param zone Zone used for answering.
 * \param name Domain name to cover.
 * \param resp Response where to add the RRSets.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL if a runtime collision occured. The server should
 *                         respond with SERVFAIL in such case.
 */
static int ns_put_covering_nsec3(const knot_zone_contents_t *zone,
                                 const knot_dname_t *name,
                                 knot_packet_t *resp)
{
	const knot_node_t *prev, *node;
	/*! \todo Check version. */
	int match = knot_zone_contents_find_nsec3_for_name(zone, name,
	                                                     &node, &prev);
	assert(match >= 0);
//	node = knot_node_current(node);
//	prev = knot_node_current(prev);

	if (match == KNOT_ZONE_NAME_FOUND){
		// run-time collision => SERVFAIL
		return KNOT_EOK;
	}
	
//	// check if the prev node is not old and if yes, take the new one
//	if (knot_node_is_old(prev)) {
//		prev = knot_node_new_node(prev);
//		assert(prev != NULL);
//	}

dbg_ns_exec(
	char *name = knot_dname_to_str(prev->owner);
	dbg_ns("Covering NSEC3 node: %s\n", name);
	free(name);
);

	ns_put_nsec3_from_node(prev, resp);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds NSEC3s comprising the 'closest encloser proof' for the given
 *        (non-existent) domain name (and their associated RRSIGs) to the
 *        response.
 *
 * For definition of 'closest encloser proof', see RFC5155, section 7.2.1,
 * Page 18.
 *
 * \note This function does not check if DNSSEC is enabled, nor if it is
 *       requested by the query.
 *
 * \param zone Zone used for answering.
 * \param closest_encloser Closest encloser of \a qname in the zone.
 * \param qname Searched (non-existent) name.
 * \param resp Response where to add the NSEC3s.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec3_closest_encloser_proof(
                                         const knot_zone_contents_t *zone,
                                         const knot_node_t **closest_encloser,
                                         const knot_dname_t *qname,
                                         knot_packet_t *resp)
{
	assert(zone != NULL);
	assert(closest_encloser != NULL);
	assert(*closest_encloser != NULL);
	assert(qname != NULL);
	assert(resp != NULL);

	if (knot_zone_contents_nsec3params(zone) == NULL) {
dbg_ns_exec(
		char *name = knot_dname_to_str(knot_node_owner(
				knot_zone_contents_apex(zone)));
		dbg_ns("No NSEC3PARAM found in zone %s.\n", name);
		free(name);
);
		return KNOT_EOK;
	}

dbg_ns_exec(
	char *name = knot_dname_to_str(knot_node_owner(*closest_encloser));
	dbg_ns("Closest encloser: %s\n", name);
	free(name);
);

	/*
	 * 1) NSEC3 that matches closest provable encloser.
	 */
	const knot_node_t *nsec3_node = NULL;
	const knot_dname_t *next_closer = NULL;
	while ((nsec3_node = knot_node_nsec3_node((*closest_encloser)))
	       == NULL) {
		next_closer = knot_node_owner((*closest_encloser));
		*closest_encloser = knot_node_parent(*closest_encloser);
		if (*closest_encloser == NULL) {
			// there are no NSEC3s to add
			return KNOT_EOK;
		}
	}

	assert(nsec3_node != NULL);

dbg_ns_exec(
	char *name = knot_dname_to_str(nsec3_node->owner);
	dbg_ns("NSEC3 node: %s\n", name);
	free(name);
	name = knot_dname_to_str((*closest_encloser)->owner);
	dbg_ns("Closest provable encloser: %s\n", name);
	free(name);
	if (next_closer != NULL) {
		name = knot_dname_to_str(next_closer);
		dbg_ns("Next closer name: %s\n", name);
		free(name);
	} else {
		dbg_ns("Next closer name: none\n");
	}
);

	ns_put_nsec3_from_node(nsec3_node, resp);

	/*
	 * 2) NSEC3 that covers the "next closer" name.
	 */
	int ret = 0;
	if (next_closer == NULL) {
		// create the "next closer" name by appending from qname
		next_closer = ns_next_closer(
			knot_node_owner(*closest_encloser), qname);

		if (next_closer == NULL) {
			return NS_ERR_SERVFAIL;
		}
dbg_ns_exec(
		char *name = knot_dname_to_str(next_closer);
		dbg_ns("Next closer name: %s\n", name);
		free(name);
);
		ret = ns_put_covering_nsec3(zone, next_closer, resp);

		// the cast is ugly, but no better way around it
		knot_dname_release((knot_dname_t *)next_closer);
	} else {
		ret = ns_put_covering_nsec3(zone, next_closer, resp);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates a name of a wildcard child of \a name.
 *
 * \param name Domain name to get the wildcard child name of.
 *
 * \return Wildcard child name or NULL if an error occured.
 */
static knot_dname_t *ns_wildcard_child_name(const knot_dname_t *name)
{
	assert(name != NULL);

	knot_dname_t *wildcard = knot_dname_new_from_str("*", 1, NULL);
	if (wildcard == NULL) {
		return NULL;
	}

	if (knot_dname_cat(wildcard, name) == NULL) {
		/* Directly discard dname. */
		knot_dname_free(&wildcard);
		return NULL;
	}

dbg_ns_exec(
	char *name = knot_dname_to_str(wildcard);
	dbg_ns("Wildcard: %s\n", name);
	free(name);
);
	return wildcard;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSEC3s covering the non-existent wildcard child of a node
 *        (and their associated RRSIGs) into the response.
 *
 * \note This function does not check if DNSSEC is enabled, nor if it is
 *       requested by the query.
 *
 * \param zone Zone used for answering.
 * \param node Node whose non-existent wildcard child should be covered.
 * \param resp Response where to add the NSEC3s.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec3_no_wildcard_child(const knot_zone_contents_t *zone,
                                          const knot_node_t *node,
                                          knot_packet_t *resp)
{
	assert(node != NULL);
	assert(resp != NULL);
	assert(node->owner != NULL);

	int ret = 0;
	knot_dname_t *wildcard = ns_wildcard_child_name(node->owner);
	if (wildcard == NULL) {
		ret = NS_ERR_SERVFAIL;
	} else {
		ret = ns_put_covering_nsec3(zone, wildcard, resp);

		/* Directly discard wildcard. */
		knot_dname_free(&wildcard);
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSECs or NSEC3s for NODATA error (and their associated RRSIGs)
 *        to the response.
 *
 * \note This function first checks if DNSSEC is enabled and requested by the
 *       query.
 * \note Note that for each zone there are either NSEC or NSEC3 records used.
 *
 * \param node Node which generated the NODATA response (i.e. not containing
 *             RRSets of the requested type).
 * \param resp Response where to add the NSECs or NSEC3s.
 */
static void ns_put_nsec_nsec3_nodata(const knot_node_t *node,
                                     knot_packet_t *resp)
{
	if (!DNSSEC_ENABLED ||
	    !knot_query_dnssec_requested(knot_packet_query(resp))) {
		return;
	}

	knot_node_t *nsec3_node = knot_node_get_nsec3_node(node);
	knot_rrset_t *rrset = NULL;
	if ((rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NSEC)) != NULL
	    || (nsec3_node != NULL && (rrset =
	         knot_node_get_rrset(nsec3_node, KNOT_RRTYPE_NSEC3)) != NULL)) {
		knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);
		// add RRSIG for the RRSet
		if ((rrset = knot_rrset_get_rrsigs(rrset)) != NULL) {
			knot_response_add_rrset_authority(resp, rrset, 1,
			                                  0, 0, 1);
		}
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSECs for NXDOMAIN error to the response.
 *
 * \note This function does not check if DNSSEC is enabled, nor if it is
 *       requested by the query.
 *
 * \param qname QNAME which generated the NXDOMAIN error (i.e. not found in the
 *              zone).
 * \param zone Zone used for answering.
 * \param previous Previous node to \a qname in the zone. May also be NULL. In
 *                 such case the function finds the previous node in the zone.
 * \param closest_encloser Closest encloser of \a qname. Must not be NULL.
 * \param resp Response where to put the NSECs.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec_nxdomain(const knot_dname_t *qname,
                                const knot_zone_contents_t *zone,
                                const knot_node_t *previous,
                                const knot_node_t *closest_encloser,
                                knot_packet_t *resp)
{
	knot_rrset_t *rrset = NULL;

	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {
		/*! \todo Check version. */
		previous = knot_zone_contents_find_previous(zone, qname);
		assert(previous != NULL);
		
		while (!knot_node_is_auth(previous)) {
			previous = knot_node_previous(previous);
		}
	}
	
	char *name = knot_dname_to_str(previous->owner);
	dbg_ns("Previous node: %s\n", name);
	free(name);

	// 1) NSEC proving that there is no node with the searched name
	rrset = knot_node_get_rrset(previous, KNOT_RRTYPE_NSEC);
	if (rrset == NULL) {
		// no NSEC records
		//return NS_ERR_SERVFAIL;
		return KNOT_EOK;
		
	}

	knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);
	rrset = knot_rrset_get_rrsigs(rrset);
	assert(rrset != NULL);
	knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);

	// 2) NSEC proving that there is no wildcard covering the name
	// this is only different from 1) if the wildcard would be
	// before 'previous' in canonical order, i.e. we can
	// search for previous until we find name lesser than wildcard
	assert(closest_encloser != NULL);

	knot_dname_t *wildcard =
		ns_wildcard_child_name(closest_encloser->owner);
	if (wildcard == NULL) {
		return NS_ERR_SERVFAIL;
	}

	const knot_node_t *prev_new = previous;

	while (knot_dname_compare(knot_node_owner(prev_new),
				    wildcard) > 0) {
dbg_ns_exec(
		char *name = knot_dname_to_str(knot_node_owner(prev_new));
		dbg_ns("Previous node: %s\n", name);
		free(name);
);
		assert(prev_new != knot_zone_contents_apex(zone));
		prev_new = knot_node_previous(prev_new);
	}
	assert(knot_dname_compare(knot_node_owner(prev_new),
	                            wildcard) < 0);

dbg_ns_exec(
	char *name = knot_dname_to_str(knot_node_owner(prev_new));
	dbg_ns("Previous node: %s\n", name);
	free(name);
);

	/* Directly discard dname. */
	knot_dname_free(&wildcard);

	if (prev_new != previous) {
		rrset = knot_node_get_rrset(prev_new, KNOT_RRTYPE_NSEC);
		assert(rrset != NULL);
		knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);
		rrset = knot_rrset_get_rrsigs(rrset);
		assert(rrset != NULL);
		knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSEC3s for NXDOMAIN error to the response.
 *
 * \note This function does not check if DNSSEC is enabled, nor if it is
 *       requested by the query.
 *
 * \param zone Zone used for answering.
 * \param closest_encloser Closest encloser of \a qname.
 * \param qname Domain name which generated the NXDOMAIN error (i.e. not found
 *              in the zone.
 * \param resp Response where to put the NSEC3s.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec3_nxdomain(const knot_zone_contents_t *zone,
                                 const knot_node_t *closest_encloser,
                                 const knot_dname_t *qname,
                                 knot_packet_t *resp)
{
	// 1) Closest encloser proof
	dbg_ns("Putting closest encloser proof.\n");
	int ret = ns_put_nsec3_closest_encloser_proof(zone, &closest_encloser,
	                                              qname, resp);
	// 2) NSEC3 covering non-existent wildcard
	if (ret == KNOT_EOK && closest_encloser != NULL) {
		dbg_ns("Putting NSEC3 for no wildcard child of closest "
		              "encloser.\n");
		ret = ns_put_nsec3_no_wildcard_child(zone, closest_encloser,
		                                     resp);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSECs or NSEC3s for the NXDOMAIN error to the response.
 *
 * \note This function first checks if DNSSEC is enabled and requested by the
 *       query.
 * \note Note that for each zone there are either NSEC or NSEC3 records used.
 *
 * \param zone Zone used for answering.
 * \param previous Previous node to \a qname in the zone. May also be NULL. In
 *                 such case the function finds the previous node in the zone.
 * \param closest_encloser Closest encloser of \a qname. Must not be NULL.
 * \param qname QNAME which generated the NXDOMAIN error (i.e. not found in the
 *              zone).
 * \param resp Response where to put the NSECs.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec_nsec3_nxdomain(const knot_zone_contents_t *zone,
                                      const knot_node_t *previous,
                                      const knot_node_t *closest_encloser,
                                      const knot_dname_t *qname,
                                      knot_packet_t *resp)
{
	int ret = 0;
	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))) {
		if (knot_zone_contents_nsec3_enabled(zone)) {
			ret = ns_put_nsec3_nxdomain(zone, closest_encloser,
			                            qname, resp);
		} else {
			ret = ns_put_nsec_nxdomain(qname, zone, previous,
		                                   closest_encloser, resp);
		}
	}
	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSEC3s for wildcard answer into the response.
 *
 * \note This function does not check if DNSSEC is enabled, nor if it is
 *       requested by the query.
 *
 * \param zone Zone used for answering.
 * \param closest_encloser Closest encloser of \a qname in the zone. In this
 *                         case it is the parent of the source of synthesis.
 * \param qname Domain name covered by the wildcard used for answering the
 *              query.
 * \param resp Response to put the NSEC3s into.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec3_wildcard(const knot_zone_contents_t *zone,
                                 const knot_node_t *closest_encloser,
                                 const knot_dname_t *qname,
                                 knot_packet_t *resp)
{
	assert(closest_encloser != NULL);
	assert(qname != NULL);
	assert(resp != NULL);
	assert(DNSSEC_ENABLED
	       && knot_query_dnssec_requested(knot_packet_query(resp)));

	if (!knot_zone_contents_nsec3_enabled(zone)) {
		return KNOT_EOK;
	}
	
	/*
	 * NSEC3 that covers the "next closer" name.
	 */
	// create the "next closer" name by appending from qname
	dbg_ns("Finding next closer name for wildcard NSEC3.\n");
	knot_dname_t *next_closer =
		ns_next_closer(closest_encloser->owner, qname);

	if (next_closer == NULL) {
		return NS_ERR_SERVFAIL;
	}
dbg_ns_exec(
	char *name = knot_dname_to_str(next_closer);
	dbg_ns("Next closer name: %s\n", name);
	free(name);
);
	int ret = ns_put_covering_nsec3(zone, next_closer, resp);


	/* Duplicate from ns_next_close(), safe to discard. */
	knot_dname_release(next_closer);

	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSECs for wildcard answer into the response.
 *
 * \note This function does not check if DNSSEC is enabled, nor if it is
 *       requested by the query.
 *
 * \param zone Zone used for answering.
 * \param qname Domain name covered by the wildcard used for answering the
 *              query.
 * \param previous Previous node of \a qname in canonical order.
 * \param resp Response to put the NSEC3s into.
 */
static void ns_put_nsec_wildcard(const knot_zone_contents_t *zone,
                                 const knot_dname_t *qname,
                                 const knot_node_t *previous,
                                 knot_packet_t *resp)
{
	assert(DNSSEC_ENABLED
	       && knot_query_dnssec_requested(knot_packet_query(resp)));

	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {		
		previous = knot_zone_contents_find_previous(zone, qname);
		assert(previous != NULL);
		
		while (!knot_node_is_auth(previous)) {
			previous = knot_node_previous(previous);
		}
	}

	knot_rrset_t *rrset =
		knot_node_get_rrset(previous, KNOT_RRTYPE_NSEC);
	if (rrset != NULL) {
		// NSEC proving that there is no node with the searched name
		knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);
		rrset = knot_rrset_get_rrsigs(rrset);
		assert(rrset != NULL);
		knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSECs or NSEC3s for wildcard NODATA answer into the response.
 *
 * \note This function first checks if DNSSEC is enabled and requested by the
 *       query.
 *
 * \param node Node used for answering.
 * \param closest_encloser Closest encloser of \a qname in the zone.
 * \param previous Previous node of \a qname in canonical order.
 * \param zone Zone used for answering.
 * \param qname Actual searched domain name.
 * \param resp Response where to put the NSECs and NSEC3s.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec_nsec3_wildcard_nodata(const knot_node_t *node,
                                          const knot_node_t *closest_encloser,
                                          const knot_node_t *previous,
                                          const knot_zone_contents_t *zone,
                                          const knot_dname_t *qname,
                                          knot_packet_t *resp)
{
	int ret = KNOT_EOK;
	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))) {
		if (knot_zone_contents_nsec3_enabled(zone)) {
			ret = ns_put_nsec3_closest_encloser_proof(zone,
			                                      &closest_encloser,
			                                      qname, resp);

			const knot_node_t *nsec3_node;
			if (ret == KNOT_EOK
			    && (nsec3_node = knot_node_nsec3_node(node))
			        != NULL) {
				ns_put_nsec3_from_node(nsec3_node, resp);
			}
		} else {
			ns_put_nsec_wildcard(zone, qname, previous, resp);
		}
	}
	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts NSECs or NSEC3s for wildcard answer into the response.
 *
 * \note This function first checks if DNSSEC is enabled and requested by the
 *       query and if the node's owner is a wildcard.
 *
 * \param node Node used for answering.
 * \param closest_encloser Closest encloser of \a qname in the zone.
 * \param previous Previous node of \a qname in canonical order.
 * \param zone Zone used for answering.
 * \param qname Actual searched domain name.
 * \param resp Response where to put the NSECs and NSEC3s.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec_nsec3_wildcard_answer(const knot_node_t *node,
                                          const knot_node_t *closest_encloser,
                                          const knot_node_t *previous,
                                          const knot_zone_contents_t *zone,
                                          const knot_dname_t *qname,
                                          knot_packet_t *resp)
{
	int r = KNOT_EOK;
	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))
	    && knot_dname_is_wildcard(knot_node_owner(node))) {
		if (knot_zone_contents_nsec3_enabled(zone)) {
			r = ns_put_nsec3_wildcard(zone, closest_encloser, qname,
			                          resp);
		} else {
			ns_put_nsec_wildcard(zone, qname, previous, resp);
		}
	}
	return r;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates a referral response.
 *
 * This function puts the delegation NS RRSet to the Authority section of the
 * response, possibly adds DS and their associated RRSIGs (if DNSSEC is enabled
 * and requested by the query) and adds any available additional data (A and
 * AAAA RRSets for the names in the NS RRs) with their associated RRSIGs
 * to the Additional section.
 *
 * \param node Delegation point node.
 * \param zone Parent zone (the one from which the response is generated).
 * \param qname Searched name (which caused the referral).
 * \param resp Response.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static inline int ns_referral(const knot_node_t *node,
                              const knot_zone_contents_t *zone,
                              const knot_dname_t *qname,
                              knot_packet_t *resp,
                              uint16_t qtype)
{
	dbg_ns("Referral response.\n");

	while (!knot_node_is_deleg_point(node)) {
		assert(knot_node_parent(node) != NULL);
		node = knot_node_parent(node);
	}

	// Special handling of DS queries
	if (qtype == KNOT_RRTYPE_DS) {
		knot_rrset_t *ds_rrset = knot_node_get_rrset(node, 
		                                             KNOT_RRTYPE_DS);
		int ret = KNOT_EOK;
		
		if (ds_rrset) {
			knot_response_add_rrset_answer(resp, ds_rrset, 1, 0, 
			                               0, 1);
			if (DNSSEC_ENABLED
			    && knot_query_dnssec_requested(
			                        knot_packet_query(resp))) {
				ns_add_rrsigs(ds_rrset, resp, node->owner,
				              knot_response_add_rrset_authority,
				              1);
			}
		} else {
			// normal NODATA response
			/*! \todo Handle in some generic way. */
			
			dbg_ns("Adding NSEC/NSEC3 for NODATA.\n");
			ns_put_nsec_nsec3_nodata(node, resp);
			
			// wildcard delegations not supported!
//			if (knot_dname_is_wildcard(node->owner)) {
//				dbg_ns("Putting NSEC/NSEC3 for wildcard"
//				       " NODATA\n");
//				ret = ns_put_nsec_nsec3_wildcard_nodata(node,
//				       closest_encloser, previous, zone, qname,
//				       resp);
//			}
			ns_put_authority_soa(zone, resp);
		}
		
		return ret;
	}
	
	knot_rrset_t *rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NS);
	assert(rrset != NULL);

	// TODO: wildcards??
	//ns_check_wildcard(name, resp, &rrset);
	
	knot_response_add_rrset_authority(resp, rrset, 1, 0, 0, 1);
	ns_add_rrsigs(rrset, resp, node->owner,
	              knot_response_add_rrset_authority, 1);

	int ret = KNOT_EOK;
	// add DS records
	dbg_ns("DNSSEC requested: %d\n",
		 knot_query_dnssec_requested(knot_packet_query(resp)));
	dbg_ns("DS records: %p\n", knot_node_rrset(node, KNOT_RRTYPE_DS));
	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))) {
		rrset = knot_node_get_rrset(node, KNOT_RRTYPE_DS);
		if (rrset != NULL) {
			knot_response_add_rrset_authority(resp, rrset, 1, 0,
			                                  0, 1);
			ns_add_rrsigs(rrset, resp, node->owner,
			              knot_response_add_rrset_authority, 1);
		} else {
			// no DS, add NSEC3 or NSEC
			// if NSEC3 enabled, search for NSEC3
			if (knot_zone_contents_nsec3_enabled(zone)) {
				const knot_node_t *nsec3_node =
					knot_node_nsec3_node(node);
				dbg_ns("There is no DS, putting NSEC3s...\n");
				if (nsec3_node != NULL) {
					dbg_ns("Putting NSEC3s from the node.\n");
					ns_put_nsec3_from_node(nsec3_node, resp);
				} else {
					dbg_ns("Putting Opt-Out NSEC3s.\n");
					// no NSEC3 (probably Opt-Out)
					// TODO: check if the zone is Opt-Out
					ret = ns_put_nsec3_closest_encloser_proof(zone,
						&node, qname, resp);
				}
			} else {
				knot_rrset_t *nsec = knot_node_get_rrset(
					node, KNOT_RRTYPE_NSEC);
				if (nsec) {
					/*! \todo Check return value? */
					knot_response_add_rrset_authority(
						resp, nsec, 1, 1, 0, 1);
					if ((nsec = knot_rrset_get_rrsigs(nsec)) != NULL) {
						knot_response_add_rrset_authority(
						        resp, nsec, 1, 1, 0, 1);
					}
				}
			}
		}
	}

	if (ret == KNOT_EOK) {
		ns_put_additional(resp);
		knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);
	}
	return ret;
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Tries to answer the query from the given node.
 *
 * Tries to put RRSets of requested type (\a qtype) to the Answer section of the
 * response. If successful, it also adds authority NS RRSet to the Authority
 * section and it may add NSEC or NSEC3s in case of a wildcard answer (\a node
 * is a wildcard node). If not successful (there are no such RRSets), it adds
 * the SOA record to the Authority section and may add NSEC or NSEC3s according
 * to the type of the response (NXDOMAIN if \a node is an empty non-terminal,
 * NODATA if it is a regular node). It also adds any additional data that may
 * be required.
 *
 * \param node Node to answer from.
 * \param closest_encloser Closest encloser of \a qname in the zone.
 * \param previous Previous domain name of \a qname in canonical order.
 * \param zone Zone used for answering.
 * \param qname Searched domain name.
 * \param qtype Searched RR type.
 * \param resp Response.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_answer_from_node(const knot_node_t *node,
                               const knot_node_t *closest_encloser,
                               const knot_node_t *previous,
                               const knot_zone_contents_t *zone,
                               const knot_dname_t *qname, uint16_t qtype,
                               knot_packet_t *resp)
{
	dbg_ns("Putting answers from found node to the response...\n");
	int answers = ns_put_answer(node, qname, qtype, resp);

	int ret = KNOT_EOK;
	if (answers == 0) {  // if NODATA response, put SOA
		if (knot_node_rrset_count(node) == 0
		    && !knot_zone_contents_nsec3_enabled(zone)) {
			// node is an empty non-terminal => NSEC for NXDOMAIN
			//assert(knot_node_rrset_count(closest_encloser) > 0);
			dbg_ns("Adding NSEC/NSEC3 for NXDOMAIN.\n");
			ret = ns_put_nsec_nsec3_nxdomain(zone,
				knot_node_previous(node), closest_encloser,
				qname, resp);
		} else {
			dbg_ns("Adding NSEC/NSEC3 for NODATA.\n");
			ns_put_nsec_nsec3_nodata(node, resp);
			if (knot_dname_is_wildcard(node->owner)) {
				dbg_ns("Putting NSEC/NSEC3 for wildcard"
				              " NODATA\n");
				ret = ns_put_nsec_nsec3_wildcard_nodata(node,
					closest_encloser, previous, zone, qname,
					resp);
			}
		}
		ns_put_authority_soa(zone, resp);
	} else {  // else put authority NS
		// if wildcard answer, add NSEC / NSEC3
		dbg_ns("Adding NSEC/NSEC3 for wildcard answer.\n");
		ret = ns_put_nsec_nsec3_wildcard_answer(node, closest_encloser,
		                                  previous, zone, qname, resp);
		ns_put_authority_ns(zone, resp);
	}

	if (ret == KNOT_EOK) {
		ns_put_additional(resp);
	}
	return ret;
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Synthetizes a CNAME RR from a DNAME.
 *
 * \param dname_rrset DNAME RRSet to synthetize from (only the first RR is
 *                    used).
 * \param qname Name to be used as the owner name of the synthetized CNAME.
 *
 * \return Synthetized CNAME RRset (this is a newly created RRSet, remember to
 *         free it).
 */
static knot_rrset_t *ns_cname_from_dname(const knot_rrset_t *dname_rrset,
                                           const knot_dname_t *qname)
{
	dbg_ns("Synthetizing CNAME from DNAME...\n");

	// create new CNAME RRSet

	knot_dname_t *owner = knot_dname_deep_copy(qname);
	if (owner == NULL) {
		return NULL;
	}

	knot_rrset_t *cname_rrset = knot_rrset_new(
		owner, KNOT_RRTYPE_CNAME, KNOT_CLASS_IN, SYNTH_CNAME_TTL);

	/* Release owner, as it's retained in rrset. */
	knot_dname_release(owner);

	if (cname_rrset == NULL) {
		return NULL;
	}

	// replace last labels of qname with DNAME
	knot_dname_t *cname = knot_dname_replace_suffix(qname,
	      knot_dname_size(knot_rrset_owner(dname_rrset)),
	      knot_rdata_get_item(knot_rrset_rdata(dname_rrset), 0)->dname);
dbg_ns_exec(
	char *name = knot_dname_to_str(cname);
	dbg_ns("CNAME canonical name: %s.\n", name);
	free(name);
);
	knot_rdata_t *cname_rdata = knot_rdata_new();
	knot_rdata_item_t cname_rdata_item;
	cname_rdata_item.dname = cname;
	knot_rdata_set_items(cname_rdata, &cname_rdata_item, 1);

	knot_rrset_add_rdata(cname_rrset, cname_rdata);

	return cname_rrset;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if the name created by replacing the owner of \a dname_rrset
 *        in the \a qname by the DNAME's target would be longer than allowed.
 *
 * \param dname_rrset DNAME RRSet to be used for the check.
 * \param qname Name whose part is to be replaced.
 *
 * \retval <>0 if the created domain name would be too long.
 * \retval 0 otherwise.
 */
static int ns_dname_is_too_long(const knot_rrset_t *dname_rrset,
                                const knot_dname_t *qname)
{
	// TODO: add function for getting DNAME target
	if (knot_dname_label_count(qname)
	        - knot_dname_label_count(knot_rrset_owner(dname_rrset))
	        + knot_dname_label_count(knot_rdata_get_item(
	                             knot_rrset_rdata(dname_rrset), 0)->dname)
	        > KNOT_MAX_DNAME_LENGTH) {
		return 1;
	} else {
		return 0;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief DNAME processing.
 *
 * This function adds the DNAME RRSet (and possibly its associated RRSIGs to the
 * Answer section of the response, synthetizes CNAME record from the DNAME and
 * adds it there too. It also stores the synthetized CNAME in the temporary
 * RRSets of the response.
 *
 * \param dname_rrset DNAME RRSet to use.
 * \param qname Searched name.
 * \param resp Response.
 */
static void ns_process_dname(knot_rrset_t *dname_rrset,
                             const knot_dname_t *qname,
                             knot_packet_t *resp)
{
dbg_ns_exec(
	char *name = knot_dname_to_str(knot_rrset_owner(dname_rrset));
	dbg_ns("Processing DNAME for owner %s...\n", name);
	free(name);
);
	// TODO: check the number of RRs in the RRSet??

	// put the DNAME RRSet into the answer
	knot_response_add_rrset_answer(resp, dname_rrset, 1, 0, 0, 1);
	ns_add_rrsigs(dname_rrset, resp, qname,
	              knot_response_add_rrset_answer, 1);

	if (ns_dname_is_too_long(dname_rrset, qname)) {
		knot_response_set_rcode(resp, KNOT_RCODE_YXDOMAIN);
		return;
	}

	// synthetize CNAME (no way to tell that client supports DNAME)
	knot_rrset_t *synth_cname = ns_cname_from_dname(dname_rrset, qname);
	// add the synthetized RRSet to the Answer
	knot_response_add_rrset_answer(resp, synth_cname, 1, 0, 0, 1);

	// no RRSIGs for this RRSet

	// add the synthetized RRSet into list of temporary RRSets of response
	knot_packet_add_tmp_rrset(resp, synth_cname);

	// do not search for the name in new zone (out-of-bailiwick)
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds DNSKEY RRSet from the apex of a zone to the response.
 *
 * \param apex Zone apex node.
 * \param resp Response.
 */
static void ns_add_dnskey(const knot_node_t *apex, knot_packet_t *resp)
{
	knot_rrset_t *rrset =
		knot_node_get_rrset(apex, KNOT_RRTYPE_DNSKEY);
	if (rrset != NULL) {
		knot_response_add_rrset_additional(resp, rrset, 0, 0, 0, 1);
		ns_add_rrsigs(rrset, resp, apex->owner,
			      knot_response_add_rrset_additional, 0);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Answers the query from the given zone.
 *
 * This function performs the actual answering logic.
 *
 * \param zone Zone to use for answering.
 * \param qname QNAME from the query.
 * \param qtype QTYPE from the query.
 * \param resp Response to fill in.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 *
 * \todo Describe the answering logic in detail.
 */
static int ns_answer_from_zone(const knot_zone_contents_t *zone,
                               knot_packet_t *resp)
{
	const knot_node_t *node = NULL, *closest_encloser = NULL,
	                    *previous = NULL;
	int cname = 0, auth_soa = 0, ret = 0, find_ret = 0;

	const knot_dname_t *qname = knot_packet_qname(resp);
	uint16_t qtype = knot_packet_qtype(resp);

search:
#ifdef USE_HASH_TABLE
	/*! \todo Check version. */
	find_ret = knot_zone_contents_find_dname_hash(zone, qname, &node,
	                                                &closest_encloser);
//	node = knot_node_current(node);
//	closest_encloser = knot_node_current(closest_encloser);
#else
	/*! \todo Check version. */
	find_ret = knot_zone_contents_find_dname(zone, qname, &node,
	                                          &closest_encloser, &previous);
	node = knot_node_current(node);
	closest_encloser = knot_node_current(closest_encloser);
	previous = knot_node_current(previous);
#endif
	if (find_ret == KNOT_EBADARG) {
		return NS_ERR_SERVFAIL;
	}

dbg_ns_exec(
	char *name;
	if (node) {
		name = knot_dname_to_str(node->owner);
		dbg_ns("zone_find_dname() returned node %s ", name);
		free(name);
	} else {
		dbg_ns("zone_find_dname() returned no node,");
	}

	if (closest_encloser != NULL) {
		name = knot_dname_to_str(closest_encloser->owner);
		dbg_ns(" closest encloser %s.\n", name);
		free(name);
	} else {
		dbg_ns(" closest encloser (nil).\n");
	}
	if (previous != NULL) {
		name = knot_dname_to_str(previous->owner);
		dbg_ns(" and previous node: %s.\n", name);
		free(name);
	} else {
		dbg_ns(" and previous node: (nil).\n");
	}
);
	if (find_ret == KNOT_EBADZONE) {
		// possible only if we followed cname
		assert(cname != 0);
		knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);
		auth_soa = 1;
		knot_response_set_aa(resp);
		goto finalize;
	}

have_node:
	dbg_ns("Closest encloser is deleg. point? %s\n",
		 (knot_node_is_deleg_point(closest_encloser)) ? "yes" : "no");

	dbg_ns("Closest encloser is non authoritative? %s\n",
		 (knot_node_is_non_auth(closest_encloser)) ? "yes" : "no");

	if (knot_node_is_deleg_point(closest_encloser)
	    || knot_node_is_non_auth(closest_encloser)) {
		ret = ns_referral(closest_encloser, zone, qname, resp, qtype);
		goto finalize;
	}

	if (find_ret == KNOT_ZONE_NAME_NOT_FOUND) {
		// DNAME?
		knot_rrset_t *dname_rrset = knot_node_get_rrset(
		                         closest_encloser, KNOT_RRTYPE_DNAME);
		if (dname_rrset != NULL) {
			ns_process_dname(dname_rrset, qname, resp);
			auth_soa = 1;
			knot_response_set_aa(resp);
			goto finalize;
		}
		// else check for a wildcard child
		const knot_node_t *wildcard_node =
			knot_node_wildcard_child(closest_encloser);

		if (wildcard_node == NULL) {
			dbg_ns("No wildcard node. (cname: %d)\n",
				 cname);
			auth_soa = 1;
			if (cname == 0) {
				dbg_ns("Setting NXDOMAIN RCODE.\n");
				// return NXDOMAIN
				knot_response_set_rcode(resp,
					KNOT_RCODE_NXDOMAIN);
				if (ns_put_nsec_nsec3_nxdomain(zone, previous,
					closest_encloser, qname, resp) != 0) {
					return NS_ERR_SERVFAIL;
				}
			} else {
				knot_response_set_rcode(resp,
					KNOT_RCODE_NOERROR);
			}
			knot_response_set_aa(resp);
			goto finalize;
		}
		// else set the node from which to take the answers to wild.node
		node = wildcard_node;
	}

	// now we have the node for answering
	if (knot_node_is_deleg_point(node) || knot_node_is_non_auth(node)) {
		ret = ns_referral(node, zone, qname, resp, qtype);
		goto finalize;
	}

	if (knot_node_rrset(node, KNOT_RRTYPE_CNAME) != NULL) {
dbg_ns_exec(
		char *name = knot_dname_to_str(node->owner);
		dbg_ns("Node %s has CNAME record, resolving...\n",
		         name);
		free(name);
);
		const knot_dname_t *act_name = qname;
		ns_follow_cname(&node, &act_name, resp,
		                knot_response_add_rrset_answer, 1);
dbg_ns_exec(
		char *name = (node != NULL) ? knot_dname_to_str(node->owner)
			: "(nil)";
		char *name2 = knot_dname_to_str(act_name);
		dbg_ns("Canonical name: %s (%p), node found: %p\n",
			 name2, act_name, node);
		dbg_ns("The node's owner: %s (%p)\n", name, (node != NULL)
		       ? node->owner : NULL);
		if (node != NULL) {
			free(name);
		}
		free(name2);
);
		qname = act_name;
		cname = 1;

		// otherwise search for the new name
		if (node == NULL) {
			goto search;
		} else if (node->owner != act_name) {
			// the stored node is closest encloser
			find_ret = KNOT_ZONE_NAME_NOT_FOUND;
			closest_encloser = node;
			node = NULL;
			goto have_node;
		} // else do nothing, just continue
	}

	ret = ns_answer_from_node(node, closest_encloser, previous, zone, qname,
	                          qtype, resp);
	if (ret == NS_ERR_SERVFAIL) {
		// in this case we should drop the response and send an error
		// for now, just send the error code with a non-complete answer
//		knot_response_set_rcode(resp, KNOT_RCODE_SERVFAIL);
//		goto finalize;
		return ret;
	} else if (ret != KNOT_EOK) {
		/*! \todo Handle RCODE return values!!! */
		goto finalize;
	}
	knot_response_set_aa(resp);
	knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);

	// this is the only case when the servers answers from
	// particular node, i.e. the only case when it may return SOA
	// or NS records in Answer section
	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))
	    && node == knot_zone_contents_apex(zone)
	    && (qtype == KNOT_RRTYPE_SOA || qtype == KNOT_RRTYPE_NS)) {
		ns_add_dnskey(node, resp);
	}

finalize:
	if (ret == KNOT_EOK && auth_soa) {
		ns_put_authority_soa(zone, resp);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Answers the query from the given zone database.
 *
 * First it searches for a zone to answer from. If there is none, it sets
 * RCODE REFUSED to the response and ends. Otherwise it tries to answer the
 * query using the found zone (see ns_answer_from_zone()).
 *
 * \param db Zone database to use for answering.
 * \param resp Response that holds the parsed query.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_answer(const knot_zone_t *zone, knot_packet_t *resp)
{
//	const knot_dname_t *qname = knot_packet_qname(resp);
//	assert(qname != NULL);

//	uint16_t qtype = knot_packet_qtype(resp);
//dbg_ns_exec(
//	char *name_str = knot_dname_to_str(qname);
//	dbg_ns("Trying to find zone for QNAME %s\n", name_str);
//	free(name_str);
//);
//	// find zone in which to search for the name
//	const knot_zone_t *zone =
//		ns_get_zone_for_qname(db, qname, qtype);
	const knot_zone_contents_t *contents = knot_zone_contents(zone);

	// if no zone found, return REFUSED
	if (zone == NULL) {
		dbg_ns("No zone found.\n");
		knot_response_set_rcode(resp, KNOT_RCODE_REFUSED);
		//knot_dname_free(&qname);
		return KNOT_EOK;
	} else if (contents == NULL) {
		dbg_ns("Zone expired or not bootstrapped. Reply SERVFAIL.\n");
		knot_response_set_rcode(resp, KNOT_RCODE_SERVFAIL);
		return KNOT_EOK;
	}

dbg_ns_exec(
	char *name_str2 = knot_dname_to_str(zone->contents->apex->owner);
	dbg_ns("Found zone for QNAME %s\n", name_str2);
	free(name_str2);
);

	// take the zone contents and use only them for answering

	return ns_answer_from_zone(contents, resp);

	//knot_dname_free(&qname);
}

/*----------------------------------------------------------------------------*/

int ns_response_to_wire(knot_packet_t *resp, uint8_t *wire,
                        size_t *wire_size)
{
	uint8_t *rwire = NULL;
	size_t rsize = 0;
	int ret = 0;

	if ((ret = knot_packet_to_wire(resp, &rwire, &rsize))
	     != KNOT_EOK) {
		dbg_ns("Error converting response packet "
		                 "to wire format (error %d).\n", ret);
		return NS_ERR_SERVFAIL;
	}

	if (rsize > *wire_size) {
		dbg_ns("Reponse size (%zu) larger than allowed wire size "
		         "(%zu).\n", rsize, *wire_size);
		return NS_ERR_SERVFAIL;
	}

	if (rwire != wire) {
		dbg_ns("Wire format reallocated, copying to place for "
		              "wire.\n");
		memcpy(wire, rwire, rsize);
	} else {
		dbg_ns("Using the same space or wire format.\n");
	}
	
	*wire_size = rsize;
	//free(rwire);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates a wire format of an error response from partially created
 *        response.
 *
 * \param resp Response to use.
 * \param wire Place for the wire format of the response.
 * \param wire_size In: space available for the wire format in bytes.
 *                  Out: actual size of the wire format in bytes.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_error_response_to_wire(knot_packet_t *resp, uint8_t *wire,
                                     size_t *wire_size)
{
	/* Do not call the packet conversion function
	 * wire format is assembled, but COUNTs in header are not set.
	 * This is ideal, we just truncate the packet after the question.
	 */
	dbg_ns("Creating error response.\n");
	
	size_t rsize = knot_packet_question_size(knot_packet_query(resp));
	dbg_ns("Error response (~ query) size: %zu\n", rsize);

	// take 'qsize' from the current wireformat of the response
	// it is already assembled - Header and Question section are copied
	const uint8_t *rwire = knot_packet_wireformat(resp);
	if (rsize > *wire_size) {
		dbg_ns("Reponse size (%zu) larger than allowed wire size"
		         " (%zu).\n", rsize, *wire_size);
		return NS_ERR_SERVFAIL;
	}

	assert(rwire != wire);
	
	/*! \todo Why is this copied?? Why we cannot use resp->wireformat?? */
	memcpy(wire, rwire, rsize);

	if (resp->opt_rr.version != EDNS_NOT_SUPPORTED) {
		short edns_size = knot_edns_to_wire(&resp->opt_rr, wire + rsize,
		                                    *wire_size - rsize);
		if (edns_size > 0) {
			*wire_size = rsize + edns_size;
		}
	} else {
		*wire_size = rsize;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

typedef struct ns_axfr_params {
	knot_ns_xfr_t *xfr;
	int ret;
} ns_axfr_params_t;

/*----------------------------------------------------------------------------*/

int knot_ns_tsig_required(int packet_nr) 
{
	dbg_ns_detail("ns_tsig_required(%d): %d\n", packet_nr,
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
	dbg_ns("Converting response to wire format..\n");
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

	/*! \note [TSIG] Generate TSIG if required (during XFR/IN). */
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

		dbg_ns_detail("Sign function returned: %s\n",
			      knot_strerror(res));
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
		dbg_ns_detail("Adding TSIG without signing, TSIG RCODE: %d.\n",
		              xfr->tsig_rcode);
		assert(xfr->tsig_rcode != KNOT_TSIG_RCODE_BADTIME);
		// add TSIG without signing
		assert(xfr->query != NULL);
		assert(knot_packet_additional_rrset_count(xfr->query) > 0);

		const knot_rrset_t *tsig = knot_packet_additional_rrset(
			xfr->query,
			knot_packet_additional_rrset_count(xfr->query) - 1);

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
		                   " Transfer size: %zu, sent: %d\n",
		                   real_size, res);
	}

	// Clean the response structure
	dbg_ns("Clearing response structure..\n");
	knot_response_clear(xfr->response, 0);
	
	// increment the packet number
	++xfr->packet_nr;
	if ((xfr->tsig_key && knot_ns_tsig_required(xfr->packet_nr))
	     || xfr->tsig_rcode != 0) {
		/*! \todo Where is xfr->tsig_size set?? */
		knot_packet_set_tsig_size(xfr->response, xfr->tsig_size);
	} else {
		knot_packet_set_tsig_size(xfr->response, 0);
	}

	dbg_ns("Response structure after clearing:\n");
	knot_packet_dump(xfr->response);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static void ns_axfr_from_node(knot_node_t *node, void *data)
{
	assert(node != NULL);
	assert(data != NULL);

	ns_axfr_params_t *params = (ns_axfr_params_t *)data;

	if (params->ret != KNOT_EOK) {
		// just skip (will be called on next node with the same params
		dbg_ns("Params contain error: %s, skipping node...\n",
		              knot_strerror(params->ret));
		return;
	}

	dbg_ns("Params OK, answering AXFR from node %p.\n", node);
dbg_ns_exec(
	char *name = knot_dname_to_str(knot_node_owner(node));
	dbg_ns("Node ownerr: %s\n", name);
	free(name);
);

	if (knot_node_rrset_count(node) == 0) {
		return;
	}

	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
	if (rrsets == NULL) {
		params->ret = KNOT_ENOMEM;
		return;
	}

	int i = 0;
	int ret = 0;
	knot_rrset_t *rrset = NULL;
	while (i < knot_node_rrset_count(node)) {
		assert(rrsets[i] != NULL);
		rrset = rrsets[i];
rrset:
		dbg_ns("  Type: %s\n",
		     knot_rrtype_to_string(knot_rrset_type(rrset)));

		// do not add SOA
		if (knot_rrset_type(rrset) == KNOT_RRTYPE_SOA) {
			++i;
			continue;
		}

		ret = knot_response_add_rrset_answer(params->xfr->response,
		                                       rrset, 0, 0, 1, 0);

		if (ret == KNOT_ESPACE) {
			// TODO: send the packet and clean the structure
			dbg_ns("Packet full, sending..\n");
			ret = ns_xfr_send_and_clear(params->xfr, 
				knot_ns_tsig_required(params->xfr->packet_nr));
			if (ret != KNOT_EOK) {
				// some wierd problem, we should end
				params->ret = KNOT_ERROR;
				break;
			}
			// otherwise try once more with the same RRSet
			goto rrset;
		} else if (ret != KNOT_EOK) {
			// some wierd problem, we should end
			params->ret = KNOT_ERROR;
			break;
		}

		// we can send the RRSets in any order, so add the RRSIGs now
		rrset = knot_rrset_get_rrsigs(rrset);
rrsigs:
		if (rrset == NULL) {
			++i;
			continue;
		}

		ret = knot_response_add_rrset_answer(params->xfr->response,
		                                        rrset, 0, 0, 1, 0);

		if (ret == KNOT_ESPACE) {
			// TODO: send the packet and clean the structure
			dbg_ns("Packet full, sending..\n");
			ret = ns_xfr_send_and_clear(params->xfr,
				knot_ns_tsig_required(params->xfr->packet_nr));
			if (ret != KNOT_EOK) {
				// some wierd problem, we should end
				params->ret = KNOT_ERROR;
				break;
			}
			// otherwise try once more with the same RRSet
			goto rrsigs;
		} else if (ret != KNOT_EOK) {
			// some wierd problem, we should end
			params->ret = KNOT_ERROR;
			break;
		}

		// this way only whole RRSets are always sent
		// we guess it will not create too much overhead

		++i;
	}
	if (rrsets != NULL) {
		free(rrsets);
	}

	/*! \todo maybe distinguish some error codes. */
	//params->ret = (ret == 0) ? KNOT_EOK : KNOT_ERROR;
}

/*----------------------------------------------------------------------------*/

static int ns_axfr_from_zone(knot_zone_contents_t *zone, knot_ns_xfr_t *xfr)
{
	assert(xfr != NULL);
	assert(xfr->query != NULL);
	assert(xfr->response != NULL);
	assert(xfr->wire != NULL);
	assert(xfr->send != NULL);

	ns_axfr_params_t params;
	memset(&params, 0, sizeof(ns_axfr_params_t));
	params.xfr = xfr;
	params.ret = KNOT_EOK;

	xfr->packet_nr = 0;
	
	/*
	 * First SOA
	 */

	// retrieve SOA - must be send as first and last RR
	knot_rrset_t *soa_rrset = knot_node_get_rrset(
		knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		// some really serious error
		return KNOT_ERROR;
	}

	int ret;

	// add SOA RR to the response
	ret = knot_response_add_rrset_answer(xfr->response, soa_rrset, 0, 0, 1,
	                                     0);
	if (ret != KNOT_EOK) {
		// something is really wrong
		return KNOT_ERROR;
	}

	// add the SOA's RRSIG
	knot_rrset_t *rrset = knot_rrset_get_rrsigs(soa_rrset);
	if (rrset != NULL
	    && (ret = knot_response_add_rrset_answer(xfr->response, rrset,
	                                             0, 0, 1, 0)) != KNOT_EOK) {
		// something is really wrong, these should definitely fit in
		return KNOT_ERROR;
	}

	knot_zone_contents_tree_apply_inorder(zone, ns_axfr_from_node,
	                                        &params);

	if (params.ret != KNOT_EOK) {
		return KNOT_ERROR;	// maybe do something with the code
	}

	knot_zone_contents_nsec3_apply_inorder(zone, ns_axfr_from_node,
	                                         &params);

	if (params.ret != KNOT_EOK) {
		return KNOT_ERROR;	// maybe do something with the code
	}

	/*
	 * Last SOA
	 */

	// try to add the SOA to the response again (last RR)
	ret = knot_response_add_rrset_answer(xfr->response, soa_rrset, 0, 0, 1,
	                                     0);
	if (ret == KNOT_ESPACE) {
			
		// if there is not enough space, send the response and
		// add the SOA record to a new packet
		dbg_ns("Packet full, sending..\n");
		ret = ns_xfr_send_and_clear(xfr,
			knot_ns_tsig_required(xfr->packet_nr));
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = knot_response_add_rrset_answer(xfr->response,
		                                     soa_rrset, 0, 0, 1, 0);
		if (ret != KNOT_EOK) {
			return KNOT_ERROR;
		}

	} else if (ret != KNOT_EOK) {
		// something is really wrong
		return KNOT_ERROR;
	}

	dbg_ns("Sending packet...\n");
	return ns_xfr_send_and_clear(xfr, 1);
}

/*----------------------------------------------------------------------------*/

static int ns_ixfr_put_rrset(knot_ns_xfr_t *xfr, knot_rrset_t *rrset)
{
	int res = knot_response_add_rrset_answer(xfr->response, rrset,
	                                         0, 0, 0, 0);
	if (res == KNOT_ESPACE) {
		knot_response_set_rcode(xfr->response, KNOT_RCODE_NOERROR);
		/*! \todo Probably rename the function. */
		ns_xfr_send_and_clear(xfr, knot_ns_tsig_required(xfr->packet_nr));

		res = knot_response_add_rrset_answer(xfr->response,
		                                     rrset, 0, 0, 0, 0);
	}

	if (res != KNOT_EOK) {
		dbg_ns("Error putting origin SOA to IXFR reply: %s\n",
			 knot_strerror(res));
		/*! \todo Probably send back AXFR instead. */
		knot_response_set_rcode(xfr->response,
		                           KNOT_RCODE_SERVFAIL);
		/*! \todo Probably rename the function. */
		ns_xfr_send_and_clear(xfr, 1);
		//socket_close(xfr->session);  /*! \todo Remove for UDP.*/
		return res;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int ns_ixfr_put_changeset(knot_ns_xfr_t *xfr, const knot_changeset_t *chgset)
{
	// 1) put origin SOA
	int res = ns_ixfr_put_rrset(xfr, chgset->soa_from);
	if (res != KNOT_EOK) {
		return res;
	}

	// 2) put remove RRSets
	for (int i = 0; i < chgset->remove_count; ++i) {
		res = ns_ixfr_put_rrset(xfr, chgset->remove[i]);
		if (res != KNOT_EOK) {
			return res;
		}
	}

	// 1) put target SOA
	res = ns_ixfr_put_rrset(xfr, chgset->soa_to);
	if (res != KNOT_EOK) {
		return res;
	}

	// 2) put remove RRSets
	for (int i = 0; i < chgset->add_count; ++i) {
		res = ns_ixfr_put_rrset(xfr, chgset->add[i]);
		if (res != KNOT_EOK) {
			return res;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int ns_ixfr_from_zone(knot_ns_xfr_t *xfr)
{
	assert(xfr != NULL);
	assert(xfr->zone != NULL);
	assert(xfr->query != NULL);
	assert(xfr->response != NULL);
	assert(knot_packet_authority_rrset_count(xfr->query) > 0);
	assert(xfr->data != NULL);
	
	knot_changesets_t *chgsets = (knot_changesets_t *)xfr->data;
	knot_zone_contents_t *contents = knot_zone_get_contents(xfr->zone);
	assert(contents);
	knot_rrset_t *zone_soa =
		knot_node_get_rrset(knot_zone_contents_apex(contents),
		                    KNOT_RRTYPE_SOA);

	// 4) put the zone SOA as the first Answer RR
	int res = knot_response_add_rrset_answer(xfr->response, zone_soa, 0, 
	                                         0, 0, 0);
	if (res != KNOT_EOK) {
		dbg_ns("IXFR query cannot be answered: %s.\n",
			 knot_strerror(res));
		knot_response_set_rcode(xfr->response,
		                           KNOT_RCODE_SERVFAIL);
		/*! \todo Probably rename the function. */
		ns_xfr_send_and_clear(xfr, 1);
//		socket_close(xfr->session);  /*! \todo Remove for UDP.*/
		return res;
	}

	// 5) put the changesets into the response while they fit in
	for (int i = 0; i < chgsets->count; ++i) {
		res = ns_ixfr_put_changeset(xfr, &chgsets->sets[i]);
		if (res != KNOT_EOK) {
			// answer is sent
			return res;
		}
	}

	if (chgsets->count > 0) {
		res = ns_ixfr_put_rrset(xfr, zone_soa);
	}

	if (res == KNOT_EOK) {
		/*! \todo Probably rename the function. */
		ns_xfr_send_and_clear(xfr, 1);
		//socket_close(xfr->session);  /*! \todo Remove for UDP.*/
//		return 1;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int ns_ixfr(knot_ns_xfr_t *xfr)
{
	assert(xfr != NULL);
	assert(xfr->query != NULL);
	assert(xfr->response != NULL);
	assert(knot_packet_qtype(xfr->response) == KNOT_RRTYPE_IXFR);

	// check if there is the required authority record
	if ((knot_packet_authority_rrset_count(xfr->query) <= 0)) {
		// malformed packet
		dbg_ns("IXFR query does not contain authority record.\n");
		knot_response_set_rcode(xfr->response, KNOT_RCODE_FORMERR);
		/*! \todo Probably rename the function. */
		if (ns_xfr_send_and_clear(xfr, 1) == KNOT_ECONN) {
			return KNOT_ECONN;
		}
		//socket_close(xfr->session);
		return KNOT_EMALF;
	}

	const knot_rrset_t *soa = knot_packet_authority_rrset(xfr->query, 0);
	const knot_dname_t *qname = knot_packet_qname(xfr->response);

	// check if XFR QNAME and SOA correspond
	if (knot_packet_qtype(xfr->query) != KNOT_RRTYPE_IXFR
	    || knot_rrset_type(soa) != KNOT_RRTYPE_SOA
	    || knot_dname_compare(qname, knot_rrset_owner(soa)) != 0) {
		// malformed packet
		dbg_ns("IXFR query is malformed.\n");
		knot_response_set_rcode(xfr->response, KNOT_RCODE_FORMERR);
		/*! \todo Probably rename the function. */
		if (ns_xfr_send_and_clear(xfr, 1) == KNOT_ECONN) {
			return KNOT_ECONN;
		}
		//socket_close(xfr->session);  /*! \todo Remove for UDP. */
		return KNOT_EMALF;
	}

	return ns_ixfr_from_zone(xfr);
}

/*----------------------------------------------------------------------------*/

static int knot_ns_prepare_response(knot_nameserver_t *nameserver,
                                    knot_packet_t *query, knot_packet_t **resp,
                                    size_t max_size)
{
	assert(max_size >= 500);
	
	// initialize response packet structure
	*resp = knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	if (*resp == NULL) {
		dbg_ns("Failed to create packet structure.\n");
		return KNOT_ENOMEM;
	}

	int ret = knot_packet_set_max_size(*resp, max_size);
	//(*resp)->wireformat = response_wire;;
	//(*resp)->max_size = max_size;

	if (ret != KNOT_EOK) {
		dbg_ns("Failed to init response structure.\n");
		knot_packet_free(resp);
		return ret;
	}

	ret = knot_response_init_from_query(*resp, query);

	if (ret != KNOT_EOK) {
		dbg_ns("Failed to init response structure.\n");
		knot_packet_free(resp);
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
	ns->zone_db = knot_zonedb_new();
	if (ns->zone_db == NULL) {
		ERR_ALLOC_FAILED;
		free(ns);
		return NULL;
	}

	// prepare empty response with SERVFAIL error
	knot_packet_t *err = knot_packet_new(KNOT_PACKET_PREALLOC_NONE);
	if (err == NULL) {
		ERR_ALLOC_FAILED;
		free(ns);
		return NULL;
	}

	dbg_ns("Created default empty response...\n");

	int rc = knot_packet_set_max_size(err, KNOT_WIRE_HEADER_SIZE);
	if (rc != KNOT_EOK) {
		dbg_ns("Error creating default error response: %s.\n",
		                 knot_strerror(rc));
		free(ns);
		knot_packet_free(&err);
		return NULL;
	}

	rc = knot_response_init(err);
	if (rc != KNOT_EOK) {
		dbg_ns("Error initializing default error response:"
		                 " %s.\n", knot_strerror(rc));
		free(ns);
		knot_packet_free(&err);
		return NULL;
	}

	knot_response_set_rcode(err, KNOT_RCODE_SERVFAIL);
	ns->err_resp_size = 0;

	dbg_ns("Converting default empty response to wire format...\n");

	uint8_t *error_wire = NULL;

	if (knot_packet_to_wire(err, &error_wire, &ns->err_resp_size) != 0) {
		dbg_ns("Error while converting "
		                 "default error response to "
		                 "wire format \n");
		knot_packet_free(&err);
		free(ns);
		return NULL;
	}

	ns->err_response = (uint8_t *)malloc(ns->err_resp_size);
	if (ns->err_response == NULL) {
		dbg_ns("Error while converting default "
		                 "error response to wire format \n");
		knot_packet_free(&err);
		free(ns);
		return NULL;
	}

	memcpy(ns->err_response, error_wire, ns->err_resp_size);

	dbg_ns("Done..\n");

	knot_packet_free(&err);

	if (EDNS_ENABLED) {
		ns->opt_rr = knot_edns_new();
		if (ns->opt_rr == NULL) {
			dbg_ns("Error while preparing OPT RR of the"
			                 " server.\n");
			knot_packet_free(&err);
			free(ns);
			return NULL;
		}
		knot_edns_set_version(ns->opt_rr, EDNS_VERSION);
		knot_edns_set_payload(ns->opt_rr, MAX_UDP_PAYLOAD_EDNS);
	} else {
		ns->opt_rr = NULL;
	}

	knot_packet_free(&err);

	return ns;
}

/*----------------------------------------------------------------------------*/

static int knot_ns_replace_nsid(knot_opt_rr_t *opt_rr, const char *nsid,
                                size_t len)
{
	assert(opt_rr != NULL);
	if (nsid == NULL || len == 0) {
		return KNOT_EOK;
	}

	int found = 0;
	int i = 0;

	while (i < opt_rr->option_count && !found) {
		if (opt_rr->options[i].code == EDNS_OPTION_NSID) {
			found = 1;
		} else {
			++i;
		}
	}

	if (found) {
		uint8_t *new_data = (uint8_t *)malloc(len);
		if (new_data == NULL) {
			return KNOT_ENOMEM;
		}

		memcpy(new_data, nsid, len);
		uint8_t *old = opt_rr->options[i].data;

		opt_rr->options[i].data = new_data;
		opt_rr->options[i].length = len;

		free(old);

		return KNOT_EOK;
	} else {
		return knot_edns_add_option(opt_rr, EDNS_OPTION_NSID,
		                            len, (const uint8_t *)nsid);
	}
}

/*----------------------------------------------------------------------------*/

void knot_ns_set_nsid(knot_nameserver_t *nameserver, const char *nsid, size_t len)
{
	if (nameserver == NULL) {
		dbg_ns("NS: set_nsid: nameserver=NULL.\n");
		return;
	}
	
	if (nsid == NULL) {
		/* This is fine. */
		return;
	}
	
	int ret = knot_ns_replace_nsid(nameserver->opt_rr, nsid, len);

//	int ret = knot_edns_add_option(nameserver->opt_rr, EDNS_OPTION_NSID,
//	                               len, (const uint8_t *)nsid);
	if (ret != KNOT_EOK) {
		dbg_ns("NS: set_nsid: could not add EDNS option.\n");
		return;
	}
	
	dbg_ns("NS: set_nsid: added successfully.\n");
}

/*----------------------------------------------------------------------------*/

int knot_ns_parse_packet(const uint8_t *query_wire, size_t qsize,
                    knot_packet_t *packet, knot_packet_type_t *type)
{
	if (packet == NULL || query_wire == NULL || type == NULL) {
		dbg_ns("Missing parameter to query parsing.\n");
		return KNOT_EBADARG;
	}

	dbg_ns("ns_parse_packet() called with query size %zu.\n", qsize);
	//dbg_ns_hex((char *)query_wire, qsize);

	if (qsize < 2) {
		return KNOT_EMALF;
	}

	// 1) create empty response
	dbg_ns("Parsing packet...\n");
	//parsed = knot_response_new_empty(NULL);

	int ret = 0;

	if ((ret = knot_packet_parse_from_wire(packet, query_wire,
	                                         qsize, 1)) != 0) {
		dbg_ns("Error while parsing packet, "
		                "libknot error '%s'.\n", knot_strerror(ret));
//		knot_response_free(&parsed);
		return KNOT_RCODE_FORMERR;
	}

	dbg_ns("Parsed packet header and Question:\n");
	knot_packet_dump(packet);

	// 3) determine the query type
	switch (knot_packet_opcode(packet))  {
	case KNOT_OPCODE_QUERY:
		switch (knot_packet_qtype(packet)) {
		case KNOT_RRTYPE_AXFR:
			*type = (knot_packet_is_query(packet))
			         ? KNOT_QUERY_AXFR : KNOT_RESPONSE_AXFR;
			break;
		case KNOT_RRTYPE_IXFR:
			*type = (knot_packet_is_query(packet))
			         ? KNOT_QUERY_IXFR : KNOT_RESPONSE_IXFR;
			break;
		default:
			*type = (knot_packet_is_query(packet))
			         ? KNOT_QUERY_NORMAL : KNOT_RESPONSE_NORMAL;
		}

		break;
	case KNOT_OPCODE_NOTIFY:
		*type = (knot_packet_is_query(packet))
		         ? KNOT_QUERY_NOTIFY : KNOT_RESPONSE_NOTIFY;
		break;
	case KNOT_OPCODE_UPDATE:
		if(knot_packet_is_query(packet)) {
			*type = KNOT_QUERY_UPDATE;
		} else {
			return KNOT_RCODE_FORMERR;
		}
		break;
	default:
		return KNOT_RCODE_NOTIMPL;
	}

//	knot_packet_free(&packet);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_ns_error_response(const knot_nameserver_t *nameserver, uint16_t query_id,
                       uint8_t rcode, uint8_t *response_wire, size_t *rsize)
{
	//dbg_ns("Error response: \n");
	//dbg_ns_hex((const char *)nameserver->err_response,
	//             nameserver->err_resp_size);

	memcpy(response_wire, nameserver->err_response,
	       nameserver->err_resp_size);
	// copy ID of the query
	knot_wire_set_id(response_wire, query_id);
	// set the RCODE
	knot_wire_set_rcode(response_wire, rcode);
	*rsize = nameserver->err_resp_size;
}

/*----------------------------------------------------------------------------*/

void knot_ns_error_response_full(knot_nameserver_t *nameserver,
                                 knot_packet_t *response, uint8_t rcode,
                                 uint8_t *response_wire, size_t *rsize)
{
	knot_response_set_rcode(response, rcode);

	if (ns_error_response_to_wire(response, response_wire, rsize) != 0) {
		knot_ns_error_response(nameserver, knot_packet_id(
		                       knot_packet_query(response)),
		                       KNOT_RCODE_SERVFAIL, response_wire,
		                       rsize);
	}
}

/*----------------------------------------------------------------------------*/

int knot_ns_prep_normal_response(knot_nameserver_t *nameserver,
                                 knot_packet_t *query, knot_packet_t **resp,
                                 const knot_zone_t **zone)
{
	dbg_ns("knot_ns_prep_normal_response()\n");

	if (nameserver == NULL || query == NULL || resp == NULL
	    || zone == NULL) {
		return KNOT_EBADARG;
	}

	// first, parse the rest of the packet
	assert(knot_packet_is_query(query));
	dbg_ns("Query - parsed: %zu, total wire size: %zu\n",
	              knot_packet_parsed(query), knot_packet_size(query));
	int ret;

	ret = knot_packet_parse_rest(query);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the query: "
				   "%s.\n", knot_strerror(ret));
		return ret;
	}

	/*
	 * Semantic checks - if ANCOUNT > 0 or NSCOUNT > 0, return FORMERR.
	 *
	 * If any xxCOUNT is less or more than actual RR count
	 * the previously called knot_packet_parse_rest() will recognize this.
	 *
	 * Check the QDCOUNT and in case of anything but 1 send back
	 * FORMERR
	 */
	if (knot_packet_ancount(query) > 0
	    || knot_packet_nscount(query) > 0
	    || knot_packet_qdcount(query) != 1) {
		dbg_ns("ANCOUNT or NSCOUNT not 0 in query, reply FORMERR.\n");
		return KNOT_EMALF;
	}

	size_t resp_max_size = 0;

	//assert(*rsize >= MAX_UDP_PAYLOAD);

	knot_packet_dump(query);

	if (knot_query_edns_supported(query)) {
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

	ret = knot_ns_prepare_response(nameserver, query, resp,
	                               resp_max_size);
	if (ret != KNOT_EOK) {
		return KNOT_ERROR;
	}

	dbg_ns("Query - parsed: %zu, total wire size: %zu\n",
	              query->parsed, query->size);
	dbg_ns("Opt RR: version: %d, payload: %d\n",
	              query->opt_rr.version, query->opt_rr.payload);

	// get the answer for the query
	knot_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);

	dbg_ns("EDNS supported in query: %d\n",
	         knot_query_edns_supported(query));

	// set the OPT RR to the response
	if (knot_query_edns_supported(query)) {
		ret = knot_response_add_opt(*resp, nameserver->opt_rr, 1,
		                            knot_query_nsid_requested(query));
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to set OPT RR to the response"
			                  ": %s\n", knot_strerror(ret));
		} else {
			// copy the DO bit from the query
			if (knot_query_dnssec_requested(query)) {
				/*! \todo API for this. */
				knot_edns_set_do(&(*resp)->opt_rr);
			}
		}
	}

	dbg_ns("Response max size: %zu\n", (*resp)->max_size);

	const knot_dname_t *qname = knot_packet_qname(*resp);
	assert(qname != NULL);

	uint16_t qtype = knot_packet_qtype(*resp);
dbg_ns_exec(
	char *name_str = knot_dname_to_str(qname);
	dbg_ns("Trying to find zone for QNAME %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	*zone = ns_get_zone_for_qname(zonedb, qname, qtype);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_normal(knot_nameserver_t *nameserver, 
                          const knot_zone_t *zone, knot_packet_t *resp,
                          uint8_t *response_wire, size_t *rsize)
{
	dbg_ns("ns_answer_normal()\n");

	int ret = ns_answer(zone, resp);

	if (ret != 0) {
		// now only one type of error (SERVFAIL), later maybe more
		knot_ns_error_response_full(nameserver, resp,
		                            KNOT_RCODE_SERVFAIL,
		                            response_wire, rsize);
	} else {
		dbg_ns("Created response packet.\n");
		//knot_response_dump(resp);
		knot_packet_dump(resp);

		// 4) Transform the packet into wire format
		if (ns_response_to_wire(resp, response_wire, rsize) != 0) {
			// send back SERVFAIL (as this is our problem)
			knot_ns_error_response_full(nameserver, resp,
			                            KNOT_RCODE_SERVFAIL,
			                            response_wire, rsize);
		}
	}

	dbg_ns("Returning response with wire size %zu\n", *rsize);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_init_xfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	dbg_ns("knot_ns_init_xfr()\n");

	if (nameserver == NULL || xfr == NULL) {
		return KNOT_EBADARG;
	}

	// no need to parse rest of the packet
	/*! \todo Parse rest of packet because of EDNS. */
	int ret = knot_packet_parse_rest(xfr->query);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the query: %s\n", 
		       knot_strerror(ret));
		knot_ns_error_response(nameserver, xfr->query->header.id,
				  (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
				                      : KNOT_RCODE_SERVFAIL, 
				  xfr->wire, &xfr->wire_size);
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire, 
		                xfr->wire_size);
		return ret;
	}
	
	dbg_packet("Parsed XFR query:\n");
	knot_packet_dump(xfr->query);

	// initialize response packet structure
	knot_packet_t *response = knot_packet_new(
	                               KNOT_PACKET_PREALLOC_RESPONSE);
	if (response == NULL) {
		dbg_ns("Failed to create packet structure.\n");
		/*! \todo xfr->wire is not NULL, will fail on assert! */
		knot_ns_error_response(nameserver, xfr->query->header.id,
				  KNOT_RCODE_SERVFAIL, xfr->wire,
				  &xfr->wire_size);
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire, 
		                xfr->wire_size);
		knot_packet_free(&response);
		return ret;
	}

	//int ret = knot_packet_set_max_size(response, xfr->wire_size);
	response->wireformat = xfr->wire;
	response->max_size = xfr->wire_size;

//	if (ret != KNOT_EOK) {
//		dbg_ns("Failed to init response structure.\n");
//		/*! \todo xfr->wire is not NULL, will fail on assert! */
//		knot_ns_error_response(nameserver, xfr->query->header.id,
//		                         KNOT_RCODE_SERVFAIL, xfr->wire,
//		                         &xfr->wire_size);
//		int res = xfr->send(xfr->session, &xfr->addr, xfr->wire, 
//		                    xfr->wire_size);
//		knot_packet_free(&response);
//		return res;
//	}

	ret = knot_response_init_from_query(response, xfr->query);

	if (ret != KNOT_EOK) {
		dbg_ns("Failed to init response structure.\n");
		/*! \todo xfr->wire is not NULL, will fail on assert! */
		knot_ns_error_response(nameserver, xfr->query->header.id,
		                         KNOT_RCODE_SERVFAIL, xfr->wire,
		                         &xfr->wire_size);
		int res = xfr->send(xfr->session, &xfr->addr, xfr->wire, 
		                    xfr->wire_size);
		knot_packet_free(&response);
		return res;
	}

	xfr->response = response;
	
	knot_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);
	
	const knot_dname_t *qname = knot_packet_qname(xfr->response);

	assert(knot_packet_qtype(xfr->response) == KNOT_RRTYPE_AXFR ||
	       knot_packet_qtype(xfr->response) == KNOT_RRTYPE_IXFR);

dbg_ns_exec(
	char *name_str = knot_dname_to_str(qname);
	dbg_ns("Trying to find zone with name %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	knot_zone_t *zone = knot_zonedb_find_zone(zonedb, qname);

	// if no zone found, return NotAuth
	if (zone == NULL) {
		dbg_ns("No zone found.\n");
		knot_response_set_rcode(xfr->response, KNOT_RCODE_NOTAUTH);
		ns_xfr_send_and_clear(xfr, 1);
		return KNOT_ENOZONE;
	}

dbg_ns_exec(
	char *name2_str = knot_dname_to_str(qname);
	dbg_ns("Found zone for name %s\n", name2_str);
	free(name2_str);
);
	xfr->zone = zone;
	
	return KNOT_EOK;
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

int ns_ixfr_load_serials(const knot_ns_xfr_t *xfr, uint32_t *serial_from, 
                         uint32_t *serial_to)
{
	if (xfr == NULL || xfr->zone == NULL || serial_from == NULL 
	    || serial_to == NULL) {
		dbg_ns_detail("Wrong parameters: xfr=%p,"
		             " xfr->zone = %p\n", xfr, xfr->zone);
		return KNOT_EBADARG;
	}
	
	const knot_zone_t *zone = xfr->zone;
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	if (!contents) {
		dbg_ns_detail("Missing contents\n");
		return KNOT_EBADARG;
	}
	
	if (knot_zone_contents_apex(contents) == NULL) {
		dbg_ns_detail("No apex.\n");
		return KNOT_EBADARG;
	}
	
	const knot_rrset_t *zone_soa =
		knot_node_rrset(knot_zone_contents_apex(contents),
		                  KNOT_RRTYPE_SOA);
	if (zone_soa == NULL) {
		dbg_ns_verb("No SOA.\n");
		return KNOT_EBADARG;
	}
	
	if (knot_packet_nscount(xfr->query) < 1) {
		dbg_ns_verb("No Authority record.\n");
		return KNOT_EMALF;
	}
	
	if (knot_packet_authority_rrset(xfr->query, 0) == NULL) {
		dbg_ns_verb("Authority record missing.\n");
		return KNOT_ERROR;
	}
	
	// retrieve origin (xfr) serial and target (zone) serial
	*serial_to = knot_rdata_soa_serial(knot_rrset_rdata(zone_soa));
	*serial_from = knot_rdata_soa_serial(knot_rrset_rdata(
			knot_packet_authority_rrset(xfr->query, 0)));
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_xfr_send_error(const knot_nameserver_t *nameserver,
                           knot_ns_xfr_t *xfr, knot_rcode_t rcode)
{
	/*! \todo Handle TSIG errors differently. */
	knot_response_set_rcode(xfr->response, rcode);
	
	/*! \todo Probably rename the function. */
	int ret = 0;
	if ((ret = ns_xfr_send_and_clear(xfr, 1)) != KNOT_EOK) {
		size_t size = 0;
		knot_ns_error_response(nameserver, xfr->query->header.id,
		                       KNOT_RCODE_SERVFAIL, xfr->wire, &size);
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire, size);
	}
	
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_axfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || nameserver == NULL || xfr->zone == NULL) {
		return KNOT_EBADARG;
	}
	
	rcu_read_lock();
	
	// take the contents and answer from them
	int ret = 0;
	knot_zone_contents_t *contents = knot_zone_get_contents(xfr->zone);
	if (!contents) {
		dbg_ns("AXFR failed on stub zone\n");
		/*! \todo replace with knot_ns_xfr_send_error() */
		knot_ns_error_response(nameserver, xfr->query->header.id,
					 KNOT_RCODE_SERVFAIL, xfr->wire,
					 &xfr->wire_size);
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire,
				xfr->wire_size);
		rcu_read_unlock();
		knot_packet_free(&xfr->response);
		return ret;
	}
	
	/*!
	 * \todo [TSIG] The TSIG data should already be stored in 'xfr'.
	 *       Now just count the expected size of the TSIG RR and save it
	 *       to the response structure.
	 */
	
	/*! \todo [TSIG] Get the TSIG size from some API function. */
	if (xfr->tsig_size > 0) {
		dbg_ns_detail("Setting TSIG size in packet: %zu\n",
		              xfr->tsig_size);
		knot_packet_set_tsig_size(xfr->response, xfr->tsig_size);
	}

	ret = ns_axfr_from_zone(contents, xfr);

	/*! \todo Somehow distinguish when it makes sense to send the SERVFAIL
	 *        and when it does not. E.g. if there was problem in sending
	 *        packet, it will probably fail when sending the SERVFAIL also.
	 */
	if (ret < 0 && ret != KNOT_ECONN) {
		dbg_ns("AXFR failed, sending SERVFAIL.\n");
		// now only one type of error (SERVFAIL), later maybe more
		/*! \todo xfr->wire is not NULL, will fail on assert! */
		/*! \todo replace with knot_ns_xfr_send_error() */
		knot_ns_error_response(nameserver, xfr->query->header.id,
		                         KNOT_RCODE_SERVFAIL, xfr->wire,
		                         &xfr->wire_size);
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire, 
		                xfr->wire_size);
	} else if (ret > 0) {
		ret = KNOT_ERROR;
	}

	rcu_read_unlock();

	knot_packet_free(&xfr->response);

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_ixfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	if (nameserver == NULL || xfr == NULL || xfr->zone == NULL
	    || xfr->response == NULL) {
		return KNOT_EBADARG;
	}

	//uint8_t *wire = NULL;
	//size_t size = xfr->wire_size;
	
	// parse rest of the packet (we need the Authority record)
	int ret = knot_packet_parse_rest(xfr->query);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the packet. Reply FORMERR.\n");
		knot_ns_xfr_send_error(nameserver, xfr, KNOT_RCODE_FORMERR);
		knot_packet_free(&xfr->response);
		return ret;
	}

	// check if the zone has contents
	if (knot_zone_contents(xfr->zone) == NULL) {
		dbg_ns("Zone expired or not bootstrapped. Reply SERVFAIL.\n");
		ret = knot_ns_xfr_send_error(nameserver, xfr, KNOT_RCODE_SERVFAIL);
		knot_packet_free(&xfr->response);
		return ret;
	}
	
	/*!
	 * \todo [TSIG] The TSIG data should already be stored in 'xfr'.
	 *       Now just count the expected size of the TSIG RR and save it
	 *       to the response structure. This should be optional, only if
	 *       the request contained TSIG, i.e. if there is the data in 'xfr'.
	 */
	
	/*! \todo [TSIG] Get the TSIG size from some API function. */
	if (xfr->tsig_size > 0) {
		knot_packet_set_tsig_size(xfr->response, xfr->tsig_size);
	}
	
	ret = ns_ixfr(xfr);

//	/*! \todo Somehow distinguish when it makes sense to send the SERVFAIL
//	 *        and when it does not. E.g. if there was problem in sending
//	 *        packet, it will probably fail when sending the SERVFAIL also.
//	 */
//	if (ret < 0) {
//		dbg_ns("IXFR failed, sending SERVFAIL.\n");
//		// now only one type of error (SERVFAIL), later maybe more
//		knot_ns_xfr_send_error(nameserver, xfr, KNOT_RCODE_SERVFAIL);
//	}

	knot_packet_free(&xfr->response);

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_axfrin(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	/*!
	 * \todo [TSIG] Here we assume that 'xfr' contains TSIG information
	 *       and the digest of the query sent to the master or the previous
	 *       digest.
	 */
	
	dbg_ns("ns_process_axfrin: incoming packet, wire size: %zu\n",
	              xfr->wire_size);

	int ret = xfrin_process_axfr_packet(/*xfr->wire, xfr->wire_size,*/
	                             /*(xfrin_constructed_zone_t **)(&xfr->data)*/
	                                    xfr);

	if (ret > 0) { // transfer finished
		dbg_ns("ns_process_axfrin: AXFR finished, zone created.\n");
		/*
		 * Adjust zone so that node count is set properly and nodes are
		 * marked authoritative / delegation point.
		 */
		xfrin_constructed_zone_t *constr_zone = 
				(xfrin_constructed_zone_t *)xfr->data;
		knot_zone_contents_t *zone = constr_zone->contents;
		assert(zone != NULL);

		/* Create and fill hash table */
		dbg_ns("ns_process_axfrin: filling hash table.\n");
		int rc = knot_zone_contents_create_and_fill_hash_table(zone);
		if (rc != KNOT_EOK) {
			return KNOT_ERROR;	// TODO: change error code
		}

		dbg_ns("ns_process_axfrin: adjusting zone.\n");
		rc = knot_zone_contents_adjust(zone);
		if (rc != KNOT_EOK) {
			return rc;
		}

		dbg_ns("ns_process_axfrin: checking loops.\n");
		rc = knot_zone_contents_check_loops(zone);
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

		//knot_zone_contents_dump(zone, 0);

		// check zone integrity
dbg_xfrin_exec(
		int errs = knot_zone_contents_integrity_check(zone);
		dbg_xfrin("Zone integrity check: %d errors.\n", errs);
);
	}
	
	/*!
	 * \todo In case of error, shouldn't the zone be destroyed here?
	 */
	
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_switch_zone(knot_nameserver_t *nameserver, 
                          knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || nameserver == NULL || xfr->new_contents == NULL) {
		return KNOT_EBADARG;
	}
	
	knot_zone_contents_t *zone = (knot_zone_contents_t *)xfr->new_contents;
	
	dbg_ns("Replacing zone by new one: %p\n", zone);
	if (zone == NULL) {
		dbg_ns("No new zone!\n");
		return KNOT_ENOZONE;
	}

	// find the zone in the zone db
	knot_zone_t *z = knot_zonedb_find_zone(nameserver->zone_db,
			knot_node_owner(knot_zone_contents_apex(zone)));
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

	int ret = xfrin_switch_zone(z, zone, xfr->type);

dbg_ns_exec(
	dbg_ns("Zone db contents: (zone count: %zu)\n",
		      nameserver->zone_db->zone_count);

	const knot_zone_t **zones = knot_zonedb_zones(nameserver->zone_db);
	for (int i = 0; i < knot_zonedb_zone_count
	     (nameserver->zone_db); i++) {
		dbg_ns("%d. zone: %p", i, zones[i]);
		char *name = knot_dname_to_str(zones[i]->name);
		dbg_ns("    zone name: %s\n", name);
		free(name);
	}
	free(zones);
);

	return ret;
}

/*----------------------------------------------------------------------------*/
/*! \todo In this function, xfr->zone is properly set. If this is so, we do not
 *        have to search for the zone after the transfer has finished.
 */
int knot_ns_process_ixfrin(knot_nameserver_t *nameserver, 
                             knot_ns_xfr_t *xfr)
{
	dbg_ns("ns_process_ixfrin: incoming packet\n");
	
	/*!
	 * \todo [TSIG] Here we assume that 'xfr' contains TSIG information
	 *       and the digest of the query sent to the master or the previous
	 *       digest.
	 */

	int ret = xfrin_process_ixfr_packet(xfr);
	
	if (ret == XFRIN_RES_FALLBACK) {
		dbg_ns("ns_process_ixfrin: Fallback to AXFR.\n");
		knot_free_changesets((knot_changesets_t **)&xfr->data);
		knot_packet_free(&xfr->query);
		return KNOT_ENOIXFR;
	}
	
	if (ret > 0) {
		dbg_ns("ns_process_ixfrin: IXFR finished\n");

		knot_changesets_t *chgsets = (knot_changesets_t *)xfr->data;
		if (chgsets == NULL || chgsets->first_soa == NULL) {
			// nothing to be done??
			dbg_ns("No changesets created for incoming IXFR!\n");
			return ret;
		}

		// find zone associated with the changesets
		knot_zone_t *zone = knot_zonedb_find_zone(
		                 nameserver->zone_db,
		                 knot_rrset_owner(chgsets->first_soa));
		if (zone == NULL) {
			dbg_ns("No zone found for incoming IXFR!\n");
			knot_free_changesets(
				(knot_changesets_t **)(&xfr->data));
			return KNOT_ENOZONE;  /*! \todo Other error code? */
		}
		
		switch (ret) {
		case XFRIN_RES_COMPLETE:
			xfr->zone = zone;
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
			
			if (ns_serial_compare(knot_rdata_soa_serial(
			      knot_rrset_rdata(chgsets->first_soa)),
			      knot_rdata_soa_serial(knot_rrset_rdata(zone_soa)))
			    > 0) {
				if ((xfr->flags & XFR_FLAG_UDP) > 0) {
					// IXFR over UDP
					dbg_ns("Update did not fit.\n");
					return KNOT_EIXFRSPACE;
				} else {
					// fallback to AXFR
					dbg_ns("ns_process_ixfrin: "
					       "Fallback to AXFR.\n");
					knot_free_changesets(
					      (knot_changesets_t **)&xfr->data);
					knot_packet_free(&xfr->query);
					return KNOT_ENOIXFR;
				}

			} else {
				// free changesets
				dbg_ns("No update needed.\n");
				knot_free_changesets(
					(knot_changesets_t **)(&xfr->data));
				return KNOT_ENOXFR;
			}
		} break;
		}
	}
	
	/*!
	 * \todo In case of error, shouldn't the zone be destroyed here?
	 */
	
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_update(knot_nameserver_t *nameserver, knot_packet_t *query,
                           uint8_t *response_wire, size_t *rsize,
                           knot_zone_t **zone, knot_changeset_t **changeset)
{
	// 1) Parse the rest of the packet
	assert(knot_packet_is_query(query));

	knot_packet_t *response;
	assert(*rsize >= MAX_UDP_PAYLOAD);
	int ret = knot_ns_prepare_response(nameserver, query, &response,
	                                   MAX_UDP_PAYLOAD);
	if (ret != KNOT_EOK) {
		knot_ns_error_response(nameserver, knot_packet_id(query),
		                       KNOT_RCODE_SERVFAIL, response_wire,
		                       rsize);
		return KNOT_EOK;
	}

	assert(response != NULL);

	dbg_ns("Query - parsed: %zu, total wire size: %zu\n",
	              query->parsed, query->size);

	if (knot_packet_parsed(query) < knot_packet_size(query)) {
		ret = knot_packet_parse_rest(query);
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to parse rest of the query: "
			              "%s.\n", knot_strerror(ret));
			knot_ns_error_response_full(nameserver, response,
			                            (ret == KNOT_EMALF)
			                               ? KNOT_RCODE_FORMERR
			                               : KNOT_RCODE_SERVFAIL,
			                            response_wire, rsize);
			knot_packet_free(&response);
			return KNOT_EOK;
		}
	}

	dbg_ns("Query - parsed: %zu, total wire size: %zu\n",
	              knot_packet_parsed(query), knot_packet_size(query));

	/*! \todo API for EDNS values. */
	dbg_ns("Opt RR: version: %d, payload: %d\n",
	              query->opt_rr.version, query->opt_rr.payload);

	// 2) Find zone for the query
	// we do not check if there is only one entry in the Question section
	// because the packet structure does not allow it
	/*! \todo Check number of Question entries while parsing. */
	if (knot_packet_qtype(query) != KNOT_RRTYPE_SOA) {
		dbg_ns("Question is not of type SOA.\n");
		knot_ns_error_response_full(nameserver, response,
		                            KNOT_RCODE_FORMERR,
		                            response_wire, rsize);
		knot_packet_free(&response);
		return KNOT_EOK;
	}

	*zone = knot_zonedb_find_zone(nameserver->zone_db,
	                            knot_packet_qname(query));
	if (*zone == NULL) {
		dbg_ns("Zone not found for the update.\n");
		knot_ns_error_response_full(nameserver, response,
		                            KNOT_RCODE_NOTAUTH,
		                            response_wire, rsize);
		knot_packet_free(&response);
		return KNOT_EOK;
	}

	uint8_t rcode = 0;
	// 3) Check zone
	ret = knot_ddns_check_zone(*zone, query, &rcode);
	if (ret == KNOT_EBADZONE) {
		// zone is slave, forward the request
		/*! \todo Implement forwarding. */
		return KNOT_EBADZONE;
	} else if (ret != KNOT_EOK) {
		dbg_ns("Failed to check zone for update: "
		              "%s.\n", knot_strerror(ret));
		knot_ns_error_response_full(nameserver, response, rcode,
		                            response_wire, rsize);
		knot_packet_free(&response);
		return KNOT_EOK;
	}

	// 4) Convert prerequisities
	knot_ddns_prereq_t *prereqs = NULL;
	ret = knot_ddns_process_prereqs(query, &prereqs, &rcode);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to check zone for update: "
		              "%s.\n", knot_strerror(ret));
		knot_ns_error_response_full(nameserver, response, rcode,
		                            response_wire, rsize);
		knot_packet_free(&response);
		return KNOT_EOK;
	}

	assert(prereqs != NULL);

	// 5) Check prerequisities
	/*! \todo Somehow ensure the zone will not be changed until the update
	 *        is finished.
	 */
	ret = knot_ddns_check_prereqs(knot_zone_contents(*zone), &prereqs,
	                              &rcode);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to check zone for update: "
		              "%s.\n", knot_strerror(ret));
		knot_ns_error_response_full(nameserver, response, rcode,
		                            response_wire, rsize);
		knot_ddns_prereqs_free(&prereqs);
		knot_packet_free(&response);
		return KNOT_EOK;
	}

	// 6) Convert update to changeset
	ret = knot_ddns_process_update(query, changeset, &rcode);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to check zone for update: "
		              "%s.\n", knot_strerror(ret));
		knot_ns_error_response_full(nameserver, response, rcode,
		                            response_wire, rsize);
		knot_ddns_prereqs_free(&prereqs);
		knot_packet_free(&response);
		return KNOT_EOK;
	}

	assert(changeset != NULL);

	// 7) Create response
	dbg_ns("Update converted successfuly.\n");

	/*! \todo No response yet. Distinguish somehow in the caller.
	 *        Maybe only this case will be EOK, other cases some error.
	 */

	knot_ddns_prereqs_free(&prereqs);
	knot_packet_free(&response);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_create_forward_query(const knot_packet_t *query,
                                 uint8_t *query_wire, size_t *size)
{
	// just copy the wireformat of the query and set a new random ID to it
	if (knot_packet_size(query) > *size) {
		return KNOT_ESPACE;
	}

	memcpy(query_wire, knot_packet_wireformat(query),
	       knot_packet_size(query));
	*size = knot_packet_size(query);

	knot_wire_set_id(query_wire, knot_random_id());

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_forward_response(const knot_packet_t *response,
                                     uint16_t original_id,
                                     uint8_t *response_wire, size_t *size)
{
	// just copy the wireformat of the response and set the original ID

	if (knot_packet_size(response) > *size) {
		return KNOT_ESPACE;
	}

	memcpy(response_wire, knot_packet_wireformat(response),
	       knot_packet_size(response));
	*size = knot_packet_size(response);

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

	free((*nameserver)->err_response);
	if ((*nameserver)->opt_rr != NULL) {
		knot_edns_free(&(*nameserver)->opt_rr);
	}

	// destroy the zone db
	knot_zonedb_deep_free(&(*nameserver)->zone_db);

	free(*nameserver);
	*nameserver = NULL;
}
