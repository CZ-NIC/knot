#include <config.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <urcu.h>

#include "name-server.h"
#include "xfr-in.h"

#include "error.h"
#include "libknot.h"
#include "debug.h"
#include "packet.h"
#include "response2.h"
#include "query.h"
#include "consts.h"
// #include "knot/zone/zone-dump-text.h"
// #include "knot/zone/zone-dump.h"
#include "changesets.h"

/*----------------------------------------------------------------------------*/

/*! \brief Maximum UDP payload with EDNS enabled. */
static const uint16_t MAX_UDP_PAYLOAD_EDNS = 4096;
/*! \brief Maximum UDP payload with EDNS disabled. */
static const uint16_t MAX_UDP_PAYLOAD      = 512;
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
	debug_knot_ns("Synthetizing RRSet from wildcard...\n");

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

	debug_knot_ns("Created RRSet header:\n");
	knot_rrset_dump(synth_rrset, 1);

	// copy all RDATA
	const knot_rdata_t *rdata = knot_rrset_rdata(wildcard_rrset);
	while (rdata != NULL) {
		// we could use the RDATA from the wildcard rrset
		// but there is no way to distinguish it when deleting
		// temporary RRSets
		knot_rdata_t *rdata_copy = knot_rdata_deep_copy(rdata,
		                                knot_rrset_type(synth_rrset));
		if (rdata_copy == NULL) {
			knot_rrset_deep_free(&synth_rrset, 1, 1, 0);
			return NULL;
		}

		debug_knot_ns("Copied RDATA:\n");
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
                              const knot_rrset_t **rrset)
{
	assert(name != NULL);
	assert(resp != NULL);
	assert(rrset != NULL);
	assert(*rrset != NULL);

	if (knot_dname_is_wildcard((*rrset)->owner)) {
		knot_rrset_t *synth_rrset =
			ns_synth_from_wildcard(*rrset, name);
		debug_knot_ns("Synthetized RRSet:\n");
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
static int ns_add_rrsigs(const knot_rrset_t *rrset, knot_packet_t *resp,
                         const knot_dname_t *name,
                         int (*add_rrset_to_resp)(knot_packet_t *,
                                                   const knot_rrset_t *,
                                                   int, int, int),
                         int tc)
{
	const knot_rrset_t *rrsigs;

	debug_knot_ns("Adding RRSIGs for RRSet, type: %s.\n",
		 knot_rrtype_to_string(knot_rrset_type(rrset)));

	assert(resp != NULL);
	assert(add_rrset_to_resp != NULL);

	debug_knot_ns("DNSSEC requested: %d\n",
	         knot_query_dnssec_requested(knot_packet_query(resp)));
	debug_knot_ns("RRSIGS: %p\n", knot_rrset_rrsigs(rrset));

	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))
	    && (rrsigs = knot_rrset_rrsigs(rrset)) != NULL) {
		if (name != NULL) {
			ns_check_wildcard(name, resp, &rrsigs);
		}
		return add_rrset_to_resp(resp, rrsigs, tc, 0, 0);
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
                                                     const knot_rrset_t *,
                                                     int, int, int),
                            int tc)
{
	debug_knot_ns("Resolving CNAME chain...\n");
	const knot_rrset_t *cname_rrset;

	while (*node != NULL
	       && (cname_rrset = knot_node_rrset(*node, KNOT_RRTYPE_CNAME))
	          != NULL) {
		/* put the CNAME record to answer, but replace the possible
		   wildcard name with qname */

		assert(cname_rrset != NULL);

		const knot_rrset_t *rrset = cname_rrset;

		// ignoring other than the first record
		if (knot_dname_is_wildcard(knot_node_owner(*node))) {
			/* if wildcard node, we must copy the RRSet and
			   replace its owner */
			rrset = ns_synth_from_wildcard(cname_rrset, *qname);
			knot_packet_add_tmp_rrset(resp,
			                            (knot_rrset_t *)rrset);
		}

		add_rrset_to_resp(resp, rrset, tc, 0, 0);
		ns_add_rrsigs(rrset, resp, *qname, add_rrset_to_resp, tc);
DEBUG_KNOT_NS(
		char *name = knot_dname_to_str(knot_rrset_owner(rrset));
		debug_knot_ns("CNAME record for owner %s put to response.\n",
			 name);
		free(name);
);

		// get the name from the CNAME RDATA
		const knot_dname_t *cname = knot_rdata_cname_name(
				knot_rrset_rdata(rrset));
		// change the node to the node of that name
		(*node) = knot_dname_node(cname, 1);
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
DEBUG_KNOT_NS(
	char *name_str = knot_dname_to_str(node->owner);
	debug_knot_ns("Putting answers from node %s.\n", name_str);
	free(name_str);
);

	switch (type) {
	case KNOT_RRTYPE_ANY: {
		debug_knot_ns("Returning all RRTYPES.\n");
		const knot_rrset_t **rrsets = knot_node_rrsets(node);
		if (rrsets == NULL) {
			break;
		}
		int i = 0;
		int ret = 0;
		const knot_rrset_t *rrset;
		while (i < knot_node_rrset_count(node)) {
			assert(rrsets[i] != NULL);
			rrset = rrsets[i];

			debug_knot_ns("  Type: %s\n",
			     knot_rrtype_to_string(knot_rrset_type(rrset)));

			ns_check_wildcard(name, resp, &rrset);
			ret = knot_response2_add_rrset_answer(resp, rrset, 1,
			                                        0, 0);
			if (ret >= 0 && (added += 1)
			    && (ret = ns_add_rrsigs(rrset, resp, name,
			           knot_response2_add_rrset_answer, 1))
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
		debug_knot_ns("Returning all RRSIGs.\n");
		const knot_rrset_t **rrsets = knot_node_rrsets(node);
		if (rrsets == NULL) {
			break;
		}
		int i = 0;
		int ret = 0;
		const knot_rrset_t *rrset;
		while (i < knot_node_rrset_count(node)) {
			assert(rrsets[i] != NULL);
			rrset = knot_rrset_rrsigs(rrsets[i]);

			if (rrset == NULL) {
				++i;
				continue;
			}

			ns_check_wildcard(name, resp, &rrset);
			ret = knot_response2_add_rrset_answer(resp, rrset, 1,
			                                        0, 0);

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
		const knot_rrset_t *rrset = knot_node_rrset(node, type);
		const knot_rrset_t *rrset2 = rrset;
		if (rrset != NULL) {
			debug_knot_ns("Found RRSet of type %s\n",
				 knot_rrtype_to_string(type));
			ns_check_wildcard(name, resp, &rrset2);
			ret = knot_response2_add_rrset_answer(resp, rrset2, 1,
			                                        0, 0);
			if (ret >= 0 && (added += 1)
			    && (ret = ns_add_rrsigs(rrset, resp, name,
			           knot_response2_add_rrset_answer, 1)) > 0) {
				added += 1;
			}
		}
	    }
	}

	knot_response2_set_rcode(resp, KNOT_RCODE_NOERROR);
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
		debug_knot_ns("Getting name from RDATA, type %s..\n",
			 knot_rrtype_to_string(knot_rrset_type(rrset)));
		dname = knot_rdata_get_name(rdata,
		                              knot_rrset_type(rrset));
		assert(dname != NULL);
		node = knot_dname_node(dname, 1);
//		// check if the node is not old and if yes, take the new one
//		if (knot_node_is_old(node)) {
//			node = knot_node_new_node(node);
//		}

		if (node != NULL && node->owner != dname) {
			// the stored node should be the closest encloser
			assert(knot_dname_is_subdomain(dname, node->owner));
			// try the wildcard child, if any
			node = knot_node_wildcard_child(node, 1);
//			// this should not be old node!!
//			assert(!knot_node_is_old(node));
		}

		const knot_rrset_t *rrset_add;

		if (node != NULL) {
DEBUG_KNOT_NS(
			char *name = knot_dname_to_str(node->owner);
			debug_knot_ns("Putting additional from node %s\n", name);
			free(name);
);
			debug_knot_ns("Checking CNAMEs...\n");
			if (knot_node_rrset(node, KNOT_RRTYPE_CNAME)
			    != NULL) {
				debug_knot_ns("Found CNAME in node, following...\n");
				const knot_dname_t *dname
						= knot_node_owner(node);
				ns_follow_cname(&node, &dname, resp,
				    knot_response2_add_rrset_additional, 0);
			}

			// A RRSet
			debug_knot_ns("A RRSets...\n");
			rrset_add = knot_node_rrset(node, KNOT_RRTYPE_A);
			if (rrset_add != NULL) {
				debug_knot_ns("Found A RRsets.\n");
				const knot_rrset_t *rrset_add2 = rrset_add;
				ns_check_wildcard(dname, resp, &rrset_add2);
				knot_response2_add_rrset_additional(
					resp, rrset_add2, 0, 1, 0);
				ns_add_rrsigs(rrset_add, resp, dname,
				      knot_response2_add_rrset_additional, 0);
			}

			// AAAA RRSet
			debug_knot_ns("AAAA RRSets...\n");
			rrset_add = knot_node_rrset(node, KNOT_RRTYPE_AAAA);
			if (rrset_add != NULL) {
				debug_knot_ns("Found AAAA RRsets.\n");
				const knot_rrset_t *rrset_add2 = rrset_add;
				ns_check_wildcard(dname, resp, &rrset_add2);
				knot_response2_add_rrset_additional(
					resp, rrset_add2, 0, 1, 0);
				ns_add_rrsigs(rrset_add, resp, dname,
				      knot_response2_add_rrset_additional, 0);
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
	debug_knot_ns("ADDITIONAL SECTION PROCESSING\n");

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
	const knot_rrset_t *ns_rrset = knot_node_rrset(
			knot_zone_contents_apex(zone), KNOT_RRTYPE_NS);

	if (ns_rrset != NULL) {
		knot_response2_add_rrset_authority(resp, ns_rrset, 0, 1, 0);
		ns_add_rrsigs(ns_rrset, resp, knot_node_owner(
		              knot_zone_contents_apex(zone)),
	                      knot_response2_add_rrset_authority, 1);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts SOA RRSet to the Auhority section of the response.
 *
 * \param zone Zone to take the SOA RRSet from.
 * \param resp Response where to add the RRSet.
 */
static void ns_put_authority_soa(const knot_zone_contents_t *zone,
                                 knot_packet_t *resp)
{
	const knot_rrset_t *soa_rrset = knot_node_rrset(
			knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	assert(soa_rrset != NULL);

	knot_response2_add_rrset_authority(resp, soa_rrset, 0, 0, 0);
	ns_add_rrsigs(soa_rrset, resp,
	              knot_node_owner(knot_zone_contents_apex(zone)),
	              knot_response2_add_rrset_authority, 1);
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

	const knot_rrset_t *rrset = knot_node_rrset(node,
	                                                KNOT_RRTYPE_NSEC3);
	assert(rrset != NULL);

	int res = knot_response2_add_rrset_authority(resp, rrset, 1, 1, 0);
	// add RRSIG for the RRSet
	if (res == 0 && (rrset = knot_rrset_rrsigs(rrset)) != NULL) {
		knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);
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
	int match = knot_zone_contents_find_nsec3_for_name(zone, name,
	                                                     &node, &prev);
	assert(match >= 0);

	if (match == KNOT_ZONE_NAME_FOUND){
		// run-time collision => SERVFAIL
		return NS_ERR_SERVFAIL;
	}
	
//	// check if the prev node is not old and if yes, take the new one
//	if (knot_node_is_old(prev)) {
//		prev = knot_node_new_node(prev);
//		assert(prev != NULL);
//	}

DEBUG_KNOT_NS(
	char *name = knot_dname_to_str(prev->owner);
	debug_knot_ns("Covering NSEC3 node: %s\n", name);
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
DEBUG_KNOT_NS(
		char *name = knot_dname_to_str(knot_node_owner(
				knot_zone_contents_apex(zone)));
		debug_knot_ns("No NSEC3PARAM found in zone %s.\n", name);
		free(name);
);
		return KNOT_EOK;
	}

DEBUG_KNOT_NS(
	char *name = knot_dname_to_str(knot_node_owner(*closest_encloser));
	debug_knot_ns("Closest encloser: %s\n", name);
	free(name);
);

	/*
	 * 1) NSEC3 that matches closest provable encloser.
	 */
	const knot_node_t *nsec3_node = NULL;
	const knot_dname_t *next_closer = NULL;
	while ((nsec3_node = knot_node_nsec3_node((*closest_encloser), 1))
	       == NULL) {
		next_closer = knot_node_owner((*closest_encloser));
		*closest_encloser = knot_node_parent(*closest_encloser, 1);
		assert(*closest_encloser != NULL);
	}

	assert(nsec3_node != NULL);

DEBUG_KNOT_NS(
	char *name = knot_dname_to_str((*closest_encloser)->owner);
	debug_knot_ns("Closest provable encloser: %s\n", name);
	free(name);
	if (next_closer != NULL) {
		name = knot_dname_to_str(next_closer);
		debug_knot_ns("Next closer name: %s\n", name);
		free(name);
	} else {
		debug_knot_ns("Next closer name: none\n");
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
DEBUG_KNOT_NS(
		char *name = knot_dname_to_str(next_closer);
		debug_knot_ns("Next closer name: %s\n", name);
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

DEBUG_KNOT_NS(
	char *name = knot_dname_to_str(wildcard);
	debug_knot_ns("Wildcard: %s\n", name);
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

	const knot_node_t *nsec3_node = knot_node_nsec3_node(node, 1);
	const knot_rrset_t *rrset = NULL;
	if ((rrset = knot_node_rrset(node, KNOT_RRTYPE_NSEC)) != NULL
	    || (nsec3_node != NULL && (rrset =
	         knot_node_rrset(nsec3_node, KNOT_RRTYPE_NSEC3)) != NULL)) {
		knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);
		// add RRSIG for the RRSet
		if ((rrset = knot_rrset_rrsigs(rrset)) != NULL) {
			knot_response2_add_rrset_authority(resp, rrset, 1,
			                                     0, 0);
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
	/*! \todo Change to zone contents. */
	const knot_rrset_t *rrset = NULL;

	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {
		previous = knot_zone_contents_find_previous(zone, qname);
		assert(previous != NULL);
	}

	// 1) NSEC proving that there is no node with the searched name
	rrset = knot_node_rrset(previous, KNOT_RRTYPE_NSEC);
	if (rrset == NULL) {
		// no NSEC records
		return NS_ERR_SERVFAIL;
	}

	knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);
	rrset = knot_rrset_rrsigs(rrset);
	assert(rrset != NULL);
	knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);

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
		debug_knot_ns("Previous node: %s\n",
		    knot_dname_to_str(knot_node_owner(prev_new)));
		assert(prev_new != knot_zone_contents_apex(zone));
		prev_new = knot_node_previous(prev_new, 1);
	}
	assert(knot_dname_compare(knot_node_owner(prev_new),
	                            wildcard) < 0);

	debug_knot_ns("Previous node: %s\n",
	    knot_dname_to_str(knot_node_owner(prev_new)));

	/* Directly discard dname. */
	knot_dname_free(&wildcard);

	if (prev_new != previous) {
		rrset = knot_node_rrset(prev_new, KNOT_RRTYPE_NSEC);
		assert(rrset != NULL);
		knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);
		rrset = knot_rrset_rrsigs(rrset);
		assert(rrset != NULL);
		knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);
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
	/*! \todo Change to zone contents. */
	// 1) Closest encloser proof
	int ret = ns_put_nsec3_closest_encloser_proof(zone, &closest_encloser,
	                                              qname, resp);
	// 2) NSEC3 covering non-existent wildcard
	if (ret == KNOT_EOK) {
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

	/*
	 * NSEC3 that covers the "next closer" name.
	 */
	// create the "next closer" name by appending from qname
	knot_dname_t *next_closer =
		ns_next_closer(closest_encloser->owner, qname);

	if (next_closer == NULL) {
		return NS_ERR_SERVFAIL;
	}
DEBUG_KNOT_NS(
	char *name = knot_dname_to_str(next_closer);
	debug_knot_ns("Next closer name: %s\n", name);
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
	}

	const knot_rrset_t *rrset =
		knot_node_rrset(previous, KNOT_RRTYPE_NSEC);
	if (rrset != NULL) {
		// NSEC proving that there is no node with the searched name
		knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);
		rrset = knot_rrset_rrsigs(rrset);
		assert(rrset != NULL);
		knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);
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
			if (ret == 0
			    && (nsec3_node = knot_node_nsec3_node(node, 1))
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
                              knot_packet_t *resp)
{
	/*! \todo Change to zone contents. */
	debug_knot_ns("Referral response.\n");

	while (!knot_node_is_deleg_point(node)) {
		assert(knot_node_parent(node, 1) != NULL);
		node = knot_node_parent(node, 1);
	}

	const knot_rrset_t *rrset = knot_node_rrset(node, KNOT_RRTYPE_NS);
	assert(rrset != NULL);

	// TODO: wildcards??
	//ns_check_wildcard(name, resp, &rrset);

	knot_response2_add_rrset_authority(resp, rrset, 1, 0, 0);
	ns_add_rrsigs(rrset, resp, node->owner,
	              knot_response2_add_rrset_authority, 1);

	int ret = KNOT_EOK;
	// add DS records
	debug_knot_ns("DNSSEC requested: %d\n",
		 knot_query_dnssec_requested(knot_packet_query(resp)));
	debug_knot_ns("DS records: %p\n", knot_node_rrset(node, KNOT_RRTYPE_DS));
	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))) {
		rrset = knot_node_rrset(node, KNOT_RRTYPE_DS);
		if (rrset != NULL) {
			knot_response2_add_rrset_authority(resp, rrset, 1, 0,
			                                    0);
			ns_add_rrsigs(rrset, resp, node->owner,
			              knot_response2_add_rrset_authority, 1);
		} else {
			// no DS, add NSEC3
			const knot_node_t *nsec3_node =
				knot_node_nsec3_node(node, 1);
			debug_knot_ns("There is no DS, putting NSEC3s...\n");
			if (nsec3_node != NULL) {
				debug_knot_ns("Putting NSEC3s from the node.\n");
				ns_put_nsec3_from_node(nsec3_node, resp);
			} else {
				debug_knot_ns("Putting Opt-Out NSEC3s.\n");
				// no NSEC3 (probably Opt-Out)
				// TODO: check if the zone is Opt-Out
				ret = ns_put_nsec3_closest_encloser_proof(zone,
					&node, qname, resp);
			}
		}
	}

	if (ret == KNOT_EOK) {
		ns_put_additional(resp);
		knot_response2_set_rcode(resp, KNOT_RCODE_NOERROR);
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
	/*! \todo Change to zone contents. */
	debug_knot_ns("Putting answers from found node to the response...\n");
	int answers = ns_put_answer(node, qname, qtype, resp);

	int ret = KNOT_EOK;
	if (answers == 0) {  // if NODATA response, put SOA
		if (knot_node_rrset_count(node) == 0) {
			// node is an empty non-terminal => NSEC for NXDOMAIN
			//assert(knot_node_rrset_count(closest_encloser) > 0);
			ret = ns_put_nsec_nsec3_nxdomain(zone,
				knot_node_previous(node, 1), closest_encloser,
				qname, resp);
		} else {
			ns_put_nsec_nsec3_nodata(node, resp);
			if (knot_dname_is_wildcard(node->owner)) {
				ret = ns_put_nsec_nsec3_wildcard_nodata(node,
					closest_encloser, previous, zone, qname,
					resp);
			}
		}
		ns_put_authority_soa(zone, resp);
	} else {  // else put authority NS
		// if wildcard answer, add NSEC / NSEC3
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
	debug_knot_ns("Synthetizing CNAME from DNAME...\n");

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
DEBUG_KNOT_NS(
	char *name = knot_dname_to_str(cname);
	debug_knot_ns("CNAME canonical name: %s.\n", name);
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
static void ns_process_dname(const knot_rrset_t *dname_rrset,
                             const knot_dname_t *qname,
                             knot_packet_t *resp)
{
DEBUG_KNOT_NS(
	char *name = knot_dname_to_str(knot_rrset_owner(dname_rrset));
	debug_knot_ns("Processing DNAME for owner %s...\n", name);
	free(name);
);
	// TODO: check the number of RRs in the RRSet??

	// put the DNAME RRSet into the answer
	knot_response2_add_rrset_answer(resp, dname_rrset, 1, 0, 0);
	ns_add_rrsigs(dname_rrset, resp, qname,
	              knot_response2_add_rrset_answer, 1);

	if (ns_dname_is_too_long(dname_rrset, qname)) {
		knot_response2_set_rcode(resp, KNOT_RCODE_YXDOMAIN);
		return;
	}

	// synthetize CNAME (no way to tell that client supports DNAME)
	knot_rrset_t *synth_cname = ns_cname_from_dname(dname_rrset, qname);
	// add the synthetized RRSet to the Answer
	knot_response2_add_rrset_answer(resp, synth_cname, 1, 0, 0);

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
	const knot_rrset_t *rrset =
		knot_node_rrset(apex, KNOT_RRTYPE_DNSKEY);
	if (rrset != NULL) {
		knot_response2_add_rrset_additional(resp, rrset, 0, 0, 0);
		ns_add_rrsigs(rrset, resp, apex->owner,
			      knot_response2_add_rrset_additional, 0);
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
                               const knot_dname_t *qname, uint16_t qtype,
                               knot_packet_t *resp)
{
	const knot_node_t *node = NULL, *closest_encloser = NULL,
	                    *previous = NULL;
	int cname = 0, auth_soa = 0, ret = 0, find_ret = 0;

search:
#ifdef USE_HASH_TABLE
	find_ret = knot_zone_contents_find_dname_hash(zone, qname, &node,
	                                                &closest_encloser);
#else
	find_ret = knot_zone_contents_find_dname(zone, qname, &node,
	                                          &closest_encloser, &previous);
#endif
	if (find_ret == KNOT_EBADARG) {
		return NS_ERR_SERVFAIL;
	}

DEBUG_KNOT_NS(
	char *name;
	if (node) {
		name = knot_dname_to_str(node->owner);
		debug_knot_ns("zone_find_dname() returned node %s ", name);
		free(name);
	} else {
		debug_knot_ns("zone_find_dname() returned no node,");
	}

	if (closest_encloser != NULL) {
		name = knot_dname_to_str(closest_encloser->owner);
		debug_knot_ns(" closest encloser %s.\n", name);
		free(name);
	} else {
		debug_knot_ns(" closest encloser (nil).\n");
	}
	if (previous != NULL) {
		name = knot_dname_to_str(previous->owner);
		debug_knot_ns(" and previous node: %s.\n", name);
		free(name);
	} else {
		debug_knot_ns(" and previous node: (nil).\n");
	}
);
	if (find_ret == KNOT_EBADZONE) {
		// possible only if we followed cname
		assert(cname != 0);
		knot_response2_set_rcode(resp, KNOT_RCODE_NOERROR);
		auth_soa = 1;
		knot_response2_set_aa(resp);
		goto finalize;
	}

have_node:
	debug_knot_ns("Closest encloser is deleg. point? %s\n",
		 (knot_node_is_deleg_point(closest_encloser)) ? "yes" : "no");

	debug_knot_ns("Closest encloser is non authoritative? %s\n",
		 (knot_node_is_non_auth(closest_encloser)) ? "yes" : "no");

	if (knot_node_is_deleg_point(closest_encloser)
	    || knot_node_is_non_auth(closest_encloser)) {
		ret = ns_referral(closest_encloser, zone, qname, resp);
		goto finalize;
	}

	if (find_ret == KNOT_ZONE_NAME_NOT_FOUND) {
		// DNAME?
		const knot_rrset_t *dname_rrset = knot_node_rrset(
		                         closest_encloser, KNOT_RRTYPE_DNAME);
		if (dname_rrset != NULL) {
			ns_process_dname(dname_rrset, qname, resp);
			auth_soa = 1;
			knot_response2_set_aa(resp);
			goto finalize;
		}
		// else check for a wildcard child
		const knot_node_t *wildcard_node =
			knot_node_wildcard_child(closest_encloser, 1);

		if (wildcard_node == NULL) {
			debug_knot_ns("No wildcard node. (cname: %d)\n",
				 cname);
			auth_soa = 1;
			if (cname == 0) {
				debug_knot_ns("Setting NXDOMAIN RCODE.\n");
				// return NXDOMAIN
				knot_response2_set_rcode(resp,
					KNOT_RCODE_NXDOMAIN);
				if (ns_put_nsec_nsec3_nxdomain(zone, previous,
					closest_encloser, qname, resp) != 0) {
					return NS_ERR_SERVFAIL;
				}
			} else {
				knot_response2_set_rcode(resp,
					KNOT_RCODE_NOERROR);
			}
			knot_response2_set_aa(resp);
			goto finalize;
		}
		// else set the node from which to take the answers to wild.node
		node = wildcard_node;
	}

	// now we have the node for answering
	if (knot_node_is_deleg_point(node) || knot_node_is_non_auth(node)) {
		ret = ns_referral(node, zone, qname, resp);
		goto finalize;
	}

	if (knot_node_rrset(node, KNOT_RRTYPE_CNAME) != NULL) {
DEBUG_KNOT_NS(
		char *name = knot_dname_to_str(node->owner);
		debug_knot_ns("Node %s has CNAME record, resolving...\n",
		         name);
		free(name);
);
		const knot_dname_t *act_name = qname;
		ns_follow_cname(&node, &act_name, resp,
		                knot_response2_add_rrset_answer, 1);
DEBUG_KNOT_NS(
		char *name2 = knot_dname_to_str(act_name);
		debug_knot_ns("Canonical name: %s, node found: %p\n",
			 name2, node);
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
	if (ret != KNOT_EOK) {
		goto finalize;
	}
	knot_response2_set_aa(resp);
	knot_response2_set_rcode(resp, KNOT_RCODE_NOERROR);

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
static int ns_answer(knot_zonedb_t *db, knot_packet_t *resp)
{
	const knot_dname_t *qname = knot_packet_qname(resp);
	assert(qname != NULL);

	uint16_t qtype = knot_packet_qtype(resp);
DEBUG_KNOT_NS(
	char *name_str = knot_dname_to_str(qname);
	debug_knot_ns("Trying to find zone for QNAME %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	const knot_zone_t *zone =
		ns_get_zone_for_qname(db, qname, qtype);

	// if no zone found, return REFUSED
	if (zone == NULL) {
		debug_knot_ns("No zone found.\n");
		knot_response2_set_rcode(resp, KNOT_RCODE_REFUSED);
		//knot_dname_free(&qname);
		return KNOT_EOK;
	}
DEBUG_KNOT_NS(
	char *name_str2 = knot_dname_to_str(zone->contents->apex->owner);
	debug_knot_ns("Found zone for QNAME %s\n", name_str2);
	free(name_str2);
);

	// take the zone contents and use only them for answering
	const knot_zone_contents_t *contents = knot_zone_contents(zone);

	return ns_answer_from_zone(contents, qname, qtype, resp);

	//knot_dname_free(&qname);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Converts the response to wire format.
 *
 * \param resp Response to convert.
 * \param wire Place for the wire format of the response.
 * \param wire_size In: space available for the wire format in bytes.
 *                  Out: actual size of the wire format in bytes.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_response_to_wire(knot_packet_t *resp, uint8_t *wire,
                               size_t *wire_size)
{
	uint8_t *rwire = NULL;
	size_t rsize = 0;
	int ret = 0;

	if ((ret = knot_packet_to_wire(resp, &rwire, &rsize))
	     != KNOT_EOK) {
		debug_knot_ns("Error converting response packet "
		                 "to wire format (error %d).\n", ret);
		return NS_ERR_SERVFAIL;
	}

	if (rsize > *wire_size) {
		debug_knot_ns("Reponse size (%zu) larger than allowed wire size "
		         "(%zu).\n", rsize, *wire_size);
		return NS_ERR_SERVFAIL;
	}

	memcpy(wire, rwire, rsize);
	*wire_size = rsize;
	//free(rwire);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

typedef struct ns_axfr_params {
	knot_ns_xfr_t *xfr;
	int ret;
} ns_axfr_params_t;

/*----------------------------------------------------------------------------*/

static int ns_axfr_send_and_clear(knot_ns_xfr_t *xfr)
{
	assert(xfr != NULL);
	assert(xfr->query != NULL);
	assert(xfr->response != NULL);
	assert(xfr->wire != NULL);
	assert(xfr->send != NULL);

	// Transform the packet into wire format
	debug_knot_ns("Converting response to wire format..\n");
	size_t real_size;
	if (ns_response_to_wire(xfr->response, xfr->wire, &real_size)
	    != 0) {
		return NS_ERR_SERVFAIL;
//		// send back SERVFAIL (as this is our problem)
//		ns_error_response(nameserver,
//				  knot_wire_get_id(query_wire),
//				  KNOT_RCODE_SERVFAIL, response_wire,
//				  rsize);
	}

	// Send the response
	debug_knot_ns("Sending response (size %zu)..\n", real_size);
	debug_knot_ns_hex((const char *)xfr->wire, real_size);
	int res = xfr->send(xfr->session, &xfr->addr, xfr->wire, real_size);
	if (res < 0) {
		debug_knot_ns("Send returned %d\n", res);
		return res;
	} else if (res != real_size) {
		debug_knot_ns("AXFR did not send right amount of bytes."
		                   " Transfer size: %zu, sent: %d\n",
		                   real_size, res);
	}

	// Clean the response structure
	debug_knot_ns("Clearing response structure..\n");
	knot_response2_clear(xfr->response, 0);

	debug_knot_ns("Response structure after clearing:\n");
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
		debug_knot_ns("Params contain error: %s, skipping node...\n",
		              knot_strerror2(params->ret));
		return;
	}

	debug_knot_ns("Params OK, answering AXFR from node %p.\n", node);
DEBUG_KNOT_NS(
	char *name = knot_dname_to_str(knot_node_owner(node));
	debug_knot_ns("Node ownerr: %s\n", name);
	free(name);
);

	if (knot_node_rrset_count(node) == 0) {
		return;
	}

	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets == NULL) {
		params->ret = KNOT_ENOMEM;
		return;
	}

	int i = 0;
	int ret = 0;
	const knot_rrset_t *rrset = NULL;
	while (i < knot_node_rrset_count(node)) {
		assert(rrsets[i] != NULL);
		rrset = rrsets[i];
rrset:
		debug_knot_ns("  Type: %s\n",
		     knot_rrtype_to_string(knot_rrset_type(rrset)));

		// do not add SOA
		if (knot_rrset_type(rrset) == KNOT_RRTYPE_SOA) {
			++i;
			continue;
		}

		ret = knot_response2_add_rrset_answer(params->xfr->response,
		                                       rrset, 0, 0, 1);

		if (ret == KNOT_ESPACE) {
			// TODO: send the packet and clean the structure
			debug_knot_ns("Packet full, sending..\n");
			ret = ns_axfr_send_and_clear(params->xfr);
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
		rrset = knot_rrset_rrsigs(rrset);
rrsigs:
		if (rrset == NULL) {
			++i;
			continue;
		}

		ret = knot_response2_add_rrset_answer(params->xfr->response,
		                                        rrset, 0, 0, 1);

		if (ret == KNOT_ESPACE) {
			// TODO: send the packet and clean the structure
			debug_knot_ns("Packet full, sending..\n");
			ret = ns_axfr_send_and_clear(params->xfr);
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
	params.xfr = xfr;
	params.ret = KNOT_EOK;

	/*
	 * First SOA
	 */

	// retrieve SOA - must be send as first and last RR
	const knot_rrset_t *soa_rrset = knot_node_rrset(
		knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		// some really serious error
		return KNOT_ERROR;
	}

	int ret;

	// add SOA RR to the response
	ret = knot_response2_add_rrset_answer(xfr->response, soa_rrset, 0, 0,
	                                        1);
	if (ret != KNOT_EOK) {
		// something is really wrong
		return KNOT_ERROR;
	}

	// add the SOA's RRSIG
	const knot_rrset_t *rrset = knot_rrset_rrsigs(soa_rrset);
	if (rrset != NULL
	    && (ret = knot_response2_add_rrset_answer(xfr->response, rrset,
	                                              0, 0, 1)) != KNOT_EOK) {
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
	ret = knot_response2_add_rrset_answer(xfr->response, soa_rrset, 0, 0,
	                                        1);
	if (ret == KNOT_ESPACE) {
		// if there is not enough space, send the response and
		// add the SOA record to a new packet
		debug_knot_ns("Packet full, sending..\n");
		ret = ns_axfr_send_and_clear(xfr);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = knot_response2_add_rrset_answer(xfr->response,
		                                        soa_rrset, 0, 0, 1);
		if (ret != KNOT_EOK) {
			return KNOT_ERROR;
		}

	} else if (ret != KNOT_EOK) {
		// something is really wrong
		return KNOT_ERROR;
	}

	debug_knot_ns("Sending packet...\n");
	return ns_axfr_send_and_clear(xfr);
}

/*----------------------------------------------------------------------------*/

static int ns_ixfr_put_rrset(knot_ns_xfr_t *xfr, const knot_rrset_t *rrset)
{
	int res = knot_response2_add_rrset_answer(xfr->response, rrset,
	                                            0, 0, 0);
	if (res == KNOT_ESPACE) {
		knot_response2_set_rcode(xfr->response, KNOT_RCODE_NOERROR);
		/*! \todo Probably rename the function. */
		ns_axfr_send_and_clear(xfr);

		res = knot_response2_add_rrset_answer(xfr->response,
		                                        rrset, 0, 0, 0);
	}

	if (res != KNOT_EOK) {
		debug_knot_ns("Error putting origin SOA to IXFR reply: %s\n",
			 knot_strerror2(res));
		/*! \todo Probably send back AXFR instead. */
		knot_response2_set_rcode(xfr->response,
		                           KNOT_RCODE_SERVFAIL);
		/*! \todo Probably rename the function. */
		ns_axfr_send_and_clear(xfr);
		//socket_close(xfr->session);  /*! \todo Remove for UDP.*/
		return KNOT_ERROR;
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
	assert(knot_packet_additional_rrset_count(xfr->query) > 0);
	assert(xfr->data != NULL);

	/*! \todo REMOVE start */
//	const knot_rrset_t *zone_soa =
//		knot_node_rrset(knot_zone_contents_apex(
//		                       knot_zone_contents(xfr->zone)),
//		                  KNOT_RRTYPE_SOA);
//	// retrieve origin (xfr) serial and target (zone) serial
//	uint32_t zone_serial = knot_rdata_soa_serial(
//	                             knot_rrset_rdata(zone_soa));
//	uint32_t xfr_serial = knot_rdata_soa_serial(knot_rrset_rdata(
//			knot_packet_authority_rrset(xfr->query, 0)));

//	// 3) load changesets from journal
//	knot_changesets_t *chgsets = (knot_changesets_t *)
//	                               calloc(1, sizeof(knot_changesets_t));
//	int res = xfr_load_changesets(xfr->zone, chgsets, xfr_serial, 
//	                              zone_serial);
//	if (res != KNOT_EOK) {
//		debug_knot_ns("IXFR query cannot be answered: %s.\n",
//		         knot_strerror2(res));
//		/*! \todo Probably send back AXFR instead. */
//		knot_response2_set_rcode(xfr->response, KNOT_RCODE_SERVFAIL);
//		/*! \todo Probably rename the function. */
//		ns_axfr_send_and_clear(xfr);
//		//socket_close(xfr->session);  /*! \todo Remove for UDP. */
//		return 1;
//	}
	
	/*! \todo REMOVE end */
	
	knot_changesets_t *chgsets = (knot_changesets_t *)xfr->data;
	
	const knot_rrset_t *zone_soa =
		knot_node_rrset(knot_zone_contents_apex(
		                       knot_zone_contents(xfr->zone)),
		                  KNOT_RRTYPE_SOA);

	// 4) put the zone SOA as the first Answer RR
	int res = knot_response2_add_rrset_answer(xfr->response, zone_soa, 0, 
	                                            0, 0);
	if (res != KNOT_EOK) {
		debug_knot_ns("IXFR query cannot be answered: %s.\n",
			 knot_strerror2(res));
		knot_response2_set_rcode(xfr->response,
		                           KNOT_RCODE_SERVFAIL);
		/*! \todo Probably rename the function. */
		ns_axfr_send_and_clear(xfr);
//		socket_close(xfr->session);  /*! \todo Remove for UDP.*/
		return 1;
	}

	// 5) put the changesets into the response while they fit in
	for (int i = 0; i < chgsets->count; ++i) {
		res = ns_ixfr_put_changeset(xfr, &chgsets->sets[i]);
		if (res != KNOT_EOK) {
			// answer is sent, socket is closed
			return KNOT_EOK;
		}
	}

	res = ns_ixfr_put_rrset(xfr, zone_soa);

	if (res == KNOT_EOK) {
		/*! \todo Probably rename the function. */
		ns_axfr_send_and_clear(xfr);
		//socket_close(xfr->session);  /*! \todo Remove for UDP.*/
		return 1;
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
		debug_knot_ns("IXFR query does not contain authority record.\n");
		knot_response2_set_rcode(xfr->response, KNOT_RCODE_FORMERR);
		/*! \todo Probably rename the function. */
		ns_axfr_send_and_clear(xfr);
		//socket_close(xfr->session);
		return 1;
	}

	const knot_rrset_t *soa = knot_packet_authority_rrset(xfr->query,
	                                                          0);
	const knot_dname_t *qname = knot_packet_qname(xfr->response);

	// check if XFR QNAME and SOA correspond
	if (knot_packet_qtype(xfr->query) != KNOT_RRTYPE_SOA
	    || knot_rrset_type(soa) != KNOT_RRTYPE_SOA
	    || knot_dname_compare(qname, knot_rrset_owner(soa)) != 0) {
		// malformed packet
		debug_knot_ns("IXFR query is malformed.\n");
		knot_response2_set_rcode(xfr->response, KNOT_RCODE_FORMERR);
		/*! \todo Probably rename the function. */
		ns_axfr_send_and_clear(xfr);
		//socket_close(xfr->session);  /*! \todo Remove for UDP. */
		return 1;
	}

	return ns_ixfr_from_zone(xfr);
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
        ns->server = 0;

	// Create zone database structure
	debug_knot_ns("Creating Zone Database structure...\n");
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

	debug_knot_ns("Created default empty response...\n");

	int rc = knot_packet_set_max_size(err, KNOT_WIRE_HEADER_SIZE);
	if (rc != KNOT_EOK) {
		debug_knot_ns("Error creating default error response: %s.\n",
		                 knot_strerror2(rc));
		free(ns);
		knot_packet_free(&err);
		return NULL;
	}

	rc = knot_response2_init(err);
	if (rc != KNOT_EOK) {
		debug_knot_ns("Error initializing default error response:"
		                 " %s.\n", knot_strerror2(rc));
		free(ns);
		knot_packet_free(&err);
		return NULL;
	}

	knot_response2_set_rcode(err, KNOT_RCODE_SERVFAIL);
	ns->err_resp_size = 0;

	debug_knot_ns("Converting default empty response to wire format...\n");

	uint8_t *error_wire = NULL;

	if (knot_packet_to_wire(err, &error_wire, &ns->err_resp_size) != 0) {
		debug_knot_ns("Error while converting "
		                 "default error response to "
		                 "wire format \n");
		knot_packet_free(&err);
		free(ns);
		return NULL;
	}

	ns->err_response = (uint8_t *)malloc(ns->err_resp_size);
	if (ns->err_response == NULL) {
		debug_knot_ns("Error while converting default "
		                 "error response to wire format \n");
		knot_packet_free(&err);
		free(ns);
		return NULL;
	}

	memcpy(ns->err_response, error_wire, ns->err_resp_size);

	debug_knot_ns("Done..\n");

	knot_packet_free(&err);

	if (EDNS_ENABLED) {
		ns->opt_rr = knot_edns_new();
		if (ns->opt_rr == NULL) {
			debug_knot_ns("Error while preparing OPT RR of the"
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

int knot_ns_parse_packet(const uint8_t *query_wire, size_t qsize,
                    knot_packet_t *packet, knot_packet_type_t *type)
{
	if (packet == NULL || query_wire == NULL || type == NULL) {
		debug_knot_ns("Missing parameter to query parsing.\n");
		return KNOT_EBADARG;
	}

	debug_knot_ns("ns_parse_packet() called with query size %zu.\n", qsize);
	debug_knot_ns_hex((char *)query_wire, qsize);

	if (qsize < 2) {
		return KNOT_EMALF;
	}

	// 1) create empty response
	debug_knot_ns("Parsing packet...\n");
	//parsed = knot_response_new_empty(NULL);

	int ret = 0;

	if ((ret = knot_packet_parse_from_wire(packet, query_wire,
	                                         qsize, 1)) != 0) {
		debug_knot_ns("Error while parsing packet, "
		                "libknot error '%s'.\n", knot_strerror2(ret));
//		knot_response_free(&parsed);
		return KNOT_RCODE_FORMERR;
	}

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
		assert(knot_packet_is_query(packet));
		*type = KNOT_QUERY_UPDATE;
		break;
	default:
		return KNOT_RCODE_NOTIMPL;
	}

//	knot_packet_free(&packet);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_ns_error_response(knot_nameserver_t *nameserver, uint16_t query_id,
                       uint8_t rcode, uint8_t *response_wire, size_t *rsize)
{
	debug_knot_ns("Error response: \n");
	debug_knot_ns_hex((const char *)nameserver->err_response,
	             nameserver->err_resp_size);

	memcpy(response_wire, nameserver->err_response,
	       nameserver->err_resp_size);
	// copy ID of the query
	knot_wire_set_id(response_wire, query_id);
	// set the RCODE
	knot_wire_set_rcode(response_wire, rcode);
	*rsize = nameserver->err_resp_size;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_normal(knot_nameserver_t *nameserver, knot_packet_t *query,
                     uint8_t *response_wire, size_t *rsize)
{
	// first, parse the rest of the packet
	assert(knot_packet_is_query(query));
	debug_knot_ns("Query - parsed: %zu, total wire size: %zu\n", query->parsed,
	         query->size);
	int ret;

	if (query->parsed < query->size) {
		ret = knot_packet_parse_rest(query);
		if (ret != KNOT_EOK) {
			debug_knot_ns("Failed to parse rest of the query: "
			                   "%s.\n", knot_strerror2(ret));
			knot_ns_error_response(nameserver, query->header.id,
			           KNOT_RCODE_SERVFAIL, response_wire, rsize);
			return KNOT_EOK;
		}
	}

	debug_knot_ns("Query - parsed: %zu, total wire size: %zu\n", query->parsed,
	         query->size);
	debug_knot_ns("Opt RR: version: %d, payload: %d\n", query->opt_rr.version,
		 query->opt_rr.payload);

	// get the answer for the query
	rcu_read_lock();
	knot_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);

	debug_knot_ns("ns_answer_normal()\n");

	// initialize response packet structure
	knot_packet_t *response = knot_packet_new(
	                               KNOT_PACKET_PREALLOC_RESPONSE);
	if (response == NULL) {
		debug_knot_ns("Failed to create packet structure.\n");
		knot_ns_error_response(nameserver, query->header.id,
		                  KNOT_RCODE_SERVFAIL, response_wire, rsize);
		rcu_read_unlock();
		return KNOT_EOK;
	}

	ret = knot_packet_set_max_size(response, *rsize);

	if (ret != KNOT_EOK) {
		debug_knot_ns("Failed to init response structure.\n");
		knot_ns_error_response(nameserver, query->header.id,
		                  KNOT_RCODE_SERVFAIL, response_wire, rsize);
		rcu_read_unlock();
		knot_packet_free(&response);
		return KNOT_EOK;
	}

	ret = knot_response2_init_from_query(response, query);

	if (ret != KNOT_EOK) {
		debug_knot_ns("Failed to init response structure.\n");
		knot_ns_error_response(nameserver, query->header.id,
		                  KNOT_RCODE_SERVFAIL, response_wire, rsize);
		rcu_read_unlock();
		knot_packet_free(&response);
		return KNOT_EOK;
	}

	debug_knot_ns("EDNS supported in query: %d\n",
	         knot_query_edns_supported(query));

	// set the OPT RR to the response
	if (knot_query_edns_supported(query)) {
		ret = knot_response2_add_opt(response, nameserver->opt_rr, 0);
		if (ret != KNOT_EOK) {
			debug_knot_ns("Failed to set OPT RR to the response"
			                  ": %s\n",knot_strerror2(ret));
		}
	}

	ret = ns_answer(zonedb, response);
	if (ret != 0) {
		// now only one type of error (SERVFAIL), later maybe more
		knot_ns_error_response(nameserver, query->header.id,
		                  KNOT_RCODE_SERVFAIL, response_wire, rsize);
	} else {
		debug_knot_ns("Created response packet.\n");
		//knot_response_dump(resp);
		knot_packet_dump(response);

		// 4) Transform the packet into wire format
		if (ns_response_to_wire(response, response_wire, rsize) != 0) {
			// send back SERVFAIL (as this is our problem)
			knot_ns_error_response(nameserver, query->header.id,
			                  KNOT_RCODE_SERVFAIL, response_wire,
			                  rsize);
		}
	}

	rcu_read_unlock();
	knot_packet_free(&response);

	debug_knot_ns("Returning response with wire size %zu\n", *rsize);
	debug_knot_ns_hex((char *)response_wire, *rsize);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_init_xfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	debug_knot_ns("knot_ns_init_xfr()\n");

	if (nameserver == NULL || xfr == NULL) {
		return KNOT_EBADARG;
	}

	// no need to parse rest of the packet
	/*! \todo Parse rest of packet because of EDNS. */

	// initialize response packet structure
	knot_packet_t *response = knot_packet_new(
	                               KNOT_PACKET_PREALLOC_RESPONSE);
	if (response == NULL) {
		debug_knot_ns("Failed to create packet structure.\n");
		/*! \todo xfr->wire is not NULL, will fail on assert! */
		knot_ns_error_response(nameserver, xfr->query->header.id,
				  KNOT_RCODE_SERVFAIL, xfr->wire,
				  &xfr->wire_size);
		int res = xfr->send(xfr->session, &xfr->addr, xfr->wire, 
		                    xfr->wire_size);
		knot_packet_free(&response);
		return res;
	}

	int ret = knot_packet_set_max_size(response, xfr->wire_size);

	if (ret != KNOT_EOK) {
		debug_knot_ns("Failed to init response structure.\n");
		/*! \todo xfr->wire is not NULL, will fail on assert! */
		knot_ns_error_response(nameserver, xfr->query->header.id,
		                         KNOT_RCODE_SERVFAIL, xfr->wire,
		                         &xfr->wire_size);
		int res = xfr->send(xfr->session, &xfr->addr, xfr->wire, 
		                    xfr->wire_size);
		knot_packet_free(&response);
		return res;
	}

	ret = knot_response2_init_from_query(response, xfr->query);

	if (ret != KNOT_EOK) {
		debug_knot_ns("Failed to init response structure.\n");
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

	assert(knot_packet_qtype(xfr->response) == KNOT_RRTYPE_AXFR);

DEBUG_KNOT_NS(
	char *name_str = knot_dname_to_str(qname);
	debug_knot_ns("Trying to find zone with name %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	knot_zone_t *zone = knot_zonedb_find_zone(zonedb, qname);

	// if no zone found, return NotAuth
	if (zone == NULL) {
		debug_knot_ns("No zone found.\n");
		knot_response2_set_rcode(xfr->response, KNOT_RCODE_NOTAUTH);
		ns_axfr_send_and_clear(xfr);
		return KNOT_ERROR;
	}

DEBUG_KNOT_NS(
	char *name_str2 = knot_dname_to_str(zone->contents->apex->owner);
	debug_knot_ns("Found zone for QNAME %s\n", name_str2);
	free(name_str2);
);
	xfr->zone = zone;
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_xfr_send_error(knot_ns_xfr_t *xfr, knot_rcode_t rcode)
{
	knot_response2_set_rcode(xfr->response, rcode);
	/*! \todo Probably rename the function. */
	return ns_axfr_send_and_clear(xfr);
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_axfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || nameserver == NULL || xfr->zone == NULL) {
		return KNOT_EBADARG;
	}
	
	rcu_read_lock();
	
	// take the contents and answer from them
	knot_zone_contents_t *contents = knot_zone_get_contents(xfr->zone);

	int ret = ns_axfr_from_zone(contents, xfr);

	/*! \todo Somehow distinguish when it makes sense to send the SERVFAIL
	 *        and when it does not. E.g. if there was problem in sending
	 *        packet, it will probably fail when sending the SERVFAIL also.
	 */
	if (ret < 0) {
		debug_knot_ns("AXFR failed, sending SERVFAIL.\n");
		// now only one type of error (SERVFAIL), later maybe more
		/*! \todo xfr->wire is not NULL, will fail on assert! */
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

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_ixfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	if (nameserver == NULL || xfr == NULL || xfr->zone == NULL
	    || xfr->response == NULL) {
		return KNOT_EBADARG;
	}
	
	// parse rest of the packet (we need the Authority record)
	int ret = knot_packet_parse_rest(xfr->query);
	if (ret != KNOT_EOK) {
		debug_knot_ns("Failed to parse rest of the packet.\n");

		/*! \todo Extract this to some function. */
		knot_response2_set_rcode(xfr->response, KNOT_RCODE_FORMERR);
		uint8_t *wire = NULL;
		size_t size = 0;
		ret = knot_packet_to_wire(xfr->response, &wire, &size);
		if (ret != KNOT_EOK) {
			knot_ns_error_response(nameserver, 
			                         xfr->query->header.id,
			                         KNOT_RCODE_FORMERR, wire, 
			                         &size);
		}

		ret = xfr->send(xfr->session, &xfr->addr, wire, size);

		knot_packet_free(&xfr->response);
		return ret;
	}
	
	ret = ns_ixfr(xfr);

	/*! \todo Somehow distinguish when it makes sense to send the SERVFAIL
	 *        and when it does not. E.g. if there was problem in sending
	 *        packet, it will probably fail when sending the SERVFAIL also.
	 */
	if (ret < 0) {
		debug_knot_ns("IXFR failed, sending SERVFAIL.\n");
		// now only one type of error (SERVFAIL), later maybe more

		/*! \todo Extract this to some function. */
		knot_response2_set_rcode(xfr->response, KNOT_RCODE_SERVFAIL);
		uint8_t *wire = NULL;
		size_t size = 0;
		ret = knot_packet_to_wire(xfr->response, &wire, &size);
		if (ret != KNOT_EOK) {
			knot_ns_error_response(nameserver, 
			                         xfr->query->header.id,
			                         KNOT_RCODE_SERVFAIL, wire, 
			                         &size);
		}

		ret = xfr->send(xfr->session, &xfr->addr, wire, size);
	} else if (ret > 0) {
		ret = KNOT_ERROR;
	}

	knot_packet_free(&xfr->response);

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_axfrin(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	/*! \todo Implement me.
	 *  - xfr contains partially-built zone or NULL (xfr->data)
	 *  - incoming packet is in xfr->wire
	 *  - incoming packet size is in xfr->wire_size
	 *  - signalize caller, that transfer is finished/error (ret. code?)
	 */
	debug_knot_ns("ns_process_axfrin: incoming packet\n");

	int ret = xfrin_process_axfr_packet(xfr->wire, xfr->wire_size,
	                               (knot_zone_contents_t **)(&xfr->data));

	if (ret > 0) { // transfer finished
		debug_knot_ns("ns_process_axfrin: AXFR finished, zone created.\n");
		/*
		 * Adjust zone so that node count is set properly and nodes are
		 * marked authoritative / delegation point.
		 */
		knot_zone_contents_t *zone = 
				(knot_zone_contents_t *)xfr->data;

		debug_knot_ns("ns_process_axfrin: adjusting zone.\n");
		knot_zone_contents_adjust_dnames(zone);

		/* Create and fill hash table */
		debug_knot_ns("ns_process_axfrin: filling hash table.\n");
		int rc = knot_zone_contents_create_and_fill_hash_table(zone);
		if (rc != KNOT_EOK) {
			return KNOT_ERROR;	// TODO: change error code
		}

		knot_zone_contents_dump(zone, 0);
	}
	
	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_switch_zone(knot_nameserver_t *nameserver, 
                          knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || nameserver == NULL || xfr->data == NULL) {
		return KNOT_EBADARG;
	}
	
	knot_zone_contents_t *zone = (knot_zone_contents_t *)xfr->data;
	
	debug_knot_ns("Replacing zone by new one: %p\n", zone);

	// find the zone in the zone db
	knot_zone_t *z = knot_zonedb_find_zone(nameserver->zone_db,
			knot_node_owner(knot_zone_contents_apex(zone)));
	if (z == NULL) {
		char *name = knot_dname_to_str(knot_node_owner(
				knot_zone_contents_apex(zone)));
		debug_knot_ns("Failed to replace zone %s, old zone "
		                   "not found\n", name);
		free(name);
	}

	knot_zone_contents_t *old = rcu_xchg_pointer(&z->contents, zone);

//	knot_zone_t *old = knot_zonedb_replace_zone(nameserver->zone_db,
//	                                                zone);
	debug_knot_ns("Old zone: %p\n", old);
//	if (old == NULL) {
//		char *name = knot_dname_to_str(
//				knot_node_owner(knot_zone_apex(zone)));
//		debug_knot_ns("Failed to replace zone %s\n", name);
//		free(name);
//	}

	// wait for readers to finish
	debug_knot_ns("Waiting for readers to finish...\n");
	synchronize_rcu();
	// destroy the old zone
	debug_knot_ns("Freeing old zone: %p\n", old);
	knot_zone_contents_deep_free(&old);

DEBUG_KNOT_NS(
	debug_knot_ns("Zone db contents: (zone count: %zu)\n", 
	              nameserver->zone_db->zone_count);

	knot_zone_t **zones = knot_zonedb_zones(nameserver->zone_db);
	for (int i = 0; i < knot_zonedb_zone_count
	     (nameserver->zone_db); i++) {
		debug_knot_ns("%d. zone: %p", i, zones[i]);
		char *name = knot_dname_to_str(zones[i]->name);
		debug_knot_ns("    zone name: %s\n", name);
		free(name);
	}
);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_apply_ixfr_changes(knot_zone_t *zone, knot_changesets_t *chgsets)
{
	/*! \todo Apply changes to the zone when they are parsed. */
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_ixfrin(knot_nameserver_t *nameserver, 
                             knot_ns_xfr_t *xfr)
{
	/*! \todo Implement me.
	 *  - xfr contains partially-built IXFR journal entry or NULL
	 *    (xfr->data)
	 *  - incoming packet is in xfr->wire
	 *  - incoming packet size is in xfr->wire_size
	 *  - signalize caller, that transfer is finished/error (ret. code?)
	 */
	debug_knot_ns("ns_process_ixfrin: incoming packet\n");

	int ret = xfrin_process_ixfr_packet(xfr->wire, xfr->wire_size,
	                                   (knot_changesets_t **)(&xfr->data));
	
	/*! \todo Save zone into the XFR structure. */

	if (ret > 0) { // transfer finished
		debug_knot_ns("ns_process_ixfrin: IXFR finished\n");

		knot_changesets_t *chgsets = (knot_changesets_t *)xfr->data;
		if (chgsets == NULL || chgsets->count == 0) {
			// nothing to be done??
			return KNOT_EOK;
		}

		// find zone associated with the changesets
		knot_zone_t *zone = knot_zonedb_find_zone(
		                 nameserver->zone_db,
		                 knot_rrset_owner(chgsets->sets[0].soa_from));
		if (zone == NULL) {
			debug_knot_ns("No zone found for incoming IXFR!\n");
			knot_free_changesets(
				(knot_changesets_t **)(&xfr->data));
			return KNOT_ENOZONE;  /*! \todo Other error code? */
		}

//		ret = xfrin_store_changesets(zone, chgsets);
//		if (ret != KNOT_EOK) {
//			debug_knot_ns("Failed to save changesets to journal.\n");
//			xfrin_free_changesets(
//				(knot_changesets_t **)(&xfr->data));
//			return ret;
//		}

//		ret = knot_ns_apply_ixfr_changes(zone, chgsets);
//		if (ret != KNOT_EOK) {
//			debug_knot_ns("Failed to apply changes to the zone.");
//			// left the changes to be applied later..?
//			// they are already stored
//		}

//		// we may free the changesets, they are stored and maybe applied
//		xfrin_free_changesets((knot_changesets_t **)(&xfr->data));
	}
	return ret;
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
