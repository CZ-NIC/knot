#include <config.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <urcu.h>

#include "knot/common.h"
#include "knot/server/name-server.h"
#include "knot/stat/stat.h"
#include "dnslib/dnslib.h"
#include "dnslib/debug.h"
#include "knot/other/error.h"
#include "knot/server/zones.h"

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
static const dnslib_zone_t *ns_get_zone_for_qname(dnslib_zonedb_t *zdb,
                                                  const dnslib_dname_t *qname,
                                                  uint16_t qtype)
{
	const dnslib_zone_t *zone;
	/*
	 * Find a zone in which to search.
	 *
	 * In case of DS query, we strip the leftmost label when searching for
	 * the zone (but use whole qname in search for the record), as the DS
	 * records are only present in a parent zone.
	 */
	if (qtype == DNSLIB_RRTYPE_DS) {
		/*
		 * TODO: optimize!!!
		 *  1) do not copy the name!
		 */
		dnslib_dname_t *name = dnslib_dname_left_chop(qname);
		zone = dnslib_zonedb_find_zone_for_name(zdb, name);
		dnslib_dname_free(&name);
	} else {
		zone = dnslib_zonedb_find_zone_for_name(zdb, qname);
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
static dnslib_rrset_t *ns_synth_from_wildcard(
	const dnslib_rrset_t *wildcard_rrset, const dnslib_dname_t *qname)
{
	debug_ns("Synthetizing RRSet from wildcard...\n");

	dnslib_dname_t *owner = dnslib_dname_copy(qname);

	dnslib_rrset_t *synth_rrset = dnslib_rrset_new(
			owner, dnslib_rrset_type(wildcard_rrset),
			dnslib_rrset_class(wildcard_rrset),
			dnslib_rrset_ttl(wildcard_rrset));

	if (synth_rrset == NULL) {
		dnslib_dname_free(&owner);
		return NULL;
	}

	debug_ns("Created RRSet header:\n");
	dnslib_rrset_dump(synth_rrset, 1);

	// copy all RDATA
	const dnslib_rdata_t *rdata = dnslib_rrset_rdata(wildcard_rrset);
	while (rdata != NULL) {
		// we could use the RDATA from the wildcard rrset
		// but there is no way to distinguish it when deleting
		// temporary RRSets
		dnslib_rdata_t *rdata_copy = dnslib_rdata_copy(rdata,
		                                dnslib_rrset_type(synth_rrset));
		if (rdata_copy == NULL) {
			dnslib_rrset_deep_free(&synth_rrset, 1, 0);
			return NULL;
		}

		debug_ns("Copied RDATA:\n");
		dnslib_rdata_dump(rdata_copy,
		                  dnslib_rrset_type(synth_rrset), 1);

		dnslib_rrset_add_rdata(synth_rrset, rdata_copy);
		rdata = dnslib_rrset_rdata_next(wildcard_rrset, rdata);
	}

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
static void ns_check_wildcard(const dnslib_dname_t *name,
                              dnslib_response_t *resp,
                              const dnslib_rrset_t **rrset)
{
	if (dnslib_dname_is_wildcard((*rrset)->owner)) {
		dnslib_rrset_t *synth_rrset =
			ns_synth_from_wildcard(*rrset, name);
		debug_ns("Synthetized RRSet:\n");
		dnslib_rrset_dump(synth_rrset, 1);
		dnslib_response_add_tmp_rrset(resp, synth_rrset);
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
 * \return DNSLIB_ENOMEM
 * \return DNSLIB_ESPACE
 */
static int ns_add_rrsigs(const dnslib_rrset_t *rrset, dnslib_response_t *resp,
                         const dnslib_dname_t *name,
                         int (*add_rrset_to_resp)(dnslib_response_t *,
                                                   const dnslib_rrset_t *,
                                                   int, int),
                         int tc)
{
	const dnslib_rrset_t *rrsigs;

	debug_ns("Adding RRSIGs for RRSet, type: %s.\n",
		 dnslib_rrtype_to_string(dnslib_rrset_type(rrset)));

	assert(resp != NULL);
	assert(add_rrset_to_resp != NULL);

	if (DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp)
	    && (rrsigs = dnslib_rrset_rrsigs(rrset)) != NULL) {
		ns_check_wildcard(name, resp, &rrsigs);
		return add_rrset_to_resp(resp, rrsigs, tc, 0);
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
static void ns_follow_cname(const dnslib_node_t **node,
                            const dnslib_dname_t **qname,
                            dnslib_response_t *resp,
                            int (*add_rrset_to_resp)(dnslib_response_t *,
                                                     const dnslib_rrset_t *,
                                                     int, int),
                            int tc)
{
	debug_ns("Resolving CNAME chain...\n");
	const dnslib_rrset_t *cname_rrset;

	while (*node != NULL
	       && (cname_rrset = dnslib_node_rrset(*node, DNSLIB_RRTYPE_CNAME))
	          != NULL) {
		/* put the CNAME record to answer, but replace the possible
		   wildcard name with qname */

		assert(cname_rrset != NULL);

		const dnslib_rrset_t *rrset = cname_rrset;

		// ignoring other than the first record
		if (dnslib_dname_is_wildcard(dnslib_node_owner(*node))) {
			/* if wildcard node, we must copy the RRSet and
			   replace its owner */
			rrset = ns_synth_from_wildcard(cname_rrset, *qname);
			dnslib_response_add_tmp_rrset(resp,
			                              (dnslib_rrset_t *)rrset);
		}

		add_rrset_to_resp(resp, rrset, tc, 0);
		ns_add_rrsigs(rrset, resp, *qname, add_rrset_to_resp, tc);
DEBUG_NS(
		char *name = dnslib_dname_to_str(dnslib_rrset_owner(rrset));
		debug_ns("CNAME record for owner %s put to response.\n",
			 name);
		free(name);
);

		// get the name from the CNAME RDATA
		const dnslib_dname_t *cname = dnslib_rdata_cname_name(
				dnslib_rrset_rdata(rrset));
		// change the node to the node of that name
		(*node) = dnslib_dname_node(cname);

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
 * \param type Type of the RRSet(s). If set to DNSLIB_RRTYPE_ANY, all RRSets
 *             from the node will be added to the answer.
 * \param resp Response where to add the RRSets.
 *
 * \return Number of RRSets added.
 */
static int ns_put_answer(const dnslib_node_t *node, const dnslib_dname_t *name,
                          uint16_t type, dnslib_response_t *resp)
{
	int added = 0;
DEBUG_NS(
	char *name_str = dnslib_dname_to_str(node->owner);
	debug_ns("Putting answers from node %s.\n", name_str);
	free(name_str);
);

	switch (type) {
	case DNSLIB_RRTYPE_ANY: {
		debug_ns("Returning all RRTYPES.\n");
		const dnslib_rrset_t **rrsets = dnslib_node_rrsets(node);
		if (rrsets == NULL) {
			break;
		}
		int i = 0;
		int ret = 0;
		const dnslib_rrset_t *rrset;
		while (i < dnslib_node_rrset_count(node)) {
			assert(rrsets[i] != NULL);
			rrset = rrsets[i];

			debug_ns("  Type: %s\n",
			     dnslib_rrtype_to_string(dnslib_rrset_type(rrset)));

			ns_check_wildcard(name, resp, &rrset);
			ret = dnslib_response_add_rrset_answer(resp, rrset, 1,
			                                       0);
			if (ret >= 0 && (added += 1)
			    && (ret = ns_add_rrsigs(rrset, resp, name,
			           dnslib_response_add_rrset_answer, 1)) >=0 ) {
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
	case DNSLIB_RRTYPE_RRSIG: {
		debug_ns("Returning all RRSIGs.\n");
		const dnslib_rrset_t **rrsets = dnslib_node_rrsets(node);
		if (rrsets == NULL) {
			break;
		}
		int i = 0;
		int ret = 0;
		const dnslib_rrset_t *rrset;
		while (i < dnslib_node_rrset_count(node)) {
			assert(rrsets[i] != NULL);
			rrset = dnslib_rrset_rrsigs(rrsets[i]);

			ns_check_wildcard(name, resp, &rrset);
			ret = dnslib_response_add_rrset_answer(resp, rrset, 1,
			                                       0);

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
		const dnslib_rrset_t *rrset = dnslib_node_rrset(node, type);
		const dnslib_rrset_t *rrset2 = rrset;
		if (rrset != NULL) {
			debug_ns("Found RRSet of type %s\n",
				 dnslib_rrtype_to_string(type));
			ns_check_wildcard(name, resp, &rrset2);
			ret = dnslib_response_add_rrset_answer(resp, rrset2, 1,
			                                       0);
			if (ret >= 0 && (added += 1)
			    && (ret = ns_add_rrsigs(rrset, resp, name,
			        dnslib_response_add_rrset_answer, 1)) > 0) {
				added += 1;
			}
		}
	    }
	}

	dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
	return added;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds RRSets to Additional section of the response.
 *
 * This function uses dnslib_rdata_get_name() to get the domain name from the
 * RDATA of the RRSet according to its type. It also does not search for the
 * retrieved domain name, but just uses its node field. Thus to work correctly,
 * the zone where the RRSet is from should be adjusted using
 * dnslib_zone_adjust_dnames().
 *
 * A and AAAA RRSets (and possible CNAMEs) for the found domain names are added.
 *
 * \warning Use this function only with types containing some domain name,
 *          otherwise it will crash (or behave strangely).
 *
 * \param resp Response where to add the Additional data.
 * \param rrset RRSet to get the Additional data for.
 */
static void ns_put_additional_for_rrset(dnslib_response_t *resp,
                                        const dnslib_rrset_t *rrset)
{
	const dnslib_node_t *node = NULL;
	const dnslib_rdata_t *rdata = NULL;
	const dnslib_dname_t *dname = NULL;

	// for all RRs in the RRset
	rdata = dnslib_rrset_rdata(rrset);
	while (rdata != NULL) {
		debug_ns("Getting name from RDATA, type %s..\n",
			 dnslib_rrtype_to_string(dnslib_rrset_type(rrset)));
		dname = dnslib_rdata_get_name(rdata,
		                              dnslib_rrset_type(rrset));
		assert(dname != NULL);
		node = dnslib_dname_node(dname);

		if (node != NULL && node->owner != dname) {
			// the stored node should be the closest encloser
			assert(dnslib_dname_is_subdomain(dname, node->owner));
			// try the wildcard child, if any
			node = dnslib_node_wildcard_child(node);
		}

		const dnslib_rrset_t *rrset_add;

		if (node != NULL) {
DEBUG_NS(
			char *name = dnslib_dname_to_str(node->owner);
			debug_ns("Putting additional from node %s\n", name);
			free(name);
);
			debug_ns("Checking CNAMEs...\n");
			if (dnslib_node_rrset(node, DNSLIB_RRTYPE_CNAME)
			    != NULL) {
				debug_ns("Found CNAME in node, following...\n");
				const dnslib_dname_t *dname
						= dnslib_node_owner(node);
				ns_follow_cname(&node, &dname, resp,
				    dnslib_response_add_rrset_additional, 0);
			}

			// A RRSet
			debug_ns("A RRSets...\n");
			rrset_add = dnslib_node_rrset(node, DNSLIB_RRTYPE_A);
			if (rrset_add != NULL) {
				debug_ns("Found A RRsets.\n");
				const dnslib_rrset_t *rrset_add2 = rrset_add;
				ns_check_wildcard(dname, resp, &rrset_add2);
				dnslib_response_add_rrset_additional(
					resp, rrset_add2, 0, 1);
				ns_add_rrsigs(rrset_add, resp, dname,
				       dnslib_response_add_rrset_additional, 0);
			}

			// AAAA RRSet
			debug_ns("AAAA RRSets...\n");
			rrset_add = dnslib_node_rrset(node, DNSLIB_RRTYPE_AAAA);
			if (rrset_add != NULL) {
				debug_ns("Found AAAA RRsets.\n");
				const dnslib_rrset_t *rrset_add2 = rrset_add;
				ns_check_wildcard(dname, resp, &rrset_add2);
				dnslib_response_add_rrset_additional(
					resp, rrset_add2, 0, 1);
				ns_add_rrsigs(rrset_add, resp, dname,
				       dnslib_response_add_rrset_additional, 0);
			}
		}

		assert(rrset != NULL);
		assert(rdata != NULL);
		rdata = dnslib_rrset_rdata_next(rrset, rdata);
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
	return (qtype == DNSLIB_RRTYPE_MX ||
	        qtype == DNSLIB_RRTYPE_NS ||
		qtype == DNSLIB_RRTYPE_SRV);
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
static void ns_put_additional(dnslib_response_t *resp)
{
        debug_ns("ADDITIONAL SECTION PROCESSING\n");

	const dnslib_rrset_t *rrset = NULL;

	for (int i = 0; i < dnslib_response_answer_rrset_count(resp); ++i) {
		rrset = dnslib_response_answer_rrset(resp, i);
		assert(rrset != NULL);
		if (ns_additional_needed(dnslib_rrset_type(rrset))) {
			ns_put_additional_for_rrset(resp, rrset);
		}
	}

	for (int i = 0; i < dnslib_response_authority_rrset_count(resp); ++i) {
		rrset = dnslib_response_authority_rrset(resp, i);
		if (ns_additional_needed(dnslib_rrset_type(rrset))) {
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
static void ns_put_authority_ns(const dnslib_zone_t *zone,
                                dnslib_response_t *resp)
{
	const dnslib_rrset_t *ns_rrset =
		dnslib_node_rrset(zone->apex, DNSLIB_RRTYPE_NS);
	assert(ns_rrset != NULL);

	dnslib_response_add_rrset_authority(resp, ns_rrset, 0, 1);
	ns_add_rrsigs(ns_rrset, resp, zone->apex->owner,
	              dnslib_response_add_rrset_authority, 1);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts SOA RRSet to the Auhority section of the response.
 *
 * \param zone Zone to take the SOA RRSet from.
 * \param resp Response where to add the RRSet.
 */
static void ns_put_authority_soa(const dnslib_zone_t *zone,
                                 dnslib_response_t *resp)
{
	const dnslib_rrset_t *soa_rrset =
		dnslib_node_rrset(zone->apex, DNSLIB_RRTYPE_SOA);
	assert(soa_rrset != NULL);

	dnslib_response_add_rrset_authority(resp, soa_rrset, 0, 0);
	ns_add_rrsigs(soa_rrset, resp, zone->apex->owner,
	              dnslib_response_add_rrset_authority, 1);
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
static dnslib_dname_t *ns_next_closer(const dnslib_dname_t *closest_encloser,
                                      const dnslib_dname_t *name)
{
	int ce_labels = dnslib_dname_label_count(closest_encloser);
	int qname_labels = dnslib_dname_label_count(name);

	assert(ce_labels < qname_labels);

	// the common labels should match
	assert(dnslib_dname_matched_labels(closest_encloser, name)
	       == ce_labels);

	// chop some labels from the qname
	dnslib_dname_t *next_closer = dnslib_dname_copy(name);
	if (next_closer == NULL) {
		return NULL;
	}

	for (int i = 0; i < (qname_labels - ce_labels - 1); ++i) {
		dnslib_dname_left_chop_no_copy(next_closer);
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
static void ns_put_nsec3_from_node(const dnslib_node_t *node,
                                   dnslib_response_t *resp)
{
	assert(DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp));

	const dnslib_rrset_t *rrset = dnslib_node_rrset(node,
	                                                DNSLIB_RRTYPE_NSEC3);
	assert(rrset != NULL);

	int res = dnslib_response_add_rrset_authority(resp, rrset, 1, 1);
	// add RRSIG for the RRSet
	if (res == 0 && (rrset = dnslib_rrset_rrsigs(rrset)) != NULL) {
		dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
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
static int ns_put_covering_nsec3(const dnslib_zone_t *zone,
                                 const dnslib_dname_t *name,
                                 dnslib_response_t *resp)
{
	const dnslib_node_t *prev, *node;
	int match = dnslib_zone_find_nsec3_for_name(zone, name,
	                                            &node, &prev);

	if (match == DNSLIB_ZONE_NAME_FOUND){
		// run-time collision => SERVFAIL
		return NS_ERR_SERVFAIL;
	}

DEBUG_NS(
	char *name = dnslib_dname_to_str(prev->owner);
	debug_ns("Covering NSEC3 node: %s\n", name);
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
static int ns_put_nsec3_closest_encloser_proof(const dnslib_zone_t *zone,
                                         const dnslib_node_t **closest_encloser,
                                         const dnslib_dname_t *qname,
                                         dnslib_response_t *resp)
{
	assert(zone != NULL);
	assert(closest_encloser != NULL);
	assert(*closest_encloser != NULL);
	assert(qname != NULL);
	assert(resp != NULL);

	if (dnslib_zone_nsec3params(zone) == NULL) {
DEBUG_NS(
		char *name = dnslib_dname_to_str(zone->apex->owner);
		debug_ns("No NSEC3PARAM found in zone %s.\n", name);
		free(name);
);
		return KNOT_EOK;
	}

DEBUG_NS(
	char *name = dnslib_dname_to_str((*closest_encloser)->owner);
	debug_ns("Closest encloser: %s\n", name);
	free(name);
);

	/*
	 * 1) NSEC3 that matches closest provable encloser.
	 */
	const dnslib_node_t *nsec3_node = NULL;
	const dnslib_dname_t *next_closer = NULL;
	while ((nsec3_node = dnslib_node_nsec3_node((*closest_encloser)))
	       == NULL) {
		next_closer = dnslib_node_owner((*closest_encloser));
		*closest_encloser = dnslib_node_parent(*closest_encloser);
		assert(*closest_encloser != NULL);
	}

	assert(nsec3_node != NULL);

DEBUG_NS(
	char *name = dnslib_dname_to_str((*closest_encloser)->owner);
	debug_ns("Closest provable encloser: %s\n", name);
	free(name);
	if (next_closer != NULL) {
		name = dnslib_dname_to_str(next_closer);
		debug_ns("Next closer name: %s\n", name);
		free(name);
	} else {
		debug_ns("Next closer name: none\n");
	}
);

	ns_put_nsec3_from_node(nsec3_node, resp);

	/*
	 * 2) NSEC3 that covers the "next closer" name.
	 */
	int ret = 0;
	if (next_closer == NULL) {
		// create the "next closer" name by appending from qname
		next_closer = ns_next_closer((*closest_encloser)->owner, qname);

		if (next_closer == NULL) {
			return NS_ERR_SERVFAIL;
		}
DEBUG_NS(
		char *name = dnslib_dname_to_str(next_closer);
		debug_ns("Next closer name: %s\n", name);
		free(name);
);
		ret = ns_put_covering_nsec3(zone, next_closer, resp);

		// the cast is ugly, but no better way around it
		dnslib_dname_free((dnslib_dname_t **)&next_closer);
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
static dnslib_dname_t *ns_wildcard_child_name(const dnslib_dname_t *name)
{
	assert(name != NULL);

	dnslib_dname_t *wildcard = dnslib_dname_new_from_str("*", 1, NULL);
	if (wildcard == NULL) {
		return NULL;
	}

	if (dnslib_dname_cat(wildcard, name) == NULL) {
		dnslib_dname_free(&wildcard);
		return NULL;
	}

DEBUG_NS(
	char *name = dnslib_dname_to_str(wildcard);
	debug_ns("Wildcard: %s\n", name);
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
static int ns_put_nsec3_no_wildcard_child(const dnslib_zone_t *zone,
                                          const dnslib_node_t *node,
                                          dnslib_response_t *resp)
{
	assert(node != NULL);
	assert(resp != NULL);
	assert(node->owner != NULL);

	int ret = 0;
	dnslib_dname_t *wildcard = ns_wildcard_child_name(node->owner);
	if (wildcard == NULL) {
		ret = NS_ERR_SERVFAIL;
	} else {
		ret = ns_put_covering_nsec3(zone, wildcard, resp);
		dnslib_dname_free(&wildcard);
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
static void ns_put_nsec_nsec3_nodata(const dnslib_node_t *node,
                                     dnslib_response_t *resp)
{
	if (!DNSSEC_ENABLED || !dnslib_response_dnssec_requested(resp)) {
		return;
	}

	const dnslib_node_t *nsec3_node = dnslib_node_nsec3_node(node);
	const dnslib_rrset_t *rrset = NULL;
	if ((rrset = dnslib_node_rrset(node, DNSLIB_RRTYPE_NSEC)) != NULL
	    || (nsec3_node != NULL && (rrset =
	         dnslib_node_rrset(nsec3_node, DNSLIB_RRTYPE_NSEC3)) != NULL)) {
		dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
		// add RRSIG for the RRSet
		if ((rrset = dnslib_rrset_rrsigs(rrset)) != NULL) {
			dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
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
static int ns_put_nsec_nxdomain(const dnslib_dname_t *qname,
                                const dnslib_zone_t *zone,
                                const dnslib_node_t *previous,
                                const dnslib_node_t *closest_encloser,
                                dnslib_response_t *resp)
{
	const dnslib_rrset_t *rrset = NULL;

	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {
		previous = dnslib_zone_find_previous(zone, qname);
		assert(previous != NULL);
	}

	// 1) NSEC proving that there is no node with the searched name
	rrset = dnslib_node_rrset(previous, DNSLIB_RRTYPE_NSEC);
	if (rrset == NULL) {
		// no NSEC records
		return NS_ERR_SERVFAIL;
	}

	dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
	rrset = dnslib_rrset_rrsigs(rrset);
	assert(rrset != NULL);
	dnslib_response_add_rrset_authority(resp, rrset, 1, 0);

	// 2) NSEC proving that there is no wildcard covering the name
	// this is only different from 1) if the wildcard would be
	// before 'previous' in canonical order, i.e. we can
	// search for previous until we find name lesser than wildcard
	assert(closest_encloser != NULL);

	dnslib_dname_t *wildcard =
		ns_wildcard_child_name(closest_encloser->owner);
	if (wildcard == NULL) {
		return NS_ERR_SERVFAIL;
	}

	const dnslib_node_t *prev_new = previous;

	while (dnslib_dname_compare(dnslib_node_owner(prev_new),
				    wildcard) > 0) {
		debug_ns("Previous node: %s\n",
		    dnslib_dname_to_str(dnslib_node_owner(prev_new)));
		assert(prev_new != zone->apex);
		prev_new = dnslib_node_previous(prev_new);
	}
	assert(dnslib_dname_compare(dnslib_node_owner(prev_new),
	                            wildcard) < 0);

	debug_ns("Previous node: %s\n",
	    dnslib_dname_to_str(dnslib_node_owner(prev_new)));

	dnslib_dname_free(&wildcard);

	if (prev_new != previous) {
		rrset = dnslib_node_rrset(prev_new, DNSLIB_RRTYPE_NSEC);
		assert(rrset != NULL);
		dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
		rrset = dnslib_rrset_rrsigs(rrset);
		assert(rrset != NULL);
		dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
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
 * \retval KNOT_OK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec3_nxdomain(const dnslib_zone_t *zone,
                                 const dnslib_node_t *closest_encloser,
                                 const dnslib_dname_t *qname,
                                 dnslib_response_t *resp)
{
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
 * \retval KNOT_OK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec_nsec3_nxdomain(const dnslib_zone_t *zone,
                                      const dnslib_node_t *previous,
                                      const dnslib_node_t *closest_encloser,
                                      const dnslib_dname_t *qname,
                                      dnslib_response_t *resp)
{
	int ret = 0;
	if (DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp)) {
		if (dnslib_zone_nsec3_enabled(zone)) {
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
static int ns_put_nsec3_wildcard(const dnslib_zone_t *zone,
                                 const dnslib_node_t *closest_encloser,
                                 const dnslib_dname_t *qname,
                                 dnslib_response_t *resp)
{
	assert(closest_encloser != NULL);
	assert(qname != NULL);
	assert(resp != NULL);
	assert(DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp));

	/*
	 * NSEC3 that covers the "next closer" name.
	 */
	// create the "next closer" name by appending from qname
	dnslib_dname_t *next_closer =
		ns_next_closer(closest_encloser->owner, qname);

	if (next_closer == NULL) {
		return NS_ERR_SERVFAIL;
	}
DEBUG_NS(
	char *name = dnslib_dname_to_str(next_closer);
	debug_ns("Next closer name: %s\n", name);
	free(name);
);
	int ret = ns_put_covering_nsec3(zone, next_closer, resp);

	// the cast is ugly, but no better way around it
	dnslib_dname_free(&next_closer);

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
static void ns_put_nsec_wildcard(const dnslib_zone_t *zone,
                                 const dnslib_dname_t *qname,
                                 const dnslib_node_t *previous,
                                 dnslib_response_t *resp)
{
	assert(DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp));

	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {
		previous = dnslib_zone_find_previous(zone, qname);
		assert(previous != NULL);
	}

	const dnslib_rrset_t *rrset =
		dnslib_node_rrset(previous, DNSLIB_RRTYPE_NSEC);
	if (rrset != NULL) {
		// NSEC proving that there is no node with the searched name
		dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
		rrset = dnslib_rrset_rrsigs(rrset);
		assert(rrset != NULL);
		dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
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
static int ns_put_nsec_nsec3_wildcard_nodata(const dnslib_node_t *node,
                                          const dnslib_node_t *closest_encloser,
                                          const dnslib_node_t *previous,
                                          const dnslib_zone_t *zone,
                                          const dnslib_dname_t *qname,
                                          dnslib_response_t *resp)
{
	int ret = KNOT_EOK;
	if (DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp)) {
		if (dnslib_zone_nsec3_enabled(zone)) {
			ret = ns_put_nsec3_closest_encloser_proof(zone,
			                                      &closest_encloser,
			                                      qname, resp);

			const dnslib_node_t *nsec3_node;
			if (ret == 0
			    && (nsec3_node = dnslib_node_nsec3_node(node))
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
static int ns_put_nsec_nsec3_wildcard_answer(const dnslib_node_t *node,
                                          const dnslib_node_t *closest_encloser,
                                          const dnslib_node_t *previous,
                                          const dnslib_zone_t *zone,
                                          const dnslib_dname_t *qname,
                                          dnslib_response_t *resp)
{
	int r = KNOT_EOK;
	if (DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp)
	    && dnslib_dname_is_wildcard(dnslib_node_owner(node))) {
		if (dnslib_zone_nsec3_enabled(zone)) {
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
static inline int ns_referral(const dnslib_node_t *node,
                              const dnslib_zone_t *zone,
                              const dnslib_dname_t *qname,
                              dnslib_response_t *resp)
{
	debug_ns("Referral response.\n");

	while (!dnslib_node_is_deleg_point(node)) {
		assert(node->parent != NULL);
		node = node->parent;
	}

	const dnslib_rrset_t *rrset = dnslib_node_rrset(node, DNSLIB_RRTYPE_NS);
	assert(rrset != NULL);

	// TODO: wildcards??
	//ns_check_wildcard(name, resp, &rrset);

	dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
	ns_add_rrsigs(rrset, resp, node->owner,
	              dnslib_response_add_rrset_authority, 1);

	int ret = KNOT_EOK;
	// add DS records
	debug_ns("DNSSEC requested: %d\n",
		 dnslib_response_dnssec_requested(resp));
	debug_ns("DS records: %p\n", dnslib_node_rrset(node, DNSLIB_RRTYPE_DS));
	if (DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp)) {
		rrset = dnslib_node_rrset(node, DNSLIB_RRTYPE_DS);
		if (rrset != NULL) {
			dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
			ns_add_rrsigs(rrset, resp, node->owner,
			              dnslib_response_add_rrset_authority, 1);
		} else {
			// no DS, add NSEC3
			const dnslib_node_t *nsec3_node =
				dnslib_node_nsec3_node(node);
			debug_ns("There is no DS, putting NSEC3s...\n");
			if (nsec3_node != NULL) {
				debug_ns("Putting NSEC3s from the node.\n");
				ns_put_nsec3_from_node(nsec3_node, resp);
			} else {
				debug_ns("Putting Opt-Out NSEC3s.\n");
				// no NSEC3 (probably Opt-Out)
				// TODO: check if the zone is Opt-Out
				ret = ns_put_nsec3_closest_encloser_proof(zone,
					&node, qname, resp);
			}
		}
	}

	if (ret == KNOT_EOK) {
		ns_put_additional(resp);
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
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
static int ns_answer_from_node(const dnslib_node_t *node,
                               const dnslib_node_t *closest_encloser,
                               const dnslib_node_t *previous,
                               const dnslib_zone_t *zone,
                               const dnslib_dname_t *qname, uint16_t qtype,
                               dnslib_response_t *resp)
{
	debug_ns("Putting answers from found node to the response...\n");
	int answers = ns_put_answer(node, qname, qtype, resp);

	int ret = KNOT_EOK;
	if (answers == 0) {  // if NODATA response, put SOA
		if (dnslib_node_rrset_count(node) == 0) {
			// node is an empty non-terminal => NSEC for NXDOMAIN
			//assert(dnslib_node_rrset_count(closest_encloser) > 0);
			ret = ns_put_nsec_nsec3_nxdomain(zone,
				dnslib_node_previous(node), closest_encloser,
				qname, resp);
		} else {
			ns_put_nsec_nsec3_nodata(node, resp);
			if (dnslib_dname_is_wildcard(node->owner)) {
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
static dnslib_rrset_t *ns_cname_from_dname(const dnslib_rrset_t *dname_rrset,
                                           const dnslib_dname_t *qname)
{
	debug_ns("Synthetizing CNAME from DNAME...\n");

	// create new CNAME RRSet

	dnslib_dname_t *owner = dnslib_dname_copy(qname);
	if (owner == NULL) {
		return NULL;
	}

	dnslib_rrset_t *cname_rrset = dnslib_rrset_new(
		owner, DNSLIB_RRTYPE_CNAME, DNSLIB_CLASS_IN, SYNTH_CNAME_TTL);

	if (cname_rrset == NULL) {
		dnslib_dname_free(&owner);
		return NULL;
	}

	// replace last labels of qname with DNAME
	dnslib_dname_t *cname = dnslib_dname_replace_suffix(qname,
	      dnslib_dname_size(dnslib_rrset_owner(dname_rrset)),
	      dnslib_rdata_get_item(dnslib_rrset_rdata(dname_rrset), 0)->dname);
DEBUG_NS(
	char *name = dnslib_dname_to_str(cname);
	debug_ns("CNAME canonical name: %s.\n", name);
	free(name);
);
	dnslib_rdata_t *cname_rdata = dnslib_rdata_new();
	dnslib_rdata_item_t cname_rdata_item;
	cname_rdata_item.dname = cname;
	dnslib_rdata_set_items(cname_rdata, &cname_rdata_item, 1);

	dnslib_rrset_add_rdata(cname_rrset, cname_rdata);

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
static int ns_dname_is_too_long(const dnslib_rrset_t *dname_rrset,
                                const dnslib_dname_t *qname)
{
	// TODO: add function for getting DNAME target
	if (dnslib_dname_label_count(qname)
	        - dnslib_dname_label_count(dnslib_rrset_owner(dname_rrset))
	        + dnslib_dname_label_count(dnslib_rdata_get_item(
	                             dnslib_rrset_rdata(dname_rrset), 0)->dname)
	        > DNSLIB_MAX_DNAME_LENGTH) {
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
static void ns_process_dname(const dnslib_rrset_t *dname_rrset,
                             const dnslib_dname_t *qname,
                             dnslib_response_t *resp)
{
DEBUG_NS(
	char *name = dnslib_dname_to_str(dnslib_rrset_owner(dname_rrset));
	debug_ns("Processing DNAME for owner %s...\n", name);
	free(name);
);
	// TODO: check the number of RRs in the RRSet??

	// put the DNAME RRSet into the answer
	dnslib_response_add_rrset_answer(resp, dname_rrset, 1, 0);
	ns_add_rrsigs(dname_rrset, resp, qname,
	              dnslib_response_add_rrset_answer, 1);

	if (ns_dname_is_too_long(dname_rrset, qname)) {
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_YXDOMAIN);
		return;
	}

	// synthetize CNAME (no way to tell that client supports DNAME)
	dnslib_rrset_t *synth_cname = ns_cname_from_dname(dname_rrset, qname);
	// add the synthetized RRSet to the Answer
	dnslib_response_add_rrset_answer(resp, synth_cname, 1, 0);

	// no RRSIGs for this RRSet

	// add the synthetized RRSet into list of temporary RRSets of response
	dnslib_response_add_tmp_rrset(resp, synth_cname);

	// do not search for the name in new zone (out-of-bailiwick)
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds DNSKEY RRSet from the apex of a zone to the response.
 *
 * \param apex Zone apex node.
 * \param resp Response.
 */
static void ns_add_dnskey(const dnslib_node_t *apex, dnslib_response_t *resp)
{

	const dnslib_rrset_t *rrset =
		dnslib_node_rrset(apex, DNSLIB_RRTYPE_DNSKEY);
	if (rrset != NULL) {
		dnslib_response_add_rrset_additional(resp, rrset, 0, 0);
		ns_add_rrsigs(rrset, resp, apex->owner,
			      dnslib_response_add_rrset_additional, 0);
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
static int ns_answer_from_zone(const dnslib_zone_t *zone,
                               const dnslib_dname_t *qname, uint16_t qtype,
                               dnslib_response_t *resp)
{
	const dnslib_node_t *node = NULL, *closest_encloser = NULL,
	                    *previous = NULL;
	int cname = 0, auth_soa = 0, ret = 0, find_ret = 0;

search:
#ifdef USE_HASH_TABLE
	find_ret = dnslib_zone_find_dname_hash(zone, qname, &node,
	                                       &closest_encloser);
#else
	find_ret = dnslib_zone_find_dname(zone, qname, &node,
	                                  &closest_encloser, &previous);
#endif
	if (find_ret == DNSLIB_EBADARG) {
		return NS_ERR_SERVFAIL;
	}

DEBUG_NS(
	char *name;
	if (node) {
		name = dnslib_dname_to_str(node->owner);
		debug_ns("zone_find_dname() returned node %s ", name);
		free(name);
	} else {
		debug_ns("zone_find_dname() returned no node,");
	}

	if (closest_encloser != NULL) {
		name = dnslib_dname_to_str(closest_encloser->owner);
		debug_ns(" closest encloser %s.\n", name);
		free(name);
	} else {
		debug_ns(" closest encloser (nil).\n");
	}
	if (previous != NULL) {
		name = dnslib_dname_to_str(previous->owner);
		debug_ns(" and previous node: %s.\n", name);
		free(name);
	} else {
		debug_ns(" and previous node: (nil).\n");
	}
);
	if (find_ret == DNSLIB_EBADZONE) {
		// possible only if we followed cname
		assert(cname != 0);
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
		auth_soa = 1;
		dnslib_response_set_aa(resp);
		goto finalize;
	}

have_node:
	debug_ns("Closest encloser is deleg. point? %s\n",
		 (dnslib_node_is_deleg_point(closest_encloser)) ? "yes" : "no");

	debug_ns("Closest encloser is non authoritative? %s\n",
		 (dnslib_node_is_non_auth(closest_encloser)) ? "yes" : "no");

	if (dnslib_node_is_deleg_point(closest_encloser)
	    || dnslib_node_is_non_auth(closest_encloser)) {
		ret = ns_referral(closest_encloser, zone, qname, resp);
		goto finalize;
	}

	if (find_ret == DNSLIB_ZONE_NAME_NOT_FOUND) {
		// DNAME?
		const dnslib_rrset_t *dname_rrset = dnslib_node_rrset(
		                         closest_encloser, DNSLIB_RRTYPE_DNAME);
		if (dname_rrset != NULL) {
			ns_process_dname(dname_rrset, qname, resp);
			auth_soa = 1;
			dnslib_response_set_aa(resp);
			goto finalize;
		}
		// else check for a wildcard child
		const dnslib_node_t *wildcard_node =
			dnslib_node_wildcard_child(closest_encloser);

		if (wildcard_node == NULL) {
			debug_ns("No wildcard node. (cname: %d)\n",
				 cname);
			auth_soa = 1;
			if (cname == 0) {
				debug_ns("Setting NXDOMAIN RCODE.\n");
				// return NXDOMAIN
				dnslib_response_set_rcode(resp,
					DNSLIB_RCODE_NXDOMAIN);
				if (ns_put_nsec_nsec3_nxdomain(zone, previous,
					closest_encloser, qname, resp) != 0) {
					return NS_ERR_SERVFAIL;
				}
			} else {
				dnslib_response_set_rcode(resp,
					DNSLIB_RCODE_NOERROR);
			}
			dnslib_response_set_aa(resp);
			goto finalize;
		}
		// else set the node from which to take the answers to wild.node
		node = wildcard_node;
	}

	// now we have the node for answering
	if (dnslib_node_is_deleg_point(node) || dnslib_node_is_non_auth(node)) {
		ret = ns_referral(node, zone, qname, resp);
		goto finalize;
	}

	if (dnslib_node_rrset(node, DNSLIB_RRTYPE_CNAME) != NULL) {
DEBUG_NS(
		char *name = dnslib_dname_to_str(node->owner);
		debug_ns("Node %s has CNAME record, resolving...\n",
		         name);
		free(name);
);
		const dnslib_dname_t *act_name = qname;
		ns_follow_cname(&node, &act_name, resp,
		                dnslib_response_add_rrset_answer, 1);
DEBUG_NS(
		char *name2 = dnslib_dname_to_str(act_name);
		debug_ns("Canonical name: %s, node found: %p\n",
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
			find_ret = DNSLIB_ZONE_NAME_NOT_FOUND;
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
	dnslib_response_set_aa(resp);
	dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);

	// this is the only case when the servers answers from
	// particular node, i.e. the only case when it may return SOA
	// or NS records in Answer section
	if (DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp)
	    && node == zone->apex
	    && (qtype == DNSLIB_RRTYPE_SOA || qtype == DNSLIB_RRTYPE_NS)) {
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
static int ns_answer(dnslib_zonedb_t *db, dnslib_response_t *resp)
{
	const dnslib_dname_t *qname = dnslib_response_qname(resp);
	uint16_t qtype = dnslib_response_qtype(resp);
DEBUG_NS(
	char *name_str = dnslib_dname_to_str(qname);
	debug_ns("Trying to find zone for QNAME %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	const dnslib_zone_t *zone =
		ns_get_zone_for_qname(db, qname, qtype);

	// if no zone found, return REFUSED
	if (zone == NULL) {
		debug_ns("No zone found.\n");
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_REFUSED);
		//dnslib_dname_free(&qname);
		return KNOT_EOK;
	}
DEBUG_NS(
	char *name_str2 = dnslib_dname_to_str(zone->apex->owner);
	debug_ns("Found zone for QNAME %s\n", name_str2);
	free(name_str2);
);
	return ns_answer_from_zone(zone, qname, qtype, resp);

	//dnslib_dname_free(&qname);
}

/*----------------------------------------------------------------------------*/

typedef struct ns_axfr_params {
	ns_xfr_t *xfr;
	int ret;
} ns_axfr_params_t;

/*----------------------------------------------------------------------------*/

static void ns_axfr_from_node(dnslib_node_t *node, void *data)
{
	assert(node != NULL);
	assert(data != NULL);

	ns_axfr_params_t *params = (ns_axfr_params_t *)data;

	if (params->ret != KNOT_EOK) {
		// just skip (will be called on next node with the same params
		debug_ns("Params contain error, skipping node...\n");
		return;
	}

	debug_ns("Params OK, answering AXFR from node %p.\n", node);

	dnslib_rrset_t **rrsets = dnslib_node_get_rrsets(node);
	if (rrsets == NULL) {
		params->ret = KNOT_ENOMEM;
		return;
	}

	/*
	 * Copy-paste
	 */
//	int i = 0;
//	int ret = 0;
//	const dnslib_rrset_t *rrset;
//	while (i < dnslib_node_rrset_count(node)) {
//		assert(rrsets[i] != NULL);
//		rrset = rrsets[i];

//		debug_ns("  Type: %s\n",
//		     dnslib_rrtype_to_string(dnslib_rrset_type(rrset)));

//		ns_check_wildcard(name, resp, &rrset);
//		ret = dnslib_response_add_rrset_answer(resp, rrset, 1,
//						       0);
//		if (ret >= 0 && (added += 1)
//		    && (ret = ns_add_rrsigs(rrset, resp, name,
//			   dnslib_response_add_rrset_answer, 1)) >=0 ) {
//			added += 1;
//		} else {
//			free(rrsets);
//			rrsets = NULL;
//			break;
//		}

//		++i;
//	}
	if (rrsets != NULL) {
		free(rrsets);
	}

	/*
	 * End of copy-paste
	 */

	params->ret = KNOT_ERROR;
}

/*----------------------------------------------------------------------------*/

static int ns_axfr_from_zone(dnslib_zone_t *zone, ns_xfr_t *xfr)
{
	ns_axfr_params_t params;
	params.xfr = xfr;
	params.ret = KNOT_EOK;

	dnslib_zone_tree_apply_inorder(zone, ns_axfr_from_node, &params);

	return KNOT_ERROR;
}

/*----------------------------------------------------------------------------*/

static int ns_axfr(const dnslib_zonedb_t *zonedb, ns_xfr_t *xfr)
{
	const dnslib_dname_t *qname = dnslib_response_qname(xfr->response);

	assert(dnslib_response_qtype(xfr->response) == DNSLIB_RRTYPE_AXFR);

DEBUG_NS(
	char *name_str = dnslib_dname_to_str(qname);
	debug_ns("Trying to find zone with name %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	dnslib_zone_t *zone =
		dnslib_zonedb_find_zone(zonedb,
		                        dnslib_response_qname(xfr->response));

	// if no zone found, return NotAuth
	if (zone == NULL) {
		debug_ns("No zone found.\n");
		dnslib_response_set_rcode(xfr->response, DNSLIB_RCODE_NOTAUTH);
		return KNOT_EOK;
	}
DEBUG_NS(
	char *name_str2 = dnslib_dname_to_str(zone->apex->owner);
	debug_ns("Found zone for QNAME %s\n", name_str2);
	free(name_str2);
);
	return ns_axfr_from_zone(zone, xfr);
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
static int ns_response_to_wire(dnslib_response_t *resp, uint8_t *wire,
                               size_t *wire_size)
{
	uint8_t *rwire = NULL;
	size_t rsize = 0;
	int ret = 0;

	if ((ret = dnslib_response_to_wire(resp, &rwire, &rsize))
	     != DNSLIB_EOK) {
		log_answer_error("Error converting response packet "
		                 "to wire format (error %d).\n", ret);
		return NS_ERR_SERVFAIL;
	}

	if (rsize > *wire_size) {
		return NS_ERR_SERVFAIL;
	}

	memcpy(wire, rwire, rsize);
	*wire_size = rsize;
	//free(rwire);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

ns_nameserver_t *ns_create()
{
	ns_nameserver_t *ns = malloc(sizeof(ns_nameserver_t));
	if (ns == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	// Create zone database structure
	debug_ns("Creating Zone Database structure...\n");
	ns->zone_db = dnslib_zonedb_new();
	if (ns->zone_db == NULL) {
		ERR_ALLOC_FAILED;
		free(ns);
		return NULL;
	}

	// prepare empty response with SERVFAIL error
	dnslib_response_t *err = dnslib_response_new_empty(NULL);
	if (err == NULL) {
		ERR_ALLOC_FAILED;
		free(ns);
		return NULL;
	}

	debug_ns("Created default empty response...\n");

	dnslib_response_set_rcode(err, DNSLIB_RCODE_SERVFAIL);
	ns->err_resp_size = 0;

	debug_ns("Converting default empty response to wire format...\n");

	uint8_t *error_wire = NULL;

	if (dnslib_response_to_wire(err, &error_wire, &ns->err_resp_size)
	    != 0) {
		log_answer_error("Error while converting "
		                 "default error response to "
		                 "wire format \n");
		dnslib_response_free(&err);
		free(ns);
		return NULL;
	}

	ns->err_response = (uint8_t *)malloc(ns->err_resp_size);
	if (ns->err_response == NULL) {
		log_answer_error("Error while converting default "
		                 "error response to wire format \n");
		dnslib_response_free(&err);
		free(ns);
		return NULL;
	}

	memcpy(ns->err_response, error_wire, ns->err_resp_size);

	debug_ns("Done..\n");

	if (EDNS_ENABLED) {
		ns->opt_rr = dnslib_edns_new();
		if (ns->opt_rr == NULL) {
			log_answer_error("Error while preparing OPT RR of the"
			                 " server.\n");
			dnslib_response_free(&err);
			free(ns);
			return NULL;
		}
		dnslib_edns_set_version(ns->opt_rr, EDNS_VERSION);
		dnslib_edns_set_payload(ns->opt_rr, MAX_UDP_PAYLOAD_EDNS);
	} else {
		ns->opt_rr = NULL;
	}

	//stat
	stat_static_gath_init();
	//!stat

	dnslib_response_free(&err);

	return ns;
}

/*----------------------------------------------------------------------------*/

int ns_parse_query(const uint8_t *query_wire, size_t qsize,
                   dnslib_response_t *parsed, dnslib_query_t *type)
{
	debug_ns("ns_answer_request() called with query size %zu.\n", qsize);
	debug_ns_hex((char *)query_wire, qsize);

	if (qsize < 2) {
		return KNOT_EMALF;
	}

	// 1) create empty response
	debug_ns("Parsing query using new dnslib structure...\n");
	parsed = dnslib_response_new_empty(NULL);

	if (parsed == NULL) {
		log_answer_error("Error while creating response packet!\n");
		return DNSLIB_RCODE_SERVFAIL;
	}

	int ret = 0;

	// 2) parse the query
	if ((ret = dnslib_response_parse_query(parsed, query_wire,
	                                       qsize)) != 0) {
		log_answer_info("Error while parsing query, "
		                "dnslib error '%d'.\n",
		                ret);
		dnslib_response_free(&parsed);
		return DNSLIB_RCODE_FORMERR;
	}

	debug_ns("Query parsed.\n");
	dnslib_response_dump(parsed);

	// 3) determine the query type
	switch (dnslib_response_opcode(parsed))  {
	case DNSLIB_OPCODE_QUERY:
		switch (dnslib_response_qtype(parsed)) {
		case DNSLIB_RRTYPE_AXFR:
			*type = DNSLIB_QUERY_AXFR;
			break;
		case DNSLIB_RRTYPE_IXFR:
			*type = DNSLIB_QUERY_IXFR;
			break;
		default:
			*type = DNSLIB_QUERY_NORMAL;
		}

		break;
	case DNSLIB_OPCODE_NOTIFY:
		*type = DNSLIB_QUERY_NOTIFY;
		break;
	case DNSLIB_OPCODE_UPDATE:
		*type = DNSLIB_QUERY_UPDATE;
		break;
	default:
		return DNSLIB_RCODE_NOTIMPL;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void ns_error_response(ns_nameserver_t *nameserver, const uint8_t *query_wire,
                       uint8_t rcode, uint8_t *response_wire, size_t *rsize)
{
	memcpy(response_wire, nameserver->err_response,
	       nameserver->err_resp_size);
	// copy ID of the query
	memcpy(response_wire, query_wire, 2);
	// set the RCODE
	dnslib_packet_set_rcode(response_wire, rcode);
	*rsize = nameserver->err_resp_size;
}

/*----------------------------------------------------------------------------*/

int ns_answer_request(ns_nameserver_t *nameserver, const uint8_t *query_wire,
                      size_t qsize, uint8_t *response_wire, size_t *rsize)
{
	debug_ns("ns_answer_request() called with query size %zu.\n", qsize);
	debug_ns_hex((char *)query_wire, qsize);

	if (qsize < 2) {
		return KNOT_EMALF;
	}

	// 1) create empty response
	debug_ns("Parsing query using new dnslib structure...\n");
	dnslib_response_t *resp = dnslib_response_new_empty(nameserver->opt_rr);

	if (resp == NULL) {
		log_answer_error("Error while creating response packet!\n");
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_SERVFAIL,
		                  response_wire, rsize);
		return KNOT_EOK;
	}

	int ret = 0;

	// 2) parse the query
	if ((ret = dnslib_response_parse_query(resp, query_wire, qsize)) != 0) {
		log_answer_info("Error while parsing query, "
		                "dnslib error '%d'.\n",
		                ret);
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_FORMERR,
		                  response_wire, rsize);
		dnslib_response_free(&resp);
		return KNOT_EOK;
	}

	// NSID
	if (NSID_ENABLED && dnslib_response_nsid_requested(resp)) {
		(void)dnslib_response_add_nsid(resp, NSID_DATA, NSID_LENGTH);
	}

	debug_ns("Query parsed.\n");
	dnslib_response_dump(resp);

	// 3) get the answer for the query
	rcu_read_lock();
	dnslib_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);

	ret = ns_answer(zonedb, resp);
	if (ret != 0) {
		// now only one type of error (SERVFAIL), later maybe more
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_SERVFAIL,
		                  response_wire, rsize);
	} else {
		debug_ns("Created response packet.\n");
		dnslib_response_dump(resp);

		// 4) Transform the packet into wire format
		if (ns_response_to_wire(resp, response_wire, rsize) != 0) {
			// send back SERVFAIL (as this is our problem)
			ns_error_response(nameserver, query_wire,
			                  DNSLIB_RCODE_SERVFAIL, response_wire,
			                  rsize);
		}
	}

	dnslib_response_free(&resp);
	rcu_read_unlock();

	debug_ns("Returning response with wire size %zu\n", *rsize);
	debug_ns_hex((char *)response_wire, *rsize);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int ns_answer_normal(ns_nameserver_t *nameserver, dnslib_response_t *resp,
                     uint8_t *response_wire, size_t *rsize)
{
	// get the answer for the query
	rcu_read_lock();
	dnslib_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);

	int ret = ns_answer(zonedb, resp);
	if (ret != 0) {
		// now only one type of error (SERVFAIL), later maybe more
		ns_error_response(nameserver, resp->wireformat,
		                  DNSLIB_RCODE_SERVFAIL, response_wire, rsize);
	} else {
		debug_ns("Created response packet.\n");
		dnslib_response_dump(resp);

		// 4) Transform the packet into wire format
		if (ns_response_to_wire(resp, response_wire, rsize) != 0) {
			// send back SERVFAIL (as this is our problem)
			ns_error_response(nameserver, resp->wireformat,
			                  DNSLIB_RCODE_SERVFAIL, response_wire,
			                  rsize);
		}
	}

	//dnslib_response_free(&resp);
	rcu_read_unlock();

	debug_ns("Returning response with wire size %zu\n", *rsize);
	debug_ns_hex((char *)response_wire, *rsize);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int ns_answer_axfr(ns_nameserver_t *nameserver, ns_xfr_t *xfr)
{
	if (nameserver == NULL || xfr == NULL) {
		return KNOT_EINVAL;
	}

	// Get pointer to the zone database
	rcu_read_lock();
	dnslib_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);

	int ret = ns_axfr(zonedb, xfr);

	if (ret != KNOT_EOK) {
		// now only one type of error (SERVFAIL), later maybe more
		ns_error_response(nameserver, xfr->response->wireformat,
				  DNSLIB_RCODE_SERVFAIL, xfr->response_wire,
				  &xfr->rsize);
		ret = xfr->send(xfr->session, xfr->response_wire, xfr->rsize);
	}

	//dnslib_response_free(&resp);

	rcu_read_unlock();

	if (ret != KNOT_EOK) {
		// there was some error but there is not much to do about it
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void ns_destroy(ns_nameserver_t **nameserver)
{
	synchronize_rcu();

	free((*nameserver)->err_response);
	if ((*nameserver)->opt_rr != NULL) {
		dnslib_edns_free(&(*nameserver)->opt_rr);
	}

	// destroy the zone db
	dnslib_zonedb_deep_free(&(*nameserver)->zone_db);

	free(*nameserver);
	*nameserver = NULL;
}

/*----------------------------------------------------------------------------*/

int ns_conf_hook(const struct conf_t *conf, void *data)
{
	ns_nameserver_t *ns = (ns_nameserver_t *)data;
	debug_ns("Event: reconfiguring name server.\n");

	dnslib_zonedb_t *old_db = 0;

	int ret = zones_update_db_from_config(conf, ns, &old_db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	// Wait until all readers finish with reading the zones.
	synchronize_rcu();

	debug_ns("Nameserver's zone db: %p, old db: %p\n", ns->zone_db, old_db);

	// Delete all deprecated zones and delete the old database.
	dnslib_zonedb_deep_free(&old_db);

	return KNOT_EOK;
}

