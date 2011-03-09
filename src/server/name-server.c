#include <config.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <urcu.h>

#include "common.h"
#include "server/name-server.h"
#include "stat/stat.h"
#include "dnslib/dnslib.h"
#include "dnslib/debug.h"
#include "dnslib/edns.h"
#include "dnslib/nsec3.h"

//static const uint8_t  RCODE_MASK           = 0xf0;
static const int      OFFSET_FLAGS2        = 3;
static const size_t   RR_FIXED_SIZE        = 10;
static const size_t   QUESTION_FIXED_SIZE  = 4;
static const uint16_t MAX_UDP_PAYLOAD_EDNS = 4096;
static const uint16_t MAX_UDP_PAYLOAD      = 512;
static const uint8_t  EDNS_VERSION         = 0;
static const uint8_t  OPT_SIZE             = 11;
static const int      EDNS_ENABLED         = 1;
static const uint32_t SYNTH_CNAME_TTL      = 0;
static const int      DNSSEC_ENABLED       = 1;
static const int      NSID_ENABLED         = 1;
static const uint16_t NSID_LENGTH          = 6;
static const uint8_t  NSID_DATA[6] = {0x46, 0x6f, 0x6f, 0x42, 0x61, 0x72};
static const int      NS_ERR_SERVFAIL      = -999;

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/

static inline void ns_error_response(ns_nameserver *nameserver,
                                     const uint8_t *query_wire,
                                     uint8_t rcode,
                                     uint8_t *response_wire,
                                     size_t *rsize)
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

dnslib_rrset_t *ns_synth_from_wildcard(const dnslib_rrset_t *wildcard_rrset,
                                       const dnslib_dname_t *qname)
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

	return 0;
}

/*----------------------------------------------------------------------------*/

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
				ns_check_wildcard(dname, resp, &rrset_add);
				dnslib_response_add_rrset_additional(
					resp, rrset_add, 0, 1);
				ns_add_rrsigs(rrset_add, resp, dname,
				       dnslib_response_add_rrset_additional, 0);
			}

			// AAAA RRSet
			debug_ns("AAAA RRSets...\n");
			rrset_add = dnslib_node_rrset(node, DNSLIB_RRTYPE_AAAA);
			if (rrset_add != NULL) {
				debug_ns("Found AAAA RRsets.\n");
				ns_check_wildcard(dname, resp, &rrset_add);
				dnslib_response_add_rrset_additional(
					resp, rrset_add, 0, 1);
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

static int ns_additional_needed(uint16_t qtype)
{
	return (qtype == DNSLIB_RRTYPE_MX ||
	        qtype == DNSLIB_RRTYPE_NS ||
		qtype == DNSLIB_RRTYPE_SRV);
}

/*----------------------------------------------------------------------------*/

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

static dnslib_dname_t *ns_next_closer(const dnslib_dname_t *closest_encloser,
                                      const dnslib_dname_t *qname)
{
	int ce_labels = dnslib_dname_label_count(closest_encloser);
	int qname_labels = dnslib_dname_label_count(qname);

	assert(ce_labels < qname_labels);

	// the common labels should match
	assert(dnslib_dname_matched_labels(closest_encloser, qname)
	       == ce_labels);

	// chop some labels from the qname
	dnslib_dname_t *next_closer = dnslib_dname_copy(qname);
	if (next_closer == NULL) {
		return NULL;
	}

	for (int i = 0; i < (qname_labels - ce_labels - 1); ++i) {
		dnslib_dname_left_chop_no_copy(next_closer);
	}

	return next_closer;
}

/*----------------------------------------------------------------------------*/

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

static int ns_put_covering_nsec3(const dnslib_zone_t *zone,
                                  const dnslib_dname_t *nsec3_name,
                                  dnslib_response_t *resp)
{
	const dnslib_node_t *prev, *node;
	int match = dnslib_zone_find_nsec3_for_name(zone, nsec3_name,
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

	return 0;
}

/*----------------------------------------------------------------------------*/

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
		return 0;
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
		return 1;
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

	return 0;
}

/*----------------------------------------------------------------------------*/

static int ns_put_nsec3_nxdomain(const dnslib_zone_t *zone,
                                 const dnslib_node_t *closest_encloser,
                                 const dnslib_dname_t *qname,
                                 dnslib_response_t *resp)
{
	// 1) Closest encloser proof
	int ret = ns_put_nsec3_closest_encloser_proof(zone, &closest_encloser,
	                                              qname, resp);
	// 2) NSEC3 covering non-existent wildcard
	if (ret == 0) {
		ret = ns_put_nsec3_no_wildcard_child(zone, closest_encloser,
		                                     resp);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

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

static void ns_put_nsec_wildcard(const dnslib_zone_t *zone,
                                 const dnslib_dname_t *qname,
                                 const dnslib_node_t *node,
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

static int ns_put_nsec_nsec3_wildcard_nodata(const dnslib_node_t *node,
                                          const dnslib_node_t *closest_encloser,
                                          const dnslib_node_t *previous,
                                          const dnslib_zone_t *zone,
                                          const dnslib_dname_t *qname,
                                          dnslib_response_t *resp)
{
	int ret = 0;
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
			ns_put_nsec_wildcard(zone, qname, node, previous, resp);
		}
	}
	return ret;
}

/*----------------------------------------------------------------------------*/

static int ns_put_nsec_nsec3_wildcard_answer(const dnslib_node_t *node,
                                          const dnslib_node_t *closest_encloser,
                                          const dnslib_node_t *previous,
                                          const dnslib_zone_t *zone,
                                          const dnslib_dname_t *qname,
                                          dnslib_response_t *resp)
{
	int r = 0;
	if (DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp)
	    && dnslib_dname_is_wildcard(dnslib_node_owner(node))) {
		if (dnslib_zone_nsec3_enabled(zone)) {
			r = ns_put_nsec3_wildcard(zone, closest_encloser, qname,
			                          resp);
		} else {
			ns_put_nsec_wildcard(zone, qname, node, previous, resp);
		}
	}
	return r;
}

/*----------------------------------------------------------------------------*/

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

	const dnslib_rrset_t *rrset =
		dnslib_node_rrset(node, DNSLIB_RRTYPE_NS);
	assert(rrset != NULL);

	// TODO: wildcards??
	//ns_check_wildcard(name, resp, &rrset);

	dnslib_response_add_rrset_authority(resp, rrset, 1, 0);
	ns_add_rrsigs(rrset, resp, node->owner,
	              dnslib_response_add_rrset_authority, 1);

	int ret = 0;
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

	if (ret == 0) {
		ns_put_additional(resp);
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
	}
	return ret;
}

/*----------------------------------------------------------------------------*/

static int ns_answer_from_node(const dnslib_node_t *node,
                               const dnslib_node_t *closest_encloser,
                               const dnslib_node_t *previous,
                               const dnslib_zone_t *zone,
                               const dnslib_dname_t *qname, uint16_t qtype,
                               dnslib_response_t *resp)
{
	debug_ns("Putting answers from found node to the response...\n");
	int answers = ns_put_answer(node, qname, qtype, resp);

	int ret = 0;
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

	if (ret == 0) {
		ns_put_additional(resp);
	}
	return ret;
}

/*----------------------------------------------------------------------------*/

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
			owner, DNSLIB_RRTYPE_CNAME,
			DNSLIB_CLASS_IN, SYNTH_CNAME_TTL);

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

static void ns_add_dnskey(const dnslib_node_t *apex, dnslib_response_t *resp)
{

	const dnslib_rrset_t *rrset =
		dnslib_node_rrset(apex, DNSLIB_RRTYPE_DNSKEY);
	assert(rrset != NULL);
	dnslib_response_add_rrset_additional(resp, rrset, 0, 0);
	ns_add_rrsigs(rrset, resp, apex->owner,
	              dnslib_response_add_rrset_additional, 0);
}

/*----------------------------------------------------------------------------*/

static int ns_answer_from_zone(const dnslib_zone_t *zone,
                               const dnslib_dname_t *qname, uint16_t qtype,
                               dnslib_response_t *resp)
{
	const dnslib_node_t *node = NULL;
	const dnslib_node_t *closest_encloser = NULL;
	const dnslib_node_t *previous = NULL;
	int cname = 0;
	//dnslib_dname_t *qname_old = NULL;
	int auth_soa = 0;

	int ret = 0;
	while (1) {
		//qname_old = dnslib_dname_copy(qname);

#ifdef USE_HASH_TABLE
		int find_ret = dnslib_zone_find_dname_hash(zone, qname,
		                                      &node, &closest_encloser);
#else
		int find_ret = dnslib_zone_find_dname(zone, qname, &node,
		                                  &closest_encloser, &previous);
#endif
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
		if (find_ret == DNSLIB_ZONE_NAME_NOT_IN_ZONE) {
			// possible only if we followed cname
			assert(cname != 0);
			dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
			auth_soa = 1;
			dnslib_response_set_aa(resp);
			break;
		}

//		assert(exact_match == 1
//		       || (exact_match == 0 && closest_encloser == node));

		debug_ns("Closest encloser is deleg. point? %s\n",
			 (dnslib_node_is_deleg_point(closest_encloser))
			 ? "yes" : "no");

		debug_ns("Closest encloser is non authoritative? %s\n",
			 (dnslib_node_is_non_auth(closest_encloser))
			 ? "yes" : "no");

		if (dnslib_node_is_deleg_point(closest_encloser)
		    || dnslib_node_is_non_auth(closest_encloser)) {
			ret = ns_referral(closest_encloser, zone, qname, resp);
			break;
		}

		if (find_ret == DNSLIB_ZONE_NAME_NOT_FOUND) {
			// DNAME?
			const dnslib_rrset_t *dname_rrset =
				dnslib_node_rrset(closest_encloser,
				                  DNSLIB_RRTYPE_DNAME);
			if (dname_rrset != NULL) {
				ns_process_dname(dname_rrset, qname, resp);
				auth_soa = 1;
				dnslib_response_set_aa(resp);
				break;
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
					if (ns_put_nsec_nsec3_nxdomain(zone,
						previous, closest_encloser,
						qname, resp) != 0) {
						return NS_ERR_SERVFAIL;
					}
				} else {
					dnslib_response_set_rcode(resp,
						DNSLIB_RCODE_NOERROR);
				}
				dnslib_response_set_aa(resp);
				break;
			}
			// else set the node from which to take the answers to
			// the wildcard node
			node = wildcard_node;
		}

		// now we have the node for answering

		if (dnslib_node_is_deleg_point(node)
		    || dnslib_node_is_non_auth(node)) {
			ret = ns_referral(node, zone, qname, resp);
			break;
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
			if (act_name != qname) {
				qname = act_name;
			}
			cname = 1;

			// otherwise search for the new name
			if (node == NULL) {
				continue; // infinite loop better than goto? :)
			}
			// if the node is delegation point, return referral
			if (dnslib_node_is_deleg_point(node)) {
				ret = ns_referral(node, zone, qname, resp);
				break;
			}
		}

		ret = ns_answer_from_node(node, closest_encloser, previous,
		                    zone, qname, qtype, resp);
		if (ret != 0) {
			break;
		}
		dnslib_response_set_aa(resp);
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);

		// this is the only case when the servers answers from
		// particular node, i.e. the only case when it may return SOA
		// or NS records in Answer section
		if (DNSSEC_ENABLED && dnslib_response_dnssec_requested(resp)
		    && node == zone->apex
		    && (qtype == DNSLIB_RRTYPE_SOA
		        || qtype == DNSLIB_RRTYPE_NS)) {
			ns_add_dnskey(node, resp);
		}

		break;
	}

	if (ret == 0 && auth_soa) {
		ns_put_authority_soa(zone, resp);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static int ns_answer(dnslib_zonedb_t *db, dnslib_response_t *resp)
{
	dnslib_dname_t *qname = resp->question.qname;
	uint16_t qtype = resp->question.qtype;
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
		return 0;
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

static int ns_response_to_wire(dnslib_response_t *resp, uint8_t *wire,
                               size_t *wire_size)
{
	uint8_t *rwire = NULL;
	size_t rsize = 0;
	int ret = 0;

	if ((ret = dnslib_response_to_wire(resp, &rwire, &rsize)) != 0) {
		log_answer_error("nameserver: Error converting response packet "
		                 "to wire format (error %d).\n", ret);
		return NS_ERR_SERVFAIL;
	}

	if (rsize > *wire_size) {
		return NS_ERR_SERVFAIL;
	}

	memcpy(wire, rwire, rsize);
	*wire_size = rsize;
	//free(rwire);

	return 0;
}

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

ns_nameserver *ns_create(dnslib_zonedb_t *database)
{
	ns_nameserver *ns = malloc(sizeof(ns_nameserver));
	if (ns == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	ns->zone_db = database;

	// prepare empty response with SERVFAIL error
	dnslib_response_t *err = dnslib_response_new_empty(NULL);
	if (err == NULL) {
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
		log_answer_error("nameserver: Error while converting a "
		                 "default error response to "
		                 "wire format \n");
		dnslib_response_free(&err);
		free(ns);
		return NULL;
	}

	ns->err_response = (uint8_t *)malloc(ns->err_resp_size);
	if (ns->err_response == NULL) {
		log_answer_error("nameserver: Error while converting default "
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

int ns_answer_request(ns_nameserver *nameserver, const uint8_t *query_wire,
                      size_t qsize, uint8_t *response_wire, size_t *rsize)
{
	debug_ns("ns_answer_request() called with query size %zu.\n", qsize);
	debug_ns_hex((char *)query_wire, qsize);

	if (qsize < 2) {
		return -1;
	}

	// 1) create empty response
	debug_ns("Parsing query using new dnslib structure...\n");
	dnslib_response_t *resp = dnslib_response_new_empty(nameserver->opt_rr);

	if (resp == NULL) {
		log_answer_error("Error while creating response packet!\n");
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_SERVFAIL,
		                  response_wire, rsize);
		return 0;
	}

	int ret = 0;

	// 2) parse the query
	if ((ret = dnslib_response_parse_query(resp, query_wire, qsize)) != 0) {
		log_answer_info("nameserver: Error while parsing query, "
		                "dnslib error '%d'.\n",
		                ret);
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_FORMERR,
		                  response_wire, rsize);
		dnslib_response_free(&resp);
		return 0;
	}

	// NSID
	if (NSID_ENABLED && dnslib_response_nsid_requested(resp)) {
		(void)dnslib_response_add_nsid(resp, NSID_DATA, NSID_LENGTH);
	}

	debug_ns("Query parsed.\n");
	dnslib_response_dump(resp);

	// 3) get the answer for the query
	rcu_read_lock();

	ret = ns_answer(nameserver->zone_db, resp);
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

	return 0;
}

/*----------------------------------------------------------------------------*/

void ns_destroy(ns_nameserver **nameserver)
{
	// do nothing with the zone database!
	free((*nameserver)->err_response);
	if ((*nameserver)->opt_rr != NULL) {
		dnslib_edns_free(&(*nameserver)->opt_rr);
	}
	free(*nameserver);
	*nameserver = NULL;
}

