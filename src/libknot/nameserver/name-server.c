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
knot_rrset_t *ns_synth_from_wildcard(
	const knot_rrset_t *wildcard_rrset, const knot_dname_t *qname)
{
	knot_rrset_t *rrset = NULL;
	int ret = knot_rrset_deep_copy(wildcard_rrset, &rrset);
	if (ret != KNOT_EOK) {
		dbg_ns("ns: ns_synth_from_wildcard: Could not copy RRSet.\n");
		return NULL;
	}

	knot_rrset_set_owner(rrset, qname);

	return rrset;
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
static int ns_check_wildcard(const knot_dname_t *name, knot_pkt_t *resp,
                             knot_rrset_t **rrset)
{
	assert(name != NULL);
	assert(resp != NULL);
	assert(rrset != NULL);
	assert(*rrset != NULL);

	if (knot_dname_is_wildcard((*rrset)->owner)) {
		resp->flags |= KNOT_PF_WILDCARD; /* Mark */
		knot_rrset_t *synth_rrset =
			ns_synth_from_wildcard(*rrset, name);
		if (synth_rrset == NULL) {
			dbg_ns("Failed to synthetize RRSet from wildcard.\n");
			return KNOT_ERROR;
		}

dbg_ns_exec_verb(
		dbg_ns_verb("Synthetized RRSet:\n");
		knot_rrset_dump(synth_rrset);
);

		*rrset = synth_rrset;
/* #10 update flags somehow, will leak */
	}

	return KNOT_EOK;
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
int ns_add_rrsigs(knot_rrset_t *rrset, knot_pkt_t *resp,
                         const knot_dname_t *name,
                         uint32_t flags)
{
	knot_rrset_t *rrsigs;

	dbg_ns_verb("Adding RRSIGs for RRSet, type: %u.\n", knot_rrset_type(rrset));

	assert(resp != NULL);

	dbg_ns_detail("DNSSEC requested: %d\n",
	              knot_pkt_have_dnssec(resp->query));
	dbg_ns_detail("RRSIGS: %p\n", knot_rrset_rrsigs(rrset));

	if (DNSSEC_ENABLED
	    && (knot_pkt_have_dnssec(resp->query)
	        || knot_pkt_qtype(resp) == KNOT_RRTYPE_ANY)
	    && (rrsigs = knot_rrset_get_rrsigs(rrset)) != NULL) {
		if (name != NULL) {
			knot_rrset_t *rrsigs_orig = rrsigs;
			int ret = ns_check_wildcard(name, resp, &rrsigs);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to process wildcard: %s\n",
				       knot_strerror(ret));
				return ret;
			}
			if (rrsigs != rrsigs_orig) {
				flags |= KNOT_PF_FREE;
			}
		}
		return knot_pkt_put(resp, 0, rrsigs, flags|KNOT_PF_CHECKDUP);
	}

	return KNOT_EOK;
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
int ns_put_answer(const knot_node_t *node,
                         const knot_zone_contents_t *zone,
                         const knot_dname_t *name,
                         uint16_t type, knot_pkt_t *resp, int *added,
                         int check_any)
{
	*added = 0;
dbg_ns_exec_verb(
	char *name_str = knot_dname_to_str(node->owner);
	dbg_ns_verb("Putting answers from node %s.\n", name_str);
	free(name_str);
);

	int ret = KNOT_EOK;

	switch (type) {
	case KNOT_RRTYPE_ANY: {
		dbg_ns_verb("Returning all RRTYPES.\n");

		// if ANY not allowed, set TC bit
		if (check_any && knot_zone_contents_any_disabled(zone)) {
			knot_wire_set_tc(resp->wire);
			break;
		}

		knot_rrset_t **rrsets = knot_node_get_rrsets(node);
		if (rrsets == NULL) {
			break;
		}
		int i = 0;
		knot_rrset_t *rrset;
		while (i < knot_node_rrset_count(node)) {
			assert(rrsets[i] != NULL);
			rrset = rrsets[i];

			dbg_ns_detail("  Type: %u\n", knot_rrset_type(rrset));

			if (knot_rrset_rdata_rr_count(rrset) > 0
			    || knot_rrset_type(rrset) == KNOT_RRTYPE_APL) {

				knot_rrset_t *rrset_orig = rrset;
				ret = ns_check_wildcard(name, resp, &rrset);
				if (ret != KNOT_EOK) {
					dbg_ns("Failed to process wildcard.\n");
					break;
				}

				unsigned flags = 0;
				if (rrset != rrset_orig) {
					flags |= KNOT_PF_FREE;
				}

				assert(KNOT_PKT_IN_AN(resp));
				ret = knot_pkt_put(resp, 0, rrset, flags);
				if (ret != KNOT_EOK) {
					dbg_ns("Failed add Answer RRSet: %s\n",
					       knot_strerror(ret));
					break;
				}

				*added += 1;
			}

			assert(KNOT_PKT_IN_AN(resp));
			ret = ns_add_rrsigs(rrset, resp, name, 1);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed add RRSIGs for Answer RRSet: %s"
				       "\n", knot_strerror(ret));
				break;
			}

			*added += 1;

			++i;
		}
		free(rrsets);
		break;
	}
	case KNOT_RRTYPE_RRSIG: {
		dbg_ns_verb("Returning all RRSIGs.\n");
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

			knot_rrset_t *rrset_orig = rrset;
			ret = ns_check_wildcard(name, resp, &rrset);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to process wildcard.\n");
				break;
			}

			unsigned flags = 0;
			if (rrset != rrset_orig) {
				flags |= KNOT_PF_FREE;
			}

			assert(KNOT_PKT_IN_AN(resp));
			ret = knot_pkt_put(resp, 0, rrset, flags);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed add Answer RRSet: %s\n",
				       knot_strerror(ret));
				break;
			}

			*added += 1;
			++i;
		}
		free(rrsets);
		break;
	}
	default: {
		int ret = 0;
		knot_rrset_t *rrset = knot_node_get_rrset(node, type);
		knot_rrset_t *rrset2 = rrset;
		if (rrset != NULL && knot_rrset_rdata_rr_count(rrset)) {
			dbg_ns_verb("Found RRSet of type %u\n", type);

			knot_rrset_t *rrset2_orig = rrset2;
			ret = ns_check_wildcard(name, resp, &rrset2);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to process wildcard.\n");
				break;
			}

			unsigned flags = 0;
			if (rrset2 != rrset2_orig) {
				flags |= KNOT_PF_FREE;
			}

			assert(KNOT_PKT_IN_AN(resp));
			ret = knot_pkt_put(resp, 0, rrset2, flags);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed add Answer RRSet: %s\n",
				       knot_strerror(ret));
				break;
			}

			*added += 1;

			assert(KNOT_PKT_IN_AN(resp));
			ret = ns_add_rrsigs(rrset, resp, name, 1);

			if (ret != KNOT_EOK) {
				dbg_ns("Failed add RRSIGs for Answer RRSet: %s"
				       "\n", knot_strerror(ret));
				break;
			}

			*added += 1;
		}
	    }
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static int ns_put_additional_rrset(knot_pkt_t *pkt, uint16_t compr_hint,
				   const knot_node_t *node, uint16_t rrtype)
{
	knot_rrset_t *rrset_add = knot_node_get_rrset(node, rrtype);
	if (rrset_add == NULL) {
		return KNOT_EOK;
	}


	/* \note Not processing wildcards as it's only optional. */
	if (knot_dname_is_wildcard(node->owner)) {
		return KNOT_EOK;
	}

	dbg_ns("%s: putting additional TYPE%hu %p\n", __func__, rrtype, rrset_add);

	/* Don't truncate if it doesn't fit. */
	unsigned flags = KNOT_PF_NOTRUNC|KNOT_PF_CHECKDUP;
	int ret = knot_pkt_put(pkt, compr_hint, rrset_add, flags);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* RRSIGs are also optional. */
	ret = ns_add_rrsigs(rrset_add, pkt, node->owner, flags);

	return ret;
}

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
static int ns_put_additional_for_rrset(knot_pkt_t *resp, uint16_t rr_id)
{
	assert(rr_id < resp->rrset_count);
	const knot_rrset_t *rrset = resp->rr[rr_id];
	knot_rrinfo_t *rrinfo = &resp->rr_info[rr_id];
	const knot_node_t *node = NULL;

	int ret = KNOT_EOK;

	/* All RRs should have additional node cached or NULL. */
	for (uint16_t i = 0; i < knot_rrset_rdata_rr_count(rrset); i++) {
		uint16_t hint = knot_pkt_compr_hint(rrinfo, COMPR_HINT_RDATA + i);
		node = rrset->additional[i];

		/* \note Not resolving CNAMEs as it doesn't pay off much. */

		/* A records */
		ret = ns_put_additional_rrset(resp, hint, node, KNOT_RRTYPE_A);
		if (ret != KNOT_EOK) {
			break;
		}

		/* AAAA records */
		ret = ns_put_additional_rrset(resp, hint, node, KNOT_RRTYPE_AAAA);
		if (ret != KNOT_EOK) {
			break;
		}

	}

	/* Truncation is okay. */
	if (ret == KNOT_ESPACE) {
		ret = KNOT_EOK;
	}

	return ret;
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
int ns_put_additional(knot_pkt_t *resp)
{
	/* Begin AR section. */
	int ret = KNOT_EOK;
	knot_pkt_put_opt(resp);

	/* Scan all RRs in AN+NS. */
	uint16_t rr_count = resp->rrset_count;
	for (uint16_t i = 0; i < rr_count; ++i) {
		if (rrset_additional_needed(knot_rrset_type(resp->rr[i]))) {
			ret = ns_put_additional_for_rrset(resp, i);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts authority NS RRSet to the Auhority section of the response.
 *
 * \param zone Zone to take the authority NS RRSet from.
 * \param resp Response where to add the RRSet.
 */
int ns_put_authority_ns(const knot_zone_contents_t *zone,
                        knot_pkt_t *resp)
{
	dbg_ns("%s: putting authority NS\n", __func__);
	assert(KNOT_PKT_IN_NS(resp));

	knot_rrset_t *ns_rrset = knot_node_get_rrset(
			knot_zone_contents_apex(zone), KNOT_RRTYPE_NS);

	if (ns_rrset != NULL) {
		int ret = knot_pkt_put(resp, 0, ns_rrset, KNOT_PF_NOTRUNC|KNOT_PF_CHECKDUP);

		if (ret != KNOT_EOK) {
			dbg_ns("Failed to add Authority NSs to response.\n");
			return ret;
		}

		/*! \bug This is strange, it should either fit both NS+RRSIG or
		 *       nothing. This would leave the last NS without RRSIG. */
		ret = ns_add_rrsigs(ns_rrset, resp, knot_node_owner(
		              knot_zone_contents_apex(zone)), 0);

		if (ret != KNOT_EOK) {
			dbg_ns("Failed to add RRSIGs for Authority NSs to "
			       "response.\n");
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts SOA RRSet to the Auhority section of the response.
 *
 * \param zone Zone to take the SOA RRSet from.
 * \param resp Response where to add the RRSet.
 */
int ns_put_authority_soa(const knot_zone_contents_t *zone,
                                 knot_pkt_t *resp)
{
	assert(KNOT_PKT_IN_NS(resp));
	dbg_ns("%s: putting authority SOA\n", __func__);

	int ret;

	knot_rrset_t *soa_rrset = knot_node_get_rrset(
			knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	assert(soa_rrset != NULL);

	// if SOA's TTL is larger than MINIMUM, copy the RRSet and set
	// MINIMUM as TTL
	uint32_t flags = KNOT_PF_NOTRUNC;
	uint32_t min = knot_rdata_soa_minimum(soa_rrset);
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
		flags |= KNOT_PF_FREE;
	}

	assert(soa_rrset != NULL);
	assert(KNOT_PKT_IN_NS(resp));
	ret = knot_pkt_put(resp, 0, soa_rrset, flags);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = ns_add_rrsigs(soa_rrset, resp,
			    knot_node_owner(knot_zone_contents_apex(zone)),
			    0);

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
	int ce_labels = knot_dname_labels(closest_encloser, NULL);
	int qname_labels = knot_dname_labels(name, NULL);

	assert(ce_labels < qname_labels);

	// the common labels should match
	assert(knot_dname_matched_labels(closest_encloser, name)
	       == ce_labels);

	// chop some labels from the qname
	for (int i = 0; i < (qname_labels - ce_labels - 1); ++i) {
		name = knot_wire_next_label(name, NULL);
	}

	return knot_dname_copy(name);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds NSEC3 RRSet (together with corresponding RRSIGs) from the given
 *        node into the response.
 *
 * \param node Node to get the NSEC3 RRSet from.
 * \param resp Response where to add the RRSets.
 */
static int ns_put_nsec3_from_node(const knot_node_t *node,
                                  knot_pkt_t *resp)
{
	assert(DNSSEC_ENABLED
	       && knot_pkt_have_dnssec(resp->query));

	knot_rrset_t *rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NSEC3);
	//assert(rrset != NULL);

	if (rrset == NULL) {
		// bad zone, ignore
		return KNOT_EOK;
	}

	int res = KNOT_EOK;
	if (knot_rrset_rdata_rr_count(rrset)) {
		assert(KNOT_PKT_IN_NS(resp));
		res = knot_pkt_put(resp, 0, rrset, KNOT_PF_CHECKDUP);
	}
	// add RRSIG for the RRSet
	if (res == KNOT_EOK && (rrset = knot_rrset_get_rrsigs(rrset)) != NULL
	    && knot_rrset_rdata_rr_count(rrset)) {
		assert(KNOT_PKT_IN_NS(resp));
		res = knot_pkt_put(resp, 0, rrset, 0);
	}

	/*! \note TC bit is already set, if something went wrong. */

	// return the error code, so that other code may be skipped
	return res;
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
                                 knot_pkt_t *resp)
{
	const knot_node_t *prev, *node;
	/*! \todo Check version. */
	int match = knot_zone_contents_find_nsec3_for_name(zone, name,
	                                                   &node, &prev);
	//assert(match >= 0);
	if (match < 0) {
		// ignoring, what can we do anyway?
		return KNOT_EOK;
	}

	if (match == KNOT_ZONE_NAME_FOUND || prev == NULL){
		// if run-time collision => SERVFAIL
		return KNOT_EOK;
	}

dbg_ns_exec_verb(
	char *name = knot_dname_to_str(prev->owner);
	dbg_ns_verb("Covering NSEC3 node: %s\n", name);
	free(name);
);

	return ns_put_nsec3_from_node(prev, resp);
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
                                         knot_pkt_t *resp)
{
	assert(zone != NULL);
	assert(closest_encloser != NULL);
	assert(*closest_encloser != NULL);
	assert(qname != NULL);
	assert(resp != NULL);

	// this function should be called only if NSEC3 is enabled in the zone
	assert(knot_zone_contents_nsec3params(zone) != NULL);

	dbg_ns_verb("Adding closest encloser proof\n");

	if (knot_zone_contents_nsec3params(zone) == NULL) {
dbg_ns_exec_verb(
		char *name = knot_dname_to_str(knot_node_owner(
				knot_zone_contents_apex(zone)));
		dbg_ns_verb("No NSEC3PARAM found in zone %s.\n", name);
		free(name);
);
		return KNOT_EOK;
	}

dbg_ns_exec_detail(
	char *name = knot_dname_to_str(knot_node_owner(*closest_encloser));
	dbg_ns_detail("Closest encloser: %s\n", name);
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

dbg_ns_exec_verb(
	char *name = knot_dname_to_str(nsec3_node->owner);
	dbg_ns_verb("NSEC3 node: %s\n", name);
	free(name);
	name = knot_dname_to_str((*closest_encloser)->owner);
	dbg_ns_verb("Closest provable encloser: %s\n", name);
	free(name);
	if (next_closer != NULL) {
		name = knot_dname_to_str(next_closer);
		dbg_ns_verb("Next closer name: %s\n", name);
		free(name);
	} else {
		dbg_ns_verb("Next closer name: none\n");
	}
);

	int ret = ns_put_nsec3_from_node(nsec3_node, resp);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/*
	 * 2) NSEC3 that covers the "next closer" name.
	 */
	if (next_closer == NULL) {
		// create the "next closer" name by appending from qname
		knot_dname_t *new_next_closer = ns_next_closer(
			knot_node_owner(*closest_encloser), qname);

		if (new_next_closer == NULL) {
			return NS_ERR_SERVFAIL;
		}
dbg_ns_exec_verb(
		char *name = knot_dname_to_str(new_next_closer);
		dbg_ns_verb("Next closer name: %s\n", name);
		free(name);
);
		ret = ns_put_covering_nsec3(zone, new_next_closer, resp);

		knot_dname_free(&new_next_closer);
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

	knot_dname_t *wildcard = knot_dname_from_str("*");
	if (wildcard == NULL) {
		return NULL;
	}

	wildcard = knot_dname_cat(wildcard, name);
	if (wildcard == NULL)
		return NULL;

dbg_ns_exec_verb(
	char *name = knot_dname_to_str(wildcard);
	dbg_ns_verb("Wildcard: %s\n", name);
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
                                          knot_pkt_t *resp)
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
int ns_put_nsec_nsec3_nodata(const knot_zone_contents_t *zone,
			     const knot_node_t *node,
			     const knot_dname_t *qname,
			     knot_pkt_t *resp)
{
	if (!DNSSEC_ENABLED ||
	    !knot_pkt_have_dnssec(resp->query)) {
		return KNOT_EOK;
	}

	/*! \todo Maybe distinguish different errors. */
	int ret = KNOT_ERROR;

	knot_rrset_t *rrset = NULL;

	if (knot_zone_contents_nsec3_enabled(zone)) {
		knot_node_t *nsec3_node = knot_node_get_nsec3_node(node);
		dbg_ns("%s: adding NSEC3 NODATA\n", __func__);

		if (nsec3_node != NULL
		    && (rrset = knot_node_get_rrset(nsec3_node,
		                                  KNOT_RRTYPE_NSEC3)) != NULL
		    && knot_rrset_rdata_rr_count(rrset)) {
			dbg_ns_detail("Putting the RRSet to Authority\n");
			assert(KNOT_PKT_IN_NS(resp));
			ret = knot_pkt_put(resp, 0, rrset, 0);
		} else {
			// No NSEC3 node => Opt-out
			return ns_put_nsec3_closest_encloser_proof(zone,
								   &node,
								   qname, resp);

		}
	} else {
		dbg_ns("%s: adding NSEC NODATA\n", __func__);
		if ((rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NSEC))
		    != NULL
		    && knot_rrset_rdata_rr_count(rrset)) {
			dbg_ns_detail("Putting the RRSet to Authority\n");
			assert(KNOT_PKT_IN_NS(resp));
			ret = knot_pkt_put(resp, 0, rrset, 0);
		}
	}

	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_ns_detail("Putting RRSet's RRSIGs to Authority\n");
	if (rrset != NULL && (rrset = knot_rrset_get_rrsigs(rrset)) != NULL) {
		assert(KNOT_PKT_IN_NS(resp));
		ret = knot_pkt_put(resp, 0, rrset, 0);
	}

	return ret;
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
                                knot_pkt_t *resp)
{
	knot_rrset_t *rrset = NULL;

	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {
		/*! \todo Check version. */
		previous = knot_zone_contents_find_previous(zone, qname);
		assert(previous != NULL);

		/*!
		 * \todo isn't this handled in adjusting?
		 * knot_zone_contents_adjust_node_in_tree_ptr()
		 */
		while (!knot_node_is_auth(previous)) {
			previous = knot_node_previous(previous);
		}
	}

dbg_ns_exec_verb(
	char *name = knot_dname_to_str(previous->owner);
	dbg_ns_verb("Previous node: %s\n", name);
	free(name);
);

	// 1) NSEC proving that there is no node with the searched name
	rrset = knot_node_get_rrset(previous, KNOT_RRTYPE_NSEC);
	if (rrset == NULL) {
		// no NSEC records
		//return NS_ERR_SERVFAIL;
		return KNOT_EOK;

	}

	assert(KNOT_PKT_IN_NS(resp));
	int ret = knot_pkt_put(resp, 0, rrset, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to add NSEC for NXDOMAIN to response: %s\n",
		       knot_strerror(ret));
		return ret;
	}

	rrset = knot_rrset_get_rrsigs(rrset);
	//assert(rrset != NULL);
	ret = knot_pkt_put(resp, 0, rrset, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to add RRSIGs for NSEC for NXDOMAIN to response:"
		       "%s\n", knot_strerror(ret));
		//return ret;
	}
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

	while (knot_dname_cmp(knot_node_owner(prev_new),
				    wildcard) > 0) {
dbg_ns_exec_verb(
		char *name = knot_dname_to_str(knot_node_owner(prev_new));
		dbg_ns_verb("Previous node: %s\n", name);
		free(name);
);
		assert(prev_new != knot_zone_contents_apex(zone));
		prev_new = knot_node_previous(prev_new);
	}
	assert(knot_dname_cmp(knot_node_owner(prev_new),
	                            wildcard) < 0);

dbg_ns_exec_verb(
	char *name = knot_dname_to_str(knot_node_owner(prev_new));
	dbg_ns_verb("Previous node: %s\n", name);
	free(name);
);

	/* Directly discard dname. */
	knot_dname_free(&wildcard);

	if (prev_new != previous) {
		rrset = knot_node_get_rrset(prev_new, KNOT_RRTYPE_NSEC);
		if (rrset == NULL || knot_rrset_rdata_rr_count(rrset) == 0) {
			// bad zone, ignore
			return KNOT_EOK;
		}
		assert(KNOT_PKT_IN_NS(resp));
		ret = knot_pkt_put(resp, 0, rrset, 0);
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to add second NSEC for NXDOMAIN to "
			       "response: %s\n", knot_strerror(ret));
			return ret;
		}
		rrset = knot_rrset_get_rrsigs(rrset);
		if (rrset == NULL || knot_rrset_rdata_rr_count(rrset) == 0) {
			// bad zone, ignore
			return KNOT_EOK;
		}
		assert(KNOT_PKT_IN_NS(resp));
		ret = knot_pkt_put(resp, 0, rrset, 0);
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to add RRSIGs for second NSEC for "
			       "NXDOMAIN to response: %s\n", knot_strerror(ret));
			//return ret;
		}
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
                                 knot_pkt_t *resp)
{
	// 1) Closest encloser proof
	int ret = ns_put_nsec3_closest_encloser_proof(zone, &closest_encloser,
	                                              qname, resp);
	// 2) NSEC3 covering non-existent wildcard
	if (ret == KNOT_EOK && closest_encloser != NULL) {
		dbg_ns_verb("Putting NSEC3 for no wildcard child of closest "
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
int ns_put_nsec_nsec3_nxdomain(const knot_zone_contents_t *zone,
                                      const knot_node_t *previous,
                                      const knot_node_t *closest_encloser,
                                      const knot_dname_t *qname,
                                      knot_pkt_t *resp)
{
	int ret = 0;
	if (DNSSEC_ENABLED
	    && knot_pkt_have_dnssec(resp->query)) {
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
                                 knot_pkt_t *resp)
{
	assert(closest_encloser != NULL);
	assert(qname != NULL);
	assert(resp != NULL);
	assert(DNSSEC_ENABLED
	       && knot_pkt_have_dnssec(resp->query));

	if (!knot_zone_contents_nsec3_enabled(zone)) {
		return KNOT_EOK;
	}

	/*
	 * NSEC3 that covers the "next closer" name.
	 */
	// create the "next closer" name by appending from qname
	dbg_ns_verb("Finding next closer name for wildcard NSEC3.\n");
	knot_dname_t *next_closer =
		ns_next_closer(closest_encloser->owner, qname);

	if (next_closer == NULL) {
		return NS_ERR_SERVFAIL;
	}
dbg_ns_exec_verb(
	char *name = knot_dname_to_str(next_closer);
	dbg_ns_verb("Next closer name: %s\n", name);
	free(name);
);
	int ret = ns_put_covering_nsec3(zone, next_closer, resp);


	/* Duplicate from ns_next_close(), safe to discard. */
	knot_dname_free(&next_closer);

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
static int ns_put_nsec_wildcard(const knot_zone_contents_t *zone,
                                const knot_dname_t *qname,
                                const knot_node_t *previous,
                                knot_pkt_t *resp)
{
	assert(DNSSEC_ENABLED
	       && knot_pkt_have_dnssec(resp->query));

	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {
		previous = knot_zone_contents_find_previous(zone, qname);
		assert(previous != NULL);

		/*!
		 * \todo isn't this handled in adjusting?
		 * knot_zone_contents_adjust_node_in_tree_ptr()
		 */
		while (!knot_node_is_auth(previous)) {
			previous = knot_node_previous(previous);
		}
	}

	knot_rrset_t *rrset =
		knot_node_get_rrset(previous, KNOT_RRTYPE_NSEC);

	int ret = KNOT_EOK;

	if (rrset != NULL && knot_rrset_rdata_rr_count(rrset)) {
		// NSEC proving that there is no node with the searched name
		assert(KNOT_PKT_IN_NS(resp));
		ret = knot_pkt_put(resp, 0, rrset, 0);
		if (ret == KNOT_EOK) {
			rrset = knot_rrset_get_rrsigs(rrset);
			//assert(rrset != NULL);
			ret = knot_pkt_put(resp, 0, rrset, 0);
		}
	}

	return ret;
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
int ns_put_nsec_nsec3_wildcard_nodata(const knot_node_t *node,
					  const knot_node_t *closest_encloser,
					  const knot_node_t *previous,
					  const knot_zone_contents_t *zone,
					  const knot_dname_t *qname,
					  knot_pkt_t *resp)
{
	int ret = KNOT_EOK;
	if (DNSSEC_ENABLED
	    && knot_pkt_have_dnssec(resp->query)) {
		if (knot_zone_contents_nsec3_enabled(zone)) {
			ret = ns_put_nsec3_closest_encloser_proof(zone,
							      &closest_encloser,
							      qname, resp);

			const knot_node_t *nsec3_node;
			if (ret == KNOT_EOK
			    && (nsec3_node = knot_node_nsec3_node(node))
				!= NULL) {
				ret = ns_put_nsec3_from_node(nsec3_node, resp);
			}
		} else {
			ret = ns_put_nsec_wildcard(zone, qname, previous, resp);
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
int ns_put_nsec_nsec3_wildcard_answer(const knot_node_t *node,
                                          const knot_node_t *closest_encloser,
                                          const knot_node_t *previous,
                                          const knot_zone_contents_t *zone,
                                          const knot_dname_t *qname,
                                          knot_pkt_t *resp)
{
	// if wildcard answer, add NSEC / NSEC3

	int ret = KNOT_EOK;
	if (DNSSEC_ENABLED
	    && knot_pkt_have_dnssec(resp->query)
	    && knot_dname_is_wildcard(knot_node_owner(node))
	    && knot_dname_cmp(qname, knot_node_owner(node)) != 0) {
		dbg_ns_verb("Adding NSEC/NSEC3 for wildcard answer.\n");
		if (knot_zone_contents_nsec3_enabled(zone)) {
			ret = ns_put_nsec3_wildcard(zone, closest_encloser,
			                            qname, resp);
		} else {
			ret = ns_put_nsec_wildcard(zone, qname, previous, resp);
		}
	}
	return ret;
}

/*----------------------------------------------------------------------------*/



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
int ns_referral(const knot_node_t *node,
                              const knot_zone_contents_t *zone,
                              const knot_dname_t *qname,
                              knot_pkt_t *resp,
                              uint16_t qtype)
{
	dbg_ns_verb("Referral response.\n");

	while (!knot_node_is_deleg_point(node)) {
		assert(knot_node_parent(node) != NULL);
		node = knot_node_parent(node);
	}


	int ret = KNOT_EOK;

	knot_rrset_t *rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NS);
	assert(rrset != NULL);

	assert(KNOT_PKT_IN_NS(resp));
	ret = knot_pkt_put(resp, 0, rrset, 0);
	if (ret == KNOT_EOK) {
		ret = ns_add_rrsigs(rrset, resp, node->owner, 0);
	}

	// add DS records
	dbg_ns_verb("DNSSEC requested: %d\n",
		 knot_pkt_have_dnssec(resp->query));
	dbg_ns_verb("DS records: %p\n", knot_node_rrset(node, KNOT_RRTYPE_DS));
	if (ret == KNOT_EOK && DNSSEC_ENABLED
	    && knot_pkt_have_dnssec(resp->query)) {
		rrset = knot_node_get_rrset(node, KNOT_RRTYPE_DS);
		if (rrset != NULL) {
			ret = knot_pkt_put(resp, 0, rrset, 0);
			if (ret == KNOT_EOK) {
				ret = ns_add_rrsigs(rrset, resp, node->owner, 0);
			}
		} else {
			// no DS, add NSEC3 or NSEC
			// if NSEC3 enabled, search for NSEC3
			if (knot_zone_contents_nsec3_enabled(zone)) {
				const knot_node_t *nsec3_node =
					knot_node_nsec3_node(node);
				dbg_ns_detail("There is no DS, putting NSEC3s."
				              "\n");
				if (nsec3_node != NULL) {
					dbg_ns_detail("Putting NSEC3s from the node.\n");
					ret = ns_put_nsec3_from_node(nsec3_node,
					                             resp);
				} else {
					dbg_ns_detail("Putting Opt-Out NSEC3s."
					              "\n");
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
					ret = knot_pkt_put(resp, 0, nsec, KNOT_PF_CHECKDUP);
					if (ret == KNOT_EOK &&
					    (nsec = knot_rrset_get_rrsigs(nsec)) != NULL) {
						ret = knot_pkt_put(resp, 0, nsec, KNOT_PF_CHECKDUP);
					}
				}
			}
		}
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
	dbg_ns_verb("Synthetizing CNAME from DNAME...\n");

	// create new CNAME RRSet

	knot_dname_t *owner = knot_dname_copy(qname);
	if (owner == NULL) {
		return NULL;
	}

	knot_rrset_t *cname_rrset = knot_rrset_new(
		owner, KNOT_RRTYPE_CNAME, KNOT_CLASS_IN, dname_rrset->ttl);
	if (cname_rrset == NULL) {
		return NULL;
	}

	/* Replace last labels of qname with DNAME. */
	const knot_dname_t *dname_wire = knot_rrset_owner(dname_rrset);
	size_t labels = knot_dname_labels(dname_wire, NULL);
	const knot_dname_t *dname_tgt = knot_rdata_dname_target(dname_rrset);
	knot_dname_t *cname = knot_dname_replace_suffix(qname, labels, dname_tgt);
	if (cname == NULL) {
		knot_rrset_free(&cname_rrset);
		return NULL;
	}
dbg_ns_exec(
	char *name = knot_dname_to_str(cname);
	dbg_ns_verb("CNAME canonical name: %s.\n", name);
	free(name);
);
	int cname_size = knot_dname_size(cname);
	uint8_t *cname_rdata = knot_rrset_create_rdata(cname_rrset, cname_size);
	if (cname_rdata == NULL) {
		dbg_ns("ns: cname_from_dname: Cannot cerate CNAME RDATA.\n");
		knot_rrset_free(&cname_rrset);
		knot_dname_free(&cname);
		return NULL;
	}

	/* Store DNAME into RDATA. */
	memcpy(cname_rdata, cname, cname_size);
	knot_dname_free(&cname);

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
static int ns_dname_is_too_long(const knot_rrset_t *rrset,
                                const knot_dname_t *qname)
{
	// TODO: add function for getting DNAME target
	if (knot_dname_labels(qname, NULL)
	        - knot_dname_labels(knot_rrset_owner(rrset), NULL)
	        + knot_dname_labels(knot_rdata_dname_target(rrset), NULL)
	        > KNOT_DNAME_MAXLEN) {
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
int ns_process_dname(knot_rrset_t *dname_rrset,
                             const knot_dname_t **qname,
                             knot_pkt_t *resp)
{
dbg_ns_exec_verb(
	char *name = knot_dname_to_str(knot_rrset_owner(dname_rrset));
	dbg_ns_verb("Processing DNAME for owner %s...\n", name);
	free(name);
);
	// TODO: check the number of RRs in the RRSet??

	// put the DNAME RRSet into the answer
	assert(KNOT_PKT_IN_AN(resp));
	int ret = knot_pkt_put(resp, 0, dname_rrset, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = ns_add_rrsigs(dname_rrset, resp, *qname, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (ns_dname_is_too_long(dname_rrset, *qname)) {
		knot_wire_set_rcode(resp->wire, KNOT_RCODE_YXDOMAIN);
		return KNOT_EOK;
	}

	// synthetize CNAME (no way to tell that client supports DNAME)
	knot_rrset_t *synth_cname = ns_cname_from_dname(dname_rrset, *qname);
	// add the synthetized RRSet to the Answer
	ret = knot_pkt_put(resp, 0, synth_cname, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// no RRSIGs for this RRSet

	// get the next SNAME from the CNAME RDATA
	const knot_dname_t *cname = knot_rdata_cname_name(synth_cname);
	dbg_ns_verb("CNAME name from RDATA: %p\n", cname);

	// save the new name which should be used for replacing wildcard
	*qname = cname;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds DNSKEY RRSet from the apex of a zone to the response.
 *
 * \param apex Zone apex node.
 * \param resp Response.
 */
int ns_add_dnskey(const knot_node_t *apex, knot_pkt_t *resp)
{
	knot_rrset_t *rrset =
		knot_node_get_rrset(apex, KNOT_RRTYPE_DNSKEY);

	int ret = KNOT_EOK;

	if (rrset != NULL) {
		ret = knot_pkt_put(resp, 0, rrset, KNOT_PF_NOTRUNC);
		if (ret == KNOT_EOK) {
			ret = ns_add_rrsigs(rrset, resp, apex->owner, 0);
		}
	}

	return ret;
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

static int ns_axfr_from_node(knot_node_t *node, void *data)
{
	assert(node != NULL);
	assert(data != NULL);

	knot_ns_xfr_t *xfr = (knot_ns_xfr_t *)data;

	dbg_ns_detail("Params OK, answering AXFR from node %p.\n", node);
dbg_ns_exec_verb(
	char *name = knot_dname_to_str(knot_node_owner(node));
	dbg_ns_verb("Node owner: %s\n", name);
	free(name);
);

	if (knot_node_rrset_count(node) == 0) {
		return KNOT_EOK;
	}

	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
	if (rrsets == NULL) {
		return KNOT_ENOMEM;
	}

	int i = 0;
	int ret = KNOT_EOK;
	knot_rrset_t *rrset = NULL;
	while (i < knot_node_rrset_count(node)) {
		assert(rrsets[i] != NULL);
		rrset = rrsets[i];
rrset:
		dbg_ns_verb("  Type: %u\n",
		            knot_rrset_type(rrset));

		// do not add SOA
		if (knot_rrset_type(rrset) == KNOT_RRTYPE_SOA) {
			++i;
			continue;
		}

		// Do not put empty RRSet
		if (knot_rrset_rdata_rr_count(rrset) <= 0) {
			rrset = knot_rrset_get_rrsigs(rrset);
			goto rrsigs;
		}

		assert(KNOT_PKT_IN_AN(xfr->response));
		ret = knot_pkt_put(xfr->response, 0, rrset, KNOT_PF_NOTRUNC);

		if (ret == KNOT_ESPACE) {
			// TODO: send the packet and clean the structure
			dbg_ns("Packet full, sending..\n");
			ret = ns_xfr_send_and_clear(xfr,
				knot_ns_tsig_required(xfr->packet_nr));
			if (ret != KNOT_EOK) {
				// some wierd problem, we should end
				ret = KNOT_ERROR;
				break;
			}
			// otherwise try once more with the same RRSet
			goto rrset;
		} else if (ret != KNOT_EOK) {
			// some wierd problem, we should end
			ret = KNOT_ERROR;
			break;
		}

		// we can send the RRSets in any order, so add the RRSIGs now
		rrset = knot_rrset_get_rrsigs(rrset);
rrsigs:
		if (rrset == NULL) {
			++i;
			continue;
		}

		assert(KNOT_PKT_IN_AN(xfr->response));
		ret = knot_pkt_put(xfr->response, 0, rrset, KNOT_PF_NOTRUNC);

		if (ret == KNOT_ESPACE) {
			// TODO: send the packet and clean the structure
			dbg_ns("Packet full, sending..\n");
			ret = ns_xfr_send_and_clear(xfr,
				knot_ns_tsig_required(xfr->packet_nr));
			if (ret != KNOT_EOK) {
				// some wierd problem, we should end
				ret = KNOT_ERROR;
				break;
			}
			// otherwise try once more with the same RRSet
			goto rrsigs;
		} else if (ret != KNOT_EOK) {
			// some wierd problem, we should end
			ret = KNOT_ERROR;
			break;
		}

		// this way only whole RRSets are always sent
		// we guess it will not create too much overhead

		++i;
	}
	free(rrsets);

	/*! \todo maybe distinguish some error codes. */
	//params->ret = (ret == 0) ? KNOT_EOK : KNOT_ERROR;
	return ret;
}

/*----------------------------------------------------------------------------*/

static int ns_axfr_from_zone(knot_zone_contents_t *zone, knot_ns_xfr_t *xfr)
{
	assert(xfr != NULL);
	assert(xfr->query != NULL);
	assert(xfr->response != NULL);
	assert(xfr->wire != NULL);
	assert(xfr->send != NULL);

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
	assert(KNOT_PKT_IN_AN(xfr->response));
	ret = knot_pkt_put(xfr->response, 0, soa_rrset, KNOT_PF_NOTRUNC);
	if (ret != KNOT_EOK) {
		// something is really wrong
		return KNOT_ERROR;
	}

	// add the SOA's RRSIG
	knot_rrset_t *rrset = knot_rrset_get_rrsigs(soa_rrset);
	if (rrset != NULL
	    && (ret = knot_pkt_put(xfr->response, 0, rrset, KNOT_PF_NOTRUNC)) != KNOT_EOK) {
		// something is really wrong, these should definitely fit in
		return KNOT_ERROR;
	}

	ret = knot_zone_contents_tree_apply_inorder(zone, ns_axfr_from_node, xfr);
	if (ret != KNOT_EOK) {
		return KNOT_ERROR;	// maybe do something with the code
	}

	ret = knot_zone_contents_nsec3_apply_inorder(zone, ns_axfr_from_node, xfr);
	if (ret != KNOT_EOK) {
		return KNOT_ERROR;	// maybe do something with the code
	}

	/*
	 * Last SOA
	 */

	// try to add the SOA to the response again (last RR)
	assert(KNOT_PKT_IN_AN(xfr->response));
	ret = knot_pkt_put(xfr->response, 0, soa_rrset, KNOT_PF_NOTRUNC);
	if (ret == KNOT_ESPACE) {

		// if there is not enough space, send the response and
		// add the SOA record to a new packet
		dbg_ns("Packet full, sending..\n");
		ret = ns_xfr_send_and_clear(xfr,
			knot_ns_tsig_required(xfr->packet_nr));
		if (ret != KNOT_EOK) {
			return ret;
		}

		assert(KNOT_PKT_IN_AN(xfr->response));
		ret = knot_pkt_put(xfr->response, 0, soa_rrset, KNOT_PF_NOTRUNC);
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
	int res;

	if (knot_rrset_rdata_rr_count(rrset) > 0) {
		assert(KNOT_PKT_IN_AN(xfr->response));
		res = knot_pkt_put(xfr->response, 0, rrset, KNOT_PF_NOTRUNC);
	} else {
		res = KNOT_ENORRSET;
	}

	if (res == KNOT_ESPACE) {
		knot_wire_set_rcode(xfr->response->wire, KNOT_RCODE_NOERROR);
		/*! \todo Probably rename the function. */
		ns_xfr_send_and_clear(xfr, knot_ns_tsig_required(xfr->packet_nr));
		assert(KNOT_PKT_IN_AN(xfr->response));
		res = knot_pkt_put(xfr->response, 0, rrset, KNOT_PF_NOTRUNC);
	}

	if (res != KNOT_EOK) {
		dbg_ns("Error putting RR to IXFR reply: %s\n",
			 knot_strerror(res));
		/*! \todo Probably send back AXFR instead. */
		knot_wire_set_rcode(xfr->response->wire,
		                           KNOT_RCODE_SERVFAIL);
		ns_xfr_send_and_clear(xfr, 1);
		return res;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int ns_ixfr_put_changeset(knot_ns_xfr_t *xfr,
                                 const knot_changeset_t *chgset)
{
	// 1) put origin SOA
	int res = ns_ixfr_put_rrset(xfr, chgset->soa_from);
	if (res != KNOT_EOK) {
		return res;
	}

	// 2) put remove RRSets
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chgset->remove) {
		knot_rrset_t *rr_rem = rr_node->rr;
		res = ns_ixfr_put_rrset(xfr, rr_rem);
		if (res != KNOT_EOK) {
			return res;
		}
	}

	// 3) put target SOA
	res = ns_ixfr_put_rrset(xfr, chgset->soa_to);
	if (res != KNOT_EOK) {
		return res;
	}

	// 4) put add RRSets
	WALK_LIST(rr_node, chgset->add) {
		knot_rrset_t *rr_add = rr_node->rr;
		res = ns_ixfr_put_rrset(xfr, rr_add);
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
	assert(xfr->data != NULL);

	rcu_read_lock();

	knot_changesets_t *chgsets = (knot_changesets_t *)xfr->data;
	knot_zone_contents_t *contents = knot_zone_get_contents(xfr->zone);
	assert(contents);
	knot_rrset_t *zone_soa =
		knot_node_get_rrset(knot_zone_contents_apex(contents),
		                    KNOT_RRTYPE_SOA);

	// 4) put the zone SOA as the first Answer RR
	assert(KNOT_PKT_IN_AN(xfr->response));
	int res = knot_pkt_put(xfr->response, 0, zone_soa, KNOT_PF_NOTRUNC);
	if (res != KNOT_EOK) {
		dbg_ns("IXFR query cannot be answered: %s.\n",
		       knot_strerror(res));
		knot_wire_set_rcode(xfr->response->wire,
		                           KNOT_RCODE_SERVFAIL);
		ns_xfr_send_and_clear(xfr, 1);
		rcu_read_unlock();
		return res;
	}

	// 5) put the changesets into the response while they fit in
	knot_changeset_t *chs = NULL;
	WALK_LIST(chs, chgsets->sets) {
		res = ns_ixfr_put_changeset(xfr, chs);
		if (res != KNOT_EOK) {
			// answer is sent
			rcu_read_unlock();
			return res;
		} else {
			log_zone_info("%s Serial %u -> %u.\n",
			              xfr->msg,
			              knot_rdata_soa_serial(chs->soa_from),
			              knot_rdata_soa_serial(chs->soa_to));
		}
	}

	if (!EMPTY_LIST(chgsets->sets)) {
		res = ns_ixfr_put_rrset(xfr, zone_soa);
	}

	if (res == KNOT_EOK) {
		ns_xfr_send_and_clear(xfr, 1);
	}

	rcu_read_unlock();

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int ns_ixfr(knot_ns_xfr_t *xfr)
{
	assert(xfr != NULL);
	assert(xfr->query != NULL);
	assert(xfr->response != NULL);
	assert(knot_pkt_qtype(xfr->response) == KNOT_RRTYPE_IXFR);

	// check if there is the required authority record
	const knot_pktsection_t *authority = knot_pkt_section(xfr->query, KNOT_AUTHORITY);
	if (authority->count <= 0) {
		// malformed packet
		dbg_ns("IXFR query does not contain authority record.\n");
		knot_wire_set_rcode(xfr->response->wire, KNOT_RCODE_FORMERR);
		if (ns_xfr_send_and_clear(xfr, 1) == KNOT_ECONN) {
			return KNOT_ECONN;
		}
		//socket_close(xfr->session);
		return KNOT_EMALF;
	}

	const knot_dname_t *qname = knot_pkt_qname(xfr->response);
	const knot_rrset_t *soa = authority->rr[0]; /* First record. */

	// check if XFR QNAME and SOA correspond
	if (knot_pkt_qtype(xfr->query) != KNOT_RRTYPE_IXFR
	    || knot_rrset_type(soa) != KNOT_RRTYPE_SOA
	    || knot_dname_cmp(qname, knot_rrset_owner(soa)) != 0) {
		// malformed packet
		dbg_ns("IXFR query is malformed.\n");
		knot_wire_set_rcode(xfr->response->wire, KNOT_RCODE_FORMERR);
		if (ns_xfr_send_and_clear(xfr, 1) == KNOT_ECONN) {
			return KNOT_ECONN;
		}
		return KNOT_EMALF;
	}

	return ns_ixfr_from_zone(xfr);
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

int ns_ixfr_load_serials(const knot_ns_xfr_t *xfr, uint32_t *serial_from,
                         uint32_t *serial_to)
{
	if (xfr == NULL || xfr->zone == NULL || serial_from == NULL
	    || serial_to == NULL) {
		return KNOT_EINVAL;
	}

	const knot_zone_t *zone = xfr->zone;
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	if (!contents) {
		dbg_ns("Missing contents\n");
		return KNOT_EINVAL;
	}

	if (knot_zone_contents_apex(contents) == NULL) {
		dbg_ns("No apex.\n");
		return KNOT_EINVAL;
	}

	const knot_rrset_t *zone_soa =
		knot_node_rrset(knot_zone_contents_apex(contents),
		                  KNOT_RRTYPE_SOA);
	if (zone_soa == NULL) {
		dbg_ns("No SOA.\n");
		return KNOT_EINVAL;
	}

	const knot_pktsection_t *authority = knot_pkt_section(xfr->query, KNOT_AUTHORITY);
	if (authority->count < 1) {
		dbg_ns("No Authority record.\n");
		return KNOT_EMALF;
	}

	// retrieve origin (xfr) serial and target (zone) serial
	*serial_to = knot_rdata_soa_serial(zone_soa);
	*serial_from = knot_rdata_soa_serial(authority->rr[0]);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_xfr_send_error(const knot_nameserver_t *nameserver,
                           knot_ns_xfr_t *xfr, knot_rcode_t rcode)
{
	/*! \todo Handle TSIG errors differently. */
	knot_wire_set_rcode(xfr->response->wire, rcode);

	int ret = 0;
	if ((ret = ns_xfr_send_and_clear(xfr, 1)) != KNOT_EOK
	    || xfr->response == NULL) {
		size_t size = 0;
		knot_ns_error_response_from_query(nameserver, xfr->query,
		                                  KNOT_RCODE_SERVFAIL,
		                                  xfr->wire, &size);
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire, size);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_axfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || nameserver == NULL || xfr->zone == NULL) {
		return KNOT_EINVAL;
	}

	rcu_read_lock();

	// take the contents and answer from them
	int ret = 0;
	knot_zone_contents_t *contents = knot_zone_get_contents(xfr->zone);
	if (!contents) {
		dbg_ns("AXFR failed on stub zone\n");
		knot_ns_xfr_send_error(nameserver, xfr, KNOT_RCODE_SERVFAIL);
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire,
				xfr->wire_size);
		rcu_read_unlock();
		knot_pkt_free(&xfr->response);
		return ret;
	}

	/*
	 * The TSIG data should already be stored in 'xfr'.
	 * Now just count the expected size of the TSIG RR and save it
	 * to the response structure.
	 */
	knot_pkt_tsig_set(xfr->response, xfr->tsig_key);

	ret = ns_axfr_from_zone(contents, xfr);

	/*! \todo Somehow distinguish when it makes sense to send the SERVFAIL
	 *        and when it does not. E.g. if there was problem in sending
	 *        packet, it will probably fail when sending the SERVFAIL also.
	 */
	if (ret < 0 && ret != KNOT_ECONN) {
		dbg_ns("AXFR failed, sending SERVFAIL.\n");
		// now only one type of error (SERVFAIL), later maybe more
		/*! \todo #2176 This should send error response every time. */
		knot_ns_xfr_send_error(nameserver, xfr, KNOT_RCODE_SERVFAIL);
	} else if (ret > 0) {
		ret = KNOT_ERROR;
	}

	rcu_read_unlock();

	knot_pkt_free(&xfr->response);

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_ixfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	if (nameserver == NULL || xfr == NULL || xfr->zone == NULL
	    || xfr->response == NULL) {
		return KNOT_EINVAL;
	}

	// parse rest of the packet (we need the Authority record)
	int ret = knot_pkt_parse_payload(xfr->query, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the packet: %s. "
		       "Reply FORMERR.\n", knot_strerror(ret));
		knot_ns_xfr_send_error(nameserver, xfr, KNOT_RCODE_FORMERR);
		knot_pkt_free(&xfr->response);
		return ret;
	}

	// check if the zone has contents
	if (knot_zone_contents(xfr->zone) == NULL) {
		dbg_ns("Zone expired or not bootstrapped. Reply SERVFAIL.\n");
		ret = knot_ns_xfr_send_error(nameserver, xfr, KNOT_RCODE_SERVFAIL);
		knot_pkt_free(&xfr->response);
		return ret;
	}

	/*
	 * The TSIG data should already be stored in 'xfr'.
	 * Now just count the expected size of the TSIG RR and save it
	 * to the response structure. This should be optional, only if
	 * the request contained TSIG, i.e. if there is the data in 'xfr'.
	 */
	knot_pkt_tsig_set(xfr->response, xfr->tsig_key);

	ret = ns_ixfr(xfr);

	knot_pkt_free(&xfr->response);

	return ret;
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
