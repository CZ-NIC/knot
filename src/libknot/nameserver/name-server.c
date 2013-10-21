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
#include "libknot/packet/packet.h"
#include "libknot/packet/response.h"
#include "libknot/packet/query.h"
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
		const knot_dname_t *parent = knot_wire_next_label(qname, NULL);
		zone = knot_zonedb_find_zone_for_name(zdb, parent);
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
static int ns_check_wildcard(const knot_dname_t *name, knot_packet_t *resp,
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

		int ret = knot_packet_add_tmp_rrset(resp, synth_rrset);
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to add sythetized RRSet to tmp list.\n");
			knot_rrset_deep_free(&synth_rrset, 1);
			return ret;
		}
		*rrset = synth_rrset;
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
static int ns_add_rrsigs(knot_rrset_t *rrset, knot_packet_t *resp,
                         const knot_dname_t *name,
                         int (*add_rrset_to_resp)(knot_packet_t *,
                                                   knot_rrset_t *,
                                                   int, int, int),
                         int tc)
{
	knot_rrset_t *rrsigs;

	dbg_ns_verb("Adding RRSIGs for RRSet, type: %u.\n", knot_rrset_type(rrset));

	assert(resp != NULL);
	assert(add_rrset_to_resp != NULL);

	dbg_ns_detail("DNSSEC requested: %d\n",
	              knot_query_dnssec_requested(knot_packet_query(resp)));
	dbg_ns_detail("RRSIGS: %p\n", knot_rrset_rrsigs(rrset));

	if (DNSSEC_ENABLED
	    && (knot_query_dnssec_requested(knot_packet_query(resp))
	        || knot_packet_qtype(resp) == KNOT_RRTYPE_ANY)
	    && (rrsigs = knot_rrset_get_rrsigs(rrset)) != NULL) {
		if (name != NULL) {
			int ret = ns_check_wildcard(name, resp, &rrsigs);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to process wildcard: %s\n",
				       knot_strerror(ret));
				return ret;
			}
		}
		return add_rrset_to_resp(resp, rrsigs, tc, 1, 1);
	}

	return KNOT_EOK;
}

/* Wrapper functions for lists. */
typedef struct chain_node {
	node_t n;
	const knot_node_t *kn_node;
} chain_node_t;

static int cname_chain_add(list_t *chain, const knot_node_t *kn_node)
{
	assert(chain != NULL);
	chain_node_t *new_node = malloc(sizeof(chain_node_t));
	CHECK_ALLOC_LOG(new_node, KNOT_ENOMEM);

	new_node->kn_node = kn_node;
	add_tail(chain, (node_t *)new_node);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int cname_chain_contains(const list_t *chain, const knot_node_t *kn_node)
{
	node_t *n = NULL;
	WALK_LIST(n, *chain) {
		chain_node_t *l_node = (chain_node_t *)n;
		if (l_node->kn_node == kn_node) {
			return 1;
		}
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

static void cname_chain_free(list_t *chain)
{
	WALK_LIST_FREE(*chain);
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
static int ns_follow_cname(const knot_node_t **node,
                            const knot_dname_t **qname,
                            knot_packet_t *resp,
                            int (*add_rrset_to_resp)(knot_packet_t *,
                                                     knot_rrset_t *,
                                                     int, int, int),
                            int tc)
{
	dbg_ns_verb("Resolving CNAME chain...\n");
	knot_rrset_t *cname_rrset;

	int ret = 0;
	int wc = 0;

	/*
	 * If stop == 1, cycle was detected, but one last entry has to be put
	 * in the packet (because of wildcard).
	 * If stop == 2, we should quit right away.
	 */
	int stop = 0;

	list_t cname_chain;
	init_list(&cname_chain);

	while (*node != NULL
	       && stop != 2
	       && (cname_rrset = knot_node_get_rrset(*node, KNOT_RRTYPE_CNAME))
	          != NULL
	       && (knot_rrset_rdata_rr_count(cname_rrset))) {
		/*
		 * Store node to chain list to sort out duplicates and cycles.
		 * Even if we follow wildcard, the result is always the same.
		 * so duplicate check does not need synthesized DNAMEs.
		 */
		if (cname_chain_add(&cname_chain, *node) != KNOT_EOK) {
			dbg_ns("Failed to add node to CNAME chain\n");
			cname_chain_free(&cname_chain);
			return KNOT_ENOMEM;
		}

		/* put the CNAME record to answer, but replace the possible
		   wildcard name with qname */

		assert(cname_rrset != NULL);

		dbg_ns_detail("CNAME RRSet: %p, owner: %p\n", cname_rrset,
		              cname_rrset->owner);

		knot_rrset_t *rrset = cname_rrset;

		// ignoring other than the first record
		if (knot_dname_is_wildcard(knot_node_owner(*node))) {
			wc = 1;
			/* if wildcard node, we must copy the RRSet and
			   replace its owner */
			rrset = ns_synth_from_wildcard(cname_rrset, *qname);
			if (rrset == NULL) {
				dbg_ns("Failed to synthetize RRSet from "
				       "wildcard RRSet followed from CNAME.\n");
				cname_chain_free(&cname_chain);
				return KNOT_ERROR; /*! \todo Better error. */
			}

			ret = knot_packet_add_tmp_rrset(resp, rrset);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to add synthetized RRSet (CNAME "
				       "follow) to the tmp RRSets in response."
				       "\n");
				knot_rrset_deep_free(&rrset, 1);
				cname_chain_free(&cname_chain);
				return ret;
			}

			ret = add_rrset_to_resp(resp, rrset, tc, 0, 1);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to add synthetized RRSet (CNAME "
				       "follow) to the response.\n");
				cname_chain_free(&cname_chain);
				return ret;
			}

			ret = ns_add_rrsigs(cname_rrset, resp, *qname,
			                    add_rrset_to_resp, tc);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to add RRSIG for the synthetized"
				       "RRSet (CNAME follow) to the response."
				       "\n");
				cname_chain_free(&cname_chain);
				return ret;
			}

			int ret = knot_response_add_wildcard_node(
			                        resp, *node, *qname);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to add wildcard node for later "
				       "processing.\n");
				cname_chain_free(&cname_chain);
				return ret;
			}
		} else {
			ret = add_rrset_to_resp(resp, rrset, tc, 0, 1);

			if (ret != KNOT_EOK) {
				dbg_ns("Failed to add followed RRSet into"
				       "the response.\n");
				cname_chain_free(&cname_chain);
				return ret;
			}

			ret = ns_add_rrsigs(rrset, resp, *qname,
			                    add_rrset_to_resp, tc);

			if (ret != KNOT_EOK) {
				dbg_ns("Failed to add RRSIG for followed RRSet "
				       "into the response.\n");
				cname_chain_free(&cname_chain);
				return ret;
			}
		}

		dbg_ns_detail("Using RRSet: %p, owner: %p\n", rrset,
		              rrset->owner);

dbg_ns_exec_verb(
		char *name = knot_dname_to_str(knot_rrset_owner(rrset));
		dbg_ns("CNAME record for owner %s put to response.\n", name);
		free(name);
);

		// get the name from the CNAME RDATA
		const knot_dname_t *cname =
			knot_rdata_cname_name(cname_rrset);
		dbg_ns_detail("CNAME name from RDATA: %p\n", cname);

		/* Attempt to find mentioned name in zone. */
		rcu_read_lock();
		const knot_zone_t *zone = resp->zone;
		knot_zone_contents_t *contents = knot_zone_get_contents(zone);
		const knot_node_t *encloser = NULL, *prev = NULL;
		knot_zone_contents_find_dname(contents, cname, node, &encloser, &prev);
		if (*node == NULL && encloser && encloser->wildcard_child)
			*node = encloser->wildcard_child;
		rcu_read_unlock();
		dbg_ns_detail("This name's node: %p\n", *node);

		// save the new name which should be used for replacing wildcard
		*qname = cname;

		// Decide if we stop or not
		if (stop == 1) {
			// Exit loop
			stop = 2;
		} else if (cname_chain_contains(&cname_chain, *node)) {
			if (wc) {
				// Do one more loop
				stop = 1;
			} else {
				// No wc, exit right away
				stop = 2;
			}
		}
	}

	cname_chain_free(&cname_chain);

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
static int ns_put_answer(const knot_node_t *node,
                         const knot_zone_contents_t *zone,
                         const knot_dname_t *name,
                         uint16_t type, knot_packet_t *resp, int *added,
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
			knot_response_set_tc(resp);
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

				ret = ns_check_wildcard(name, resp, &rrset);
				if (ret != KNOT_EOK) {
					dbg_ns("Failed to process wildcard.\n");
					break;
				}

				ret = knot_response_add_rrset_answer(resp,
				                                     rrset, 1,
				                                     0, 1);
				if (ret != KNOT_EOK) {
					dbg_ns("Failed add Answer RRSet: %s\n",
					       knot_strerror(ret));
					break;
				}

				*added += 1;
			}

			ret = ns_add_rrsigs(rrset, resp, name,
			                    knot_response_add_rrset_answer, 1);
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

			ret = ns_check_wildcard(name, resp, &rrset);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to process wildcard.\n");
				break;
			}

			ret = knot_response_add_rrset_answer(resp, rrset, 1,
			                                     0, 1);
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

			ret = ns_check_wildcard(name, resp, &rrset2);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed to process wildcard.\n");
				break;
			}

			ret = knot_response_add_rrset_answer(resp, rrset2, 1,
			                                     0, 1);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed add Answer RRSet: %s\n",
				       knot_strerror(ret));
				break;
			}

			*added += 1;

			ret = ns_add_rrsigs(rrset, resp, name,
			                    knot_response_add_rrset_answer, 1);

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
static int ns_put_additional_for_rrset(knot_packet_t *resp,
                                       const knot_rrset_t *rrset)
{
	const knot_node_t *node = NULL, *encloser = NULL, *prev = NULL;

	int ret = 0;

	// for all RRs in the RRset
	/* TODO all dnames, or only the ones returned by rdata_get_name? */
	for (uint16_t i = 0; i < knot_rrset_rdata_rr_count(rrset); i++) {
		dbg_ns_verb("Getting name from RDATA, type %u..\n",
		            knot_rrset_type(rrset));
		const knot_dname_t *dname = knot_rdata_name(rrset, i);
		assert(dname);
dbg_ns_exec_detail(
		char *name = knot_dname_to_str(dname);
		dbg_ns_detail("Name: %s\n", name);
		free(name);
);
		assert(dname != NULL);

		/* Attempt to find mentioned name in zone. */
		rcu_read_lock();
		const knot_zone_t *zone = resp->zone;
		knot_zone_contents_t *contents = knot_zone_get_contents(zone);
		knot_zone_contents_find_dname(contents, dname, &node, &encloser, &prev);
		if (node == NULL && encloser && encloser->wildcard_child)
			node = encloser->wildcard_child;
		rcu_read_unlock();

		knot_rrset_t *rrset_add;

		if (node != NULL) {
dbg_ns_exec(
			char *name = knot_dname_to_str(node->owner);
			dbg_ns_verb("Putting additional from node %s\n", name);
			free(name);
);
			dbg_ns_detail("Checking CNAMEs...\n");
			if (knot_node_rrset(node, KNOT_RRTYPE_CNAME) != NULL) {
				dbg_ns_detail("Found CNAME in node.\n");
				const knot_dname_t *dname
						= knot_node_owner(node);
				ret = ns_follow_cname(&node, &dname, resp,
				    knot_response_add_rrset_additional, 0);
				if (ret != KNOT_EOK) {
					dbg_ns("Failed to follow CNAME.\n");
					return ret;
				}
			}

			// A RRSet
			dbg_ns_detail("A RRSets...\n");
			rrset_add = knot_node_get_rrset(node, KNOT_RRTYPE_A);
			if (rrset_add != NULL) {
				dbg_ns_detail("Found A RRsets.\n");
				knot_rrset_t *rrset_add2 = rrset_add;
				ret = ns_check_wildcard(dname, resp,
				                        &rrset_add2);
				if (ret != KNOT_EOK) {
					dbg_ns("Failed to process wildcard for"
					       "Additional section: %s.\n",
					       knot_strerror(ret));
					return ret;
				}

				ret = knot_response_add_rrset_additional(
					resp, rrset_add2, 0, 1, 1);

				if (ret != KNOT_EOK) {
					dbg_ns("Failed to add A RRSet to "
					       "Additional section: %s.\n",
					       knot_strerror(ret));
					return ret;
				}

				ret = ns_add_rrsigs(rrset_add, resp, dname,
				      knot_response_add_rrset_additional, 0);

				if (ret != KNOT_EOK) {
					dbg_ns("Failed to add RRSIGs for A RR"
					       "Set to Additional section: %s."
					       "\n", knot_strerror(ret));
					return ret;
				}
			}

			// AAAA RRSet
			dbg_ns_detail("AAAA RRSets...\n");
			rrset_add = knot_node_get_rrset(node, KNOT_RRTYPE_AAAA);
			if (rrset_add != NULL) {
				dbg_ns_detail("Found AAAA RRsets.\n");
				knot_rrset_t *rrset_add2 = rrset_add;
				ret =  ns_check_wildcard(dname, resp,
				                         &rrset_add2);
				if (ret != KNOT_EOK) {
					dbg_ns("Failed to process wildcard for"
					       "Additional section: %s.\n",
					       knot_strerror(ret));
					return ret;
				}

				ret = knot_response_add_rrset_additional(
					resp, rrset_add2, 0, 1, 1);

				if (ret != KNOT_EOK) {
					dbg_ns("Failed to add AAAA RRSet to "
					       "Additional section.\n");
					return ret;
				}

				ret = ns_add_rrsigs(rrset_add, resp, dname,
				      knot_response_add_rrset_additional, 0);

				if (ret != KNOT_EOK) {
					dbg_ns("Failed to add RRSIG for AAAA RR"
					       "Set to Additional section.\n");
					return ret;
				}
			}
		}

		assert(rrset != NULL);
	}

	return KNOT_EOK;
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
static int ns_put_additional(knot_packet_t *resp)
{
	dbg_ns_verb("ADDITIONAL SECTION PROCESSING\n");

	const knot_rrset_t *rrset = NULL;
	int ret = 0;

	for (int i = 0; i < knot_packet_answer_rrset_count(resp); ++i) {
		rrset = knot_packet_answer_rrset(resp, i);
		assert(rrset != NULL);
		if (ns_additional_needed(knot_rrset_type(rrset))) {
			ret = ns_put_additional_for_rrset(resp, rrset);
			if (ret != KNOT_EOK) {
				// if error, do not try to add other RRSets
				return ret;
			}
		}
	}

	for (int i = 0; i < knot_packet_authority_rrset_count(resp); ++i) {
		rrset = knot_packet_authority_rrset(resp, i);
		if (ns_additional_needed(knot_rrset_type(rrset))) {
			ret = ns_put_additional_for_rrset(resp, rrset);
			if (ret != KNOT_EOK) {
				// if error, do not try to add other RRSets
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Puts authority NS RRSet to the Auhority section of the response.
 *
 * \param zone Zone to take the authority NS RRSet from.
 * \param resp Response where to add the RRSet.
 */
static int ns_put_authority_ns(const knot_zone_contents_t *zone,
                                knot_packet_t *resp)
{
	dbg_ns_verb("PUTTING AUTHORITY NS\n");

	knot_rrset_t *ns_rrset = knot_node_get_rrset(
			knot_zone_contents_apex(zone), KNOT_RRTYPE_NS);

	if (ns_rrset != NULL) {
		int ret = knot_response_add_rrset_authority(resp, ns_rrset, 0,
		                                            1, 1);

		if (ret != KNOT_EOK) {
			dbg_ns("Failed to add Authority NSs to response.\n");
			return ret;
		}

		ret = ns_add_rrsigs(ns_rrset, resp, knot_node_owner(
		              knot_zone_contents_apex(zone)),
		              knot_response_add_rrset_authority, 1);

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
static int ns_put_authority_soa(const knot_zone_contents_t *zone,
                                 knot_packet_t *resp)
{
	dbg_ns_verb("PUTTING AUTHORITY SOA\n");

	int ret;

	knot_rrset_t *soa_rrset = knot_node_get_rrset(
			knot_zone_contents_apex(zone), KNOT_RRTYPE_SOA);
	assert(soa_rrset != NULL);

	// if SOA's TTL is larger than MINIMUM, copy the RRSet and set
	// MINIMUM as TTL
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
		ret = knot_packet_add_tmp_rrset(resp, soa_copy);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&soa_copy, 1);
			return ret;
		}
	}

	assert(soa_rrset != NULL);

	ret = knot_response_add_rrset_authority(resp, soa_rrset, 0, 0, 1);
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
                                  knot_packet_t *resp)
{
	assert(DNSSEC_ENABLED
	       && knot_query_dnssec_requested(knot_packet_query(resp)));

	knot_rrset_t *rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NSEC3);
	//assert(rrset != NULL);

	if (rrset == NULL) {
		// bad zone, ignore
		return KNOT_EOK;
	}

	int res = KNOT_EOK;
	if (knot_rrset_rdata_rr_count(rrset)) {
		res = knot_response_add_rrset_authority(resp, rrset, 1, 1, 1);
	}
	// add RRSIG for the RRSet
	if (res == KNOT_EOK && (rrset = knot_rrset_get_rrsigs(rrset)) != NULL
	    && knot_rrset_rdata_rr_count(rrset)) {
		res = knot_response_add_rrset_authority(resp, rrset, 1, 0, 1);
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
                                 knot_packet_t *resp)
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
                                         knot_packet_t *resp)
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

	knot_dname_t *wildcard = knot_dname_from_str("*", 1);
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
static int ns_put_nsec_nsec3_nodata(const knot_zone_contents_t *zone,
                                    const knot_node_t *node,
                                    knot_packet_t *resp)
{
	if (!DNSSEC_ENABLED ||
	    !knot_query_dnssec_requested(knot_packet_query(resp))) {
		return KNOT_EOK;
	}

	/*! \todo Maybe distinguish different errors. */
	int ret = KNOT_ERROR;

	knot_rrset_t *rrset = NULL;

	if (knot_zone_contents_nsec3_enabled(zone)) {
		knot_node_t *nsec3_node = knot_node_get_nsec3_node(node);
		dbg_ns_verb("Adding NSEC3 for NODATA, NSEC3 node: %p\n",
		            nsec3_node);

		if (nsec3_node != NULL
		    && (rrset = knot_node_get_rrset(nsec3_node,
		                                  KNOT_RRTYPE_NSEC3)) != NULL
		    && knot_rrset_rdata_rr_count(rrset)) {
			dbg_ns_detail("Putting the RRSet to Authority\n");
			ret = knot_response_add_rrset_authority(resp, rrset, 1,
			                                        0, 1);
		} else {
			return KNOT_ENONODE;
		}
	} else {
		dbg_ns_verb("Adding NSEC for NODATA\n");
		if ((rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NSEC))
		    != NULL
		    && knot_rrset_rdata_rr_count(rrset)) {
			dbg_ns_detail("Putting the RRSet to Authority\n");
			ret = knot_response_add_rrset_authority(resp, rrset, 1,
			                                        0, 1);
		}
	}

	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_ns_detail("Putting RRSet's RRSIGs to Authority\n");
	if (rrset != NULL && (rrset = knot_rrset_get_rrsigs(rrset)) != NULL) {
		ret = knot_response_add_rrset_authority(resp, rrset, 1,
		                                        0, 1);
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
                                knot_packet_t *resp)
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

	int ret = knot_response_add_rrset_authority(resp, rrset, 1, 0, 1);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to add NSEC for NXDOMAIN to response: %s\n",
		       knot_strerror(ret));
		return ret;
	}

	rrset = knot_rrset_get_rrsigs(rrset);
	//assert(rrset != NULL);
	ret = knot_response_add_rrset_authority(resp, rrset, 1, 0, 1);
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
		ret = knot_response_add_rrset_authority(resp, rrset, 1, 0, 1);
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
		ret = knot_response_add_rrset_authority(resp, rrset, 1, 0, 1);
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
                                 knot_packet_t *resp)
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
                                knot_packet_t *resp)
{
	assert(DNSSEC_ENABLED
	       && knot_query_dnssec_requested(knot_packet_query(resp)));

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
		ret = knot_response_add_rrset_authority(resp, rrset, 1, 0,
		                                        1);
		if (ret == KNOT_EOK) {
			rrset = knot_rrset_get_rrsigs(rrset);
			//assert(rrset != NULL);
			ret = knot_response_add_rrset_authority(resp, rrset, 1,
			                                        0, 1);
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
static int ns_put_nsec_nsec3_wildcard_answer(const knot_node_t *node,
                                          const knot_node_t *closest_encloser,
                                          const knot_node_t *previous,
                                          const knot_zone_contents_t *zone,
                                          const knot_dname_t *qname,
                                          knot_packet_t *resp)
{
	// if wildcard answer, add NSEC / NSEC3

	int ret = KNOT_EOK;
	if (DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))
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

static int ns_put_nsec_nsec3_wildcard_nodes(knot_packet_t *response,
                                            const knot_zone_contents_t *zone)
{
	assert(response != NULL);
	assert(zone != NULL);

	int ret = 0;

	for (int i = 0; i < response->wildcard_nodes.count; ++i) {
		ret = ns_put_nsec_nsec3_wildcard_answer(
		                        response->wildcard_nodes.nodes[i],
		                        knot_node_parent(
		                            response->wildcard_nodes.nodes[i]),
		                        NULL, zone,
		                        response->wildcard_nodes.snames[i],
		                        response);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
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
	dbg_ns_verb("Referral response.\n");

	while (!knot_node_is_deleg_point(node)) {
		assert(knot_node_parent(node) != NULL);
		node = knot_node_parent(node);
	}

	int at_deleg = knot_dname_is_equal(qname, knot_node_owner(node));

	int ret = KNOT_EOK;

	// Special handling of DS queries
	if (qtype == KNOT_RRTYPE_DS && at_deleg) {
		knot_rrset_t *ds_rrset = knot_node_get_rrset(node,
		                                             KNOT_RRTYPE_DS);

		if (ds_rrset && knot_rrset_rdata_rr_count(ds_rrset) > 0) {
			ret = knot_response_add_rrset_answer(resp, ds_rrset, 1,
			                                     0, 1);
			if (ret == KNOT_EOK && DNSSEC_ENABLED
			    && knot_query_dnssec_requested(
			                        knot_packet_query(resp))) {
				ret = ns_add_rrsigs(ds_rrset, resp, node->owner,
				              knot_response_add_rrset_answer,
				              1);
			}
		} else {
			// normal NODATA response
			/*! \todo Handle in some generic way. */

			dbg_ns_verb("Adding NSEC/NSEC3 for NODATA.\n");
			ret = ns_put_nsec_nsec3_nodata(zone, node, resp);

			if (ret == KNOT_ENONODE) {
				// No NSEC3 node => Opt-out
				const knot_node_t *closest_encloser = node;
				ret = ns_put_nsec3_closest_encloser_proof(zone,
				                              &closest_encloser,
				                              qname, resp);

			} else if (ret != KNOT_EOK) {
				return ret;
			}

			ret = ns_put_authority_soa(zone, resp);
		}

		// This is an authoritative answer, set AA bit
		knot_response_set_aa(resp);

		return ret;
	}

	knot_rrset_t *rrset = knot_node_get_rrset(node, KNOT_RRTYPE_NS);
	assert(rrset != NULL);

	ret = knot_response_add_rrset_authority(resp, rrset, 1, 0, 1);
	if (ret == KNOT_EOK) {
		ret = ns_add_rrsigs(rrset, resp, node->owner,
		                    knot_response_add_rrset_authority, 1);
	}

	// add DS records
	dbg_ns_verb("DNSSEC requested: %d\n",
		 knot_query_dnssec_requested(knot_packet_query(resp)));
	dbg_ns_verb("DS records: %p\n", knot_node_rrset(node, KNOT_RRTYPE_DS));
	if (ret == KNOT_EOK && DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))) {
		rrset = knot_node_get_rrset(node, KNOT_RRTYPE_DS);
		if (rrset != NULL) {
			ret = knot_response_add_rrset_authority(resp, rrset, 1,
			                                        0, 1);
			if (ret == KNOT_EOK) {
				ret = ns_add_rrsigs(rrset, resp, node->owner,
				          knot_response_add_rrset_authority, 1);
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
					ret = knot_response_add_rrset_authority(
						resp, nsec, 1, 1, 1);
					if (ret == KNOT_EOK &&
					    (nsec = knot_rrset_get_rrsigs(nsec)) != NULL) {
						ret = knot_response_add_rrset_authority(
						        resp, nsec, 1, 1, 1);
					}
				}
			}
		}
	}

	if (ret == KNOT_ESPACE) {
		knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);
		ret = KNOT_EOK;
	} else if (ret == KNOT_EOK) {
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
                               knot_packet_t *resp, int check_any)
{
	dbg_ns_verb("Putting answers from found node to the response...\n");
	int answers = 0;

	int ret = ns_put_answer(node, zone, qname, qtype, resp, &answers,
	                        check_any);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(ret == KNOT_EOK);

	if (answers == 0) {  // if NODATA response, put SOA
		ret = ns_put_authority_soa(zone, resp);
		if (knot_node_rrset_count(node) == 0
		    && !knot_zone_contents_nsec3_enabled(zone)) {
			// node is an empty non-terminal => NSEC for NXDOMAIN
			//assert(knot_node_rrset_count(closest_encloser) > 0);
			dbg_ns_verb("Adding NSEC/NSEC3 for NXDOMAIN.\n");
			ret = ns_put_nsec_nsec3_nxdomain(zone,
				knot_node_previous(node), closest_encloser,
				qname, resp);
		} else {
			dbg_ns_verb("Adding NSEC/NSEC3 for NODATA.\n");
			ret = ns_put_nsec_nsec3_nodata(zone, node, resp);
			if (ret != KNOT_EOK) {
				dbg_ns("Failed adding NSEC/NSEC3 for NODATA: %s"
				       "\n", knot_strerror(ret));
				return ret;
			}

			if (knot_dname_is_wildcard(node->owner)) {
				dbg_ns_verb("Putting NSEC/NSEC3 for wildcard"
				            " NODATA\n");
				ret = ns_put_nsec_nsec3_wildcard_nodata(node,
					closest_encloser, previous, zone, qname,
					resp);
				if (ret != KNOT_EOK) {
					return ret;
				}
			}
		}
	} else {  // else put authority NS
		assert(closest_encloser == knot_node_parent(node)
		      || !knot_dname_is_wildcard(knot_node_owner(node))
		      || knot_dname_cmp(qname, knot_node_owner(node)) == 0);

		ret = ns_put_nsec_nsec3_wildcard_answer(node, closest_encloser,
		                                  previous, zone, qname, resp);

		if (ret == KNOT_EOK) {
			ret = ns_put_authority_ns(zone, resp);
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
		owner, KNOT_RRTYPE_CNAME, KNOT_CLASS_IN, SYNTH_CNAME_TTL);
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
static int ns_process_dname(knot_rrset_t *dname_rrset,
                             const knot_dname_t **qname,
                             knot_packet_t *resp)
{
dbg_ns_exec_verb(
	char *name = knot_dname_to_str(knot_rrset_owner(dname_rrset));
	dbg_ns_verb("Processing DNAME for owner %s...\n", name);
	free(name);
);
	// TODO: check the number of RRs in the RRSet??

	// put the DNAME RRSet into the answer
	int ret = knot_response_add_rrset_answer(resp, dname_rrset, 1, 0, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = ns_add_rrsigs(dname_rrset, resp, *qname,
	                    knot_response_add_rrset_answer, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (ns_dname_is_too_long(dname_rrset, *qname)) {
		knot_response_set_rcode(resp, KNOT_RCODE_YXDOMAIN);
		return KNOT_EOK;
	}

	// synthetize CNAME (no way to tell that client supports DNAME)
	knot_rrset_t *synth_cname = ns_cname_from_dname(dname_rrset, *qname);
	// add the synthetized RRSet to the Answer
	ret = knot_response_add_rrset_answer(resp, synth_cname, 1, 0, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// no RRSIGs for this RRSet

	// add the synthetized RRSet into list of temporary RRSets of response
	ret = knot_packet_add_tmp_rrset(resp, synth_cname);
	if (ret != KNOT_EOK) {
		return ret;
	}

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
static int ns_add_dnskey(const knot_node_t *apex, knot_packet_t *resp)
{
	knot_rrset_t *rrset =
		knot_node_get_rrset(apex, KNOT_RRTYPE_DNSKEY);

	int ret = KNOT_EOK;

	if (rrset != NULL) {
		ret = knot_response_add_rrset_additional(resp, rrset, 0, 0,
		                                        1);
		if (ret == KNOT_EOK) {
			ret = ns_add_rrsigs(rrset, resp, apex->owner,
			              knot_response_add_rrset_additional, 0);
		}
	}

	return ret;
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
                               knot_packet_t *resp, int check_any)
{
	const knot_node_t *node = NULL, *closest_encloser = NULL,
	                    *previous = NULL;
	int cname = 0, auth_soa = 0, ret = 0, find_ret = 0;

	const knot_dname_t *qname = knot_packet_qname(resp);
	uint16_t qtype = knot_packet_qtype(resp);

search:
	// Searching for a name directly is faster than when we need previous dname
	node = knot_zone_contents_find_node(zone, qname);
	if (node != NULL) {
		// If node is found, closest_encloser is equal to node itself
		closest_encloser = node;
		find_ret = KNOT_ZONE_NAME_FOUND;
	} else {
		// We need previous and closest encloser, full search has to be done
		find_ret = knot_zone_contents_find_dname(zone, qname, &node,
		                                         &closest_encloser, &previous);
		if (find_ret == KNOT_EINVAL) {
			return NS_ERR_SERVFAIL;
		}
	}

dbg_ns_exec_verb(
	char *name;
	if (node) {
		name = knot_dname_to_str(node->owner);
		dbg_ns_verb("zone_find_dname() returned node %s \n", name);
		free(name);
	} else {
		dbg_ns_verb("zone_find_dname() returned no node,\n");
	}

	if (closest_encloser != NULL) {
		name = knot_dname_to_str(closest_encloser->owner);
		dbg_ns_verb(" closest encloser %s.\n", name);
		free(name);
	} else {
		dbg_ns_verb(" closest encloser (nil).\n");
	}
	if (previous != NULL) {
		name = knot_dname_to_str(previous->owner);
		dbg_ns_verb(" and previous node: %s.\n", name);
		free(name);
	} else {
		dbg_ns_verb(" and previous node: (nil).\n");
	}
);
	if (find_ret == KNOT_EOUTOFZONE) {
		// possible only if we followed CNAME or DNAME
		assert(cname != 0);
		knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);
		auth_soa = 1;
		knot_response_set_aa(resp);
		goto finalize;
	}

have_node:
	dbg_ns_verb("Closest encloser is deleg. point? %s\n",
		 (knot_node_is_deleg_point(closest_encloser)) ? "yes" : "no");

	dbg_ns_verb("Closest encloser is non authoritative? %s\n",
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
		if (dname_rrset != NULL
		    && knot_rrset_rdata_rr_count(dname_rrset) > 0) {
			ret = ns_process_dname(dname_rrset, &qname, resp);

			knot_response_set_aa(resp);

			if (ret != KNOT_EOK) {
				goto finalize;
			}

			// do not search for the name in new zone
			// (out-of-bailiwick), just in the current zone if it
			// belongs there

			cname = 1;
			goto search;
		}
		// else check for a wildcard child
		const knot_node_t *wildcard_node =
			knot_node_wildcard_child(closest_encloser);

		if (wildcard_node == NULL) {
			dbg_ns_verb("No wildcard node. (cname: %d)\n",
			            cname);
			auth_soa = 1;
			if (cname == 0) {
				dbg_ns_detail("Setting NXDOMAIN RCODE.\n");
				// return NXDOMAIN
				knot_response_set_rcode(resp,
					KNOT_RCODE_NXDOMAIN);
			} else {
				knot_response_set_rcode(resp,
					KNOT_RCODE_NOERROR);
			}

			if (ns_put_nsec_nsec3_nxdomain(zone, previous,
				closest_encloser, qname, resp) != 0) {
				return NS_ERR_SERVFAIL;
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

	if (knot_node_rrset(node, KNOT_RRTYPE_CNAME) != NULL
	    && qtype != KNOT_RRTYPE_CNAME && qtype != KNOT_RRTYPE_RRSIG) {
dbg_ns_exec(
		char *name = knot_dname_to_str(node->owner);
		dbg_ns("Node %s has CNAME record, resolving...\n", name);
		free(name);
);
		const knot_dname_t *act_name = qname;
		ret = ns_follow_cname(&node, &act_name, resp,
		                      knot_response_add_rrset_answer, 1);

		/*! \todo IS OK??? */
		knot_response_set_aa(resp);

		if (ret != KNOT_EOK) {
			// KNOT_ESPACE case is handled there
			goto finalize;
		}
dbg_ns_exec_verb(
		char *name = (node != NULL) ? knot_dname_to_str(node->owner)
			: "(nil)";
		char *name2 = knot_dname_to_str(act_name);
		dbg_ns_verb("Canonical name: %s (%p), node found: %p\n",
		            name2, act_name, node);
		dbg_ns_verb("The node's owner: %s (%p)\n", name, (node != NULL)
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
		} else if (knot_node_owner(node) != act_name) {
			if(knot_dname_is_wildcard(knot_node_owner(node))) {
				// we must set the closest encloser to the
				// parent of the node, to be right
				closest_encloser = knot_node_parent(node);
				assert(closest_encloser != NULL);
			} else {
				// the stored node is closest encloser
				find_ret = KNOT_ZONE_NAME_NOT_FOUND;
				closest_encloser = node;
				node = NULL;
				goto have_node;
			}
		}
	}

	ret = ns_answer_from_node(node, closest_encloser, previous, zone, qname,
	                          qtype, resp, check_any);
	if (ret == NS_ERR_SERVFAIL) {
		// in this case we should drop the response and send an error
		// for now, just send the error code with a non-complete answer
		return ret;
	} else if (ret != KNOT_EOK) {
		/*! \todo Handle RCODE return values!!! */
		// In case ret == KNOT_ESPACE, this is later converted to EOK
		// so it does not cause error response
		knot_response_set_aa(resp);
		goto finalize;
	}
	knot_response_set_aa(resp);
	knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);

	// this is the only case when the servers answers from
	// particular node, i.e. the only case when it may return SOA
	// or NS records in Answer section
	if (knot_packet_tc(resp) == 0 && DNSSEC_ENABLED
	    && knot_query_dnssec_requested(knot_packet_query(resp))
	    && node == knot_zone_contents_apex(zone)
	    && (qtype == KNOT_RRTYPE_SOA || qtype == KNOT_RRTYPE_NS)) {
		ret = ns_add_dnskey(node, resp);
	}

finalize:
	if (ret == KNOT_EOK && knot_packet_tc(resp) == 0 && auth_soa) {
		ret = ns_put_authority_soa(zone, resp);
	}

	if (ret == KNOT_ESPACE) {
		knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);
		ret = KNOT_EOK;
	}

	// add all missing NSECs/NSEC3s for wildcard nodes
	ret = ns_put_nsec_nsec3_wildcard_nodes(resp, zone);

	if (ret == KNOT_EOK) {
		ns_put_additional(resp);
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
static int ns_answer(const knot_zone_t *zone, knot_packet_t *resp,
                     int check_any)
{
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

	return ns_answer_from_zone(contents, resp, check_any);
}

/*----------------------------------------------------------------------------*/

int ns_response_to_wire(knot_packet_t *resp, uint8_t *wire,
                        size_t *wire_size)
{
	uint8_t *rwire = NULL;
	size_t rsize = 0;
	int ret = 0;

	if ((ret = knot_packet_to_wire(resp, &rwire, &rsize)) != KNOT_EOK) {
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
	dbg_ns_verb("Creating error response.\n");

	size_t rsize = knot_packet_question_size(knot_packet_query(resp));
	dbg_ns_detail("Error response (~ query) size: %zu\n", rsize);

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
			uint16_t ar_count = knot_wire_get_arcount(wire);
			knot_wire_set_arcount(wire, ar_count + 1);
			*wire_size = rsize + edns_size;
		}
	} else {
		*wire_size = rsize;
	}

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
		       " Transfer size: %zu, sent: %d\n", real_size, res);
	}

	// Clean the response structure
	dbg_ns_verb("Clearing response structure..\n");
	knot_response_clear(xfr->response);

	// increment the packet number
	++xfr->packet_nr;
	if ((xfr->tsig_key && knot_ns_tsig_required(xfr->packet_nr))
	     || xfr->tsig_rcode != 0) {
		/*! \todo Where is xfr->tsig_size set?? */
		knot_packet_set_tsig_size(xfr->response, xfr->tsig_size);
	} else {
		knot_packet_set_tsig_size(xfr->response, 0);
	}

dbg_ns_exec_verb(
	dbg_ns_verb("Response structure after clearing:\n");
	knot_packet_dump(xfr->response);
);

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

		ret = knot_response_add_rrset_answer(xfr->response, rrset,
		                                     0, 0, 0);

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

		ret = knot_response_add_rrset_answer(xfr->response, rrset,
		                                     0, 0, 0);

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
	ret = knot_response_add_rrset_answer(xfr->response, soa_rrset, 0, 0, 0);
	if (ret != KNOT_EOK) {
		// something is really wrong
		return KNOT_ERROR;
	}

	// add the SOA's RRSIG
	knot_rrset_t *rrset = knot_rrset_get_rrsigs(soa_rrset);
	if (rrset != NULL
	    && (ret = knot_response_add_rrset_answer(xfr->response, rrset,
	                                             0, 0, 0)) != KNOT_EOK) {
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
	ret = knot_response_add_rrset_answer(xfr->response, soa_rrset, 0, 0, 0);
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
		                                     soa_rrset, 0, 0, 0);
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
		res = knot_response_add_rrset_answer(xfr->response, rrset,
	                                             0, 0, 0);
	} else {
		res = KNOT_ENORRSET;
	}

	if (res == KNOT_ESPACE) {
		knot_response_set_rcode(xfr->response, KNOT_RCODE_NOERROR);
		/*! \todo Probably rename the function. */
		ns_xfr_send_and_clear(xfr, knot_ns_tsig_required(xfr->packet_nr));

		res = knot_response_add_rrset_answer(xfr->response,
		                                     rrset, 0, 0, 0);
	}

	if (res != KNOT_EOK) {
		dbg_ns("Error putting RR to IXFR reply: %s\n",
			 knot_strerror(res));
		/*! \todo Probably send back AXFR instead. */
		knot_response_set_rcode(xfr->response,
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
	assert(knot_packet_authority_rrset_count(xfr->query) > 0);
	assert(xfr->data != NULL);

	rcu_read_lock();

	knot_changesets_t *chgsets = (knot_changesets_t *)xfr->data;
	knot_zone_contents_t *contents = knot_zone_get_contents(xfr->zone);
	assert(contents);
	knot_rrset_t *zone_soa =
		knot_node_get_rrset(knot_zone_contents_apex(contents),
		                    KNOT_RRTYPE_SOA);

	// 4) put the zone SOA as the first Answer RR
	int res = knot_response_add_rrset_answer(xfr->response, zone_soa, 0,
	                                         0, 0);
	if (res != KNOT_EOK) {
		dbg_ns("IXFR query cannot be answered: %s.\n",
		       knot_strerror(res));
		knot_response_set_rcode(xfr->response,
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
	assert(knot_packet_qtype(xfr->response) == KNOT_RRTYPE_IXFR);

	// check if there is the required authority record
	if ((knot_packet_authority_rrset_count(xfr->query) <= 0)) {
		// malformed packet
		dbg_ns("IXFR query does not contain authority record.\n");
		knot_response_set_rcode(xfr->response, KNOT_RCODE_FORMERR);
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
	    || knot_dname_cmp(qname, knot_rrset_owner(soa)) != 0) {
		// malformed packet
		dbg_ns("IXFR query is malformed.\n");
		knot_response_set_rcode(xfr->response, KNOT_RCODE_FORMERR);
		if (ns_xfr_send_and_clear(xfr, 1) == KNOT_ECONN) {
			return KNOT_ECONN;
		}
		return KNOT_EMALF;
	}

	return ns_ixfr_from_zone(xfr);
}

/*----------------------------------------------------------------------------*/

static int knot_ns_prepare_response(knot_packet_t *query, knot_packet_t **resp,
                                    size_t max_size)
{
	assert(max_size >= 500);

	// initialize response packet structure
	*resp = knot_packet_new_mm(&query->mm);
	if (*resp == NULL) {
		dbg_ns("Failed to create packet structure.\n");
		return KNOT_ENOMEM;
	}

	int ret = knot_packet_set_max_size(*resp, max_size);

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
	knot_packet_t *err = knot_packet_new();
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

	ns->opt_rr = NULL;
	ns->identity = NULL;
	ns->version = NULL;

	knot_packet_free(&err);

	return ns;
}

/*----------------------------------------------------------------------------*/

int knot_ns_parse_packet(const uint8_t *query_wire, size_t qsize,
                    knot_packet_t *packet, knot_packet_type_t *type)
{
	if (packet == NULL || query_wire == NULL || type == NULL) {
		dbg_ns("Missing parameter to query parsing.\n");
		return KNOT_EINVAL;
	}

	dbg_ns_verb("ns_parse_packet() called with query size %zu.\n", qsize);

	// 1) create empty response
	dbg_ns_verb("Parsing packet...\n");

	int ret = 0;
	*type = KNOT_QUERY_INVALID;

	if ((ret = knot_packet_parse_from_wire(packet, query_wire,
	                                         qsize, 1, 0)) != 0) {
		dbg_ns("Error while parsing packet, "
		       "libknot error '%s'.\n", knot_strerror(ret));
		return KNOT_RCODE_FORMERR;
	}

	dbg_ns_verb("Parsed packet header and Question:\n");
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
			*type = KNOT_RESPONSE_UPDATE;
		}
		break;
	default:
		return KNOT_RCODE_NOTIMPL;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static void knot_ns_error_response(const knot_nameserver_t *nameserver,
                                   uint16_t query_id, uint8_t *flags1_query,
                                   uint8_t rcode, uint8_t *response_wire,
                                   size_t *rsize)
{
	memcpy(response_wire, nameserver->err_response,
	       nameserver->err_resp_size);

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
	*rsize = nameserver->err_resp_size;
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
                                      const knot_packet_t *query,
                                      uint8_t rcode, uint8_t *response_wire,
                                      size_t *rsize)
{
	if (query->parsed < 2) {
		// ignore packet
		return KNOT_EFEWDATA;
	}

	if (query->parsed < KNOT_WIRE_HEADER_SIZE) {
		return knot_ns_error_response_from_query_wire(nameserver,
			query->wireformat, query->size, rcode, response_wire,
			rsize);
	}

	size_t max_size = *rsize;
	uint8_t flags1 = knot_wire_get_flags1(knot_packet_wireformat(query));
	const size_t question_off = KNOT_WIRE_HEADER_SIZE;

	// prepare the generic error response
	knot_ns_error_response(nameserver, knot_packet_id(query),
	                       &flags1, rcode, response_wire,
	                       rsize);

	if (query->parsed > KNOT_WIRE_HEADER_SIZE + question_off) {

		/* Append question only (do not rewrite header). */
		size_t question_size = knot_packet_question_size(query);
		question_size -= question_off;
		if (max_size >= *rsize + question_size) {
			if (response_wire != knot_packet_wireformat(query)) {
				memcpy(response_wire + question_off,
				       knot_packet_wireformat(query) + question_off,
				       question_size);
			}
			*rsize += question_size;
			knot_wire_set_qdcount(response_wire, 1);
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_ns_error_response_full(knot_nameserver_t *nameserver,
                                 knot_packet_t *response, uint8_t rcode,
                                 uint8_t *response_wire, size_t *rsize)
{
	knot_response_set_rcode(response, rcode);

	if (ns_error_response_to_wire(response, response_wire, rsize) != 0) {
		knot_ns_error_response_from_query(nameserver,
		                                  knot_packet_query(response),
		                                  KNOT_RCODE_SERVFAIL,
		                                  response_wire, rsize);
	}
}

/*----------------------------------------------------------------------------*/

int knot_ns_prep_normal_response(knot_nameserver_t *nameserver,
                                 knot_packet_t *query, knot_packet_t **resp,
                                 const knot_zone_t **zone, size_t max_size)
{
	dbg_ns_verb("knot_ns_prep_normal_response()\n");

	if (nameserver == NULL || query == NULL || resp == NULL
	    || zone == NULL) {
		return KNOT_EINVAL;
	}

	// first, parse the rest of the packet
	assert(knot_packet_is_query(query));
	dbg_ns_verb("Query - parsed: %zu, total wire size: %zu\n",
	            knot_packet_parsed(query), knot_packet_size(query));
	int ret;

	ret = knot_packet_parse_rest(query, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the query: %s.\n",
		       knot_strerror(ret));
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
	    || (knot_packet_nscount(query) > 0
	        && (knot_packet_qtype(query) != KNOT_RRTYPE_IXFR))
	    || knot_packet_qdcount(query) != 1) {
		dbg_ns("ANCOUNT or NSCOUNT not 0 in query, "
		       "or QDCOUNT != 1. Reply FORMERR.\n");
		return KNOT_EMALF;
	}

	/*
	 * Check what is in the Additional section. Only OPT and TSIG are
	 * allowed. TSIG must be the last record if present.
	 */
	if (knot_packet_arcount(query) > 0) {
		int ok = 0;
		const knot_rrset_t *add1 =
		                knot_packet_additional_rrset(query, 0);
		if (knot_packet_additional_rrset_count(query) == 1
		    && (knot_rrset_type(add1) == KNOT_RRTYPE_OPT
		        || knot_rrset_type(add1) == KNOT_RRTYPE_TSIG)) {
			ok = 1;
		} else if (knot_packet_additional_rrset_count(query) == 2) {
			const knot_rrset_t *add2 =
			                knot_packet_additional_rrset(query, 1);
			if (knot_rrset_type(add1) == KNOT_RRTYPE_OPT
			    && knot_rrset_type(add2) == KNOT_RRTYPE_TSIG) {
				ok = 1;
			}
		}

		if (!ok) {
			dbg_ns("Additional section malformed. Reply FORMERR\n");
			return KNOT_EMALF;
		}
	}

	size_t resp_max_size = 0;

	knot_packet_dump(query);

	if (max_size > 0) {
		// if TCP is used, buffer size is the only constraint
		assert(max_size > 0);
		resp_max_size = max_size;
	} else if (knot_query_edns_supported(query)) {
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
	dbg_ns_detail("EDNS supported in query: %d\n",
	              knot_query_edns_supported(query));

	// set the OPT RR to the response
	if (knot_query_edns_supported(query)) {
		ret = knot_response_add_opt(*resp, nameserver->opt_rr,
		                            knot_query_nsid_requested(query));
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to set OPT RR to the response"
			       ": %s\n", knot_strerror(ret));
		} else {
			// copy the DO bit from the query
			if (knot_query_dnssec_requested(query)) {
				knot_edns_set_do(&(*resp)->opt_rr);
			}
		}
	}

	dbg_ns_verb("Response max size: %zu\n", (*resp)->max_size);

	// search for zone only for IN and ANY classes
	uint16_t qclass = knot_packet_qclass(*resp);
	if (qclass != KNOT_CLASS_IN && qclass != KNOT_CLASS_ANY)
		return KNOT_EOK;

	const knot_dname_t *qname = knot_packet_qname(*resp);
	assert(qname != NULL);

	uint16_t qtype = knot_packet_qtype(*resp);
dbg_ns_exec_verb(
	char *name_str = knot_dname_to_str(qname);
	dbg_ns_verb("Trying to find zone for QNAME %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	knot_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);
	*zone = ns_get_zone_for_qname(zonedb, qname, qtype);

	/* Assign zone to packets. */
	query->zone = *zone;
	(*resp)->zone = *zone;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_prep_update_response(knot_nameserver_t *nameserver,
                                 knot_packet_t *query, knot_packet_t **resp,
                                 knot_zone_t **zone, size_t max_size)
{
	dbg_ns_verb("knot_ns_prep_update_response()\n");

	if (nameserver == NULL || query == NULL || resp == NULL
	    || zone == NULL) {
		return KNOT_EINVAL;
	}

	// first, parse the rest of the packet
	assert(knot_packet_is_query(query));
	dbg_ns_verb("Query - parsed: %zu, total wire size: %zu\n",
	            knot_packet_parsed(query), knot_packet_size(query));
	int ret;

	ret = knot_packet_parse_rest(query, 0);
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
	if (knot_packet_qdcount(query) != 1) {
		dbg_ns("QDCOUNT != 1. Reply FORMERR.\n");
		return KNOT_EMALF;
	}

	/*
	 * Check what is in the Additional section. Only OPT and TSIG are
	 * allowed. TSIG must be the last record if present.
	 */
	/*! \todo Put to separate function - used in prep_normal_response(). */
	if (knot_packet_arcount(query) > 0) {
		int ok = 0;
		const knot_rrset_t *add1 =
		                knot_packet_additional_rrset(query, 0);
		if (knot_packet_additional_rrset_count(query) == 1
		    && (knot_rrset_type(add1) == KNOT_RRTYPE_OPT
		        || knot_rrset_type(add1) == KNOT_RRTYPE_TSIG)) {
			ok = 1;
		} else if (knot_packet_additional_rrset_count(query) == 2) {
			const knot_rrset_t *add2 =
			                knot_packet_additional_rrset(query, 1);
			if (knot_rrset_type(add1) == KNOT_RRTYPE_OPT
			    && knot_rrset_type(add2) == KNOT_RRTYPE_TSIG) {
				ok = 1;
			}
		}

		if (!ok) {
			dbg_ns("Additional section malformed. Reply FORMERR\n");
			return KNOT_EMALF;
		}
	}

	size_t resp_max_size = 0;

	knot_packet_dump(query);

	/*! \todo Put to separate function - used in prep_normal_response(). */
	if (max_size > 0) {
		// if TCP is used, buffer size is the only constraint
		assert(max_size > 0);
		resp_max_size = max_size;
	} else if (knot_query_edns_supported(query)) {
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
	              knot_query_edns_supported(query));

	// set the OPT RR to the response
	if (knot_query_edns_supported(query)) {
		ret = knot_response_add_opt(*resp, nameserver->opt_rr,
		                            knot_query_nsid_requested(query));
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to set OPT RR to the response"
			       ": %s\n", knot_strerror(ret));
		} else {
			// copy the DO bit from the query
			if (knot_query_dnssec_requested(query)) {
				knot_edns_set_do(&(*resp)->opt_rr);
			}
		}
	}

	dbg_ns_verb("Response max size: %zu\n", (*resp)->max_size);

	const knot_dname_t *qname = knot_packet_qname(knot_packet_query(*resp));
	assert(qname != NULL);

//	uint16_t qtype = knot_packet_qtype(*resp);
dbg_ns_exec_verb(
	char *name_str = knot_dname_to_str(qname);
	dbg_ns_verb("Trying to find zone %s\n", name_str);
	free(name_str);
);
	// find zone
	*zone = knot_zonedb_find_zone(zonedb, qname);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_normal(knot_nameserver_t *nameserver,
                          const knot_zone_t *zone, knot_packet_t *resp,
                          uint8_t *response_wire, size_t *rsize, int check_any)
{
	dbg_ns_verb("ns_answer_normal()\n");

	int ret = ns_answer(zone, resp, check_any);

	if (ret != 0) {
		// now only one type of error (SERVFAIL), later maybe more
		knot_ns_error_response_full(nameserver, resp,
		                            KNOT_RCODE_SERVFAIL,
		                            response_wire, rsize);
	} else {
		dbg_ns_verb("Created response packet.\n");
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

	dbg_ns_verb("Returning response with wire size %zu\n", *rsize);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_answer_ixfr_udp(knot_nameserver_t *nameserver,
                            const knot_zone_t *zone, knot_packet_t *resp,
                            uint8_t *response_wire, size_t *rsize)
{
	dbg_ns("ns_answer_ixfr_udp()\n");

	const knot_zone_contents_t *contents = knot_zone_contents(zone);

	// if no zone found, return REFUSED
	if (zone == NULL) {
		dbg_ns("No zone found.\n");
		knot_response_set_rcode(resp, KNOT_RCODE_REFUSED);
		return KNOT_EOK;
	} else if (contents == NULL) {
		dbg_ns("Zone expired or not bootstrapped. Reply SERVFAIL.\n");
		knot_response_set_rcode(resp, KNOT_RCODE_SERVFAIL);
		return KNOT_EOK;
	}

	const knot_node_t *apex = knot_zone_contents_apex(contents);
	assert(apex != NULL);
	knot_rrset_t *soa = knot_node_get_rrset(apex, KNOT_RRTYPE_SOA);

	// just put the SOA to the Answer section of the response and send back
	int ret = knot_response_add_rrset_answer(resp, soa, 1, 0, 0);
	if (ret != KNOT_EOK) {
		knot_ns_error_response_full(nameserver, resp,
		                            KNOT_RCODE_SERVFAIL,
		                            response_wire, rsize);
	}

	dbg_ns("Created response packet.\n");
	knot_packet_dump(resp);

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

	ret = knot_packet_parse_rest(xfr->query, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the query: %s\n",
		       knot_strerror(ret));
		xfr->rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
		                                 : KNOT_RCODE_SERVFAIL;
		return ret;
	}

dbg_ns_exec_verb(
	dbg_ns_verb("Parsed XFR query:\n");
	knot_packet_dump(xfr->query);
);

	knot_zonedb_t *zonedb = rcu_dereference(nameserver->zone_db);
	const knot_dname_t *qname = knot_packet_qname(xfr->query);

dbg_ns_exec_verb(
	char *name_str = knot_dname_to_str(qname);
	dbg_ns_verb("Trying to find zone with name %s\n", name_str);
	free(name_str);
);
	// find zone in which to search for the name
	knot_zone_t *zone = knot_zonedb_find_zone(zonedb, qname);

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
	knot_packet_t *resp = knot_packet_new_mm(&xfr->query->mm);
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

	resp->wireformat = xfr->wire;
	resp->max_size = xfr->wire_size;

	ret = knot_response_init_from_query(resp, xfr->query);

	if (ret != KNOT_EOK) {
		dbg_ns("Failed to init response structure.\n");
		/*! \todo xfr->wire is not NULL, will fail on assert! */
		knot_ns_error_response_from_query(nameserver, xfr->query,
		                                  KNOT_RCODE_SERVFAIL,
		                                  xfr->wire, &xfr->wire_size);
		int res = xfr->send(xfr->session, &xfr->addr, xfr->wire,
		                    xfr->wire_size);
		knot_packet_free(&resp);
		return res;
	}

	xfr->response = resp;

	assert(knot_packet_qtype(xfr->response) == KNOT_RRTYPE_AXFR ||
	       knot_packet_qtype(xfr->response) == KNOT_RRTYPE_IXFR);
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

	if (knot_packet_nscount(xfr->query) < 1) {
		dbg_ns("No Authority record.\n");
		return KNOT_EMALF;
	}

	if (knot_packet_authority_rrset(xfr->query, 0) == NULL) {
		dbg_ns("Authority record missing.\n");
		return KNOT_ERROR;
	}

	// retrieve origin (xfr) serial and target (zone) serial
	*serial_to = knot_rdata_soa_serial(zone_soa);
	*serial_from =
		knot_rdata_soa_serial(knot_packet_authority_rrset(xfr->query, 0));

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_xfr_send_error(const knot_nameserver_t *nameserver,
                           knot_ns_xfr_t *xfr, knot_rcode_t rcode)
{
	/*! \todo Handle TSIG errors differently. */
	knot_response_set_rcode(xfr->response, rcode);

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
		knot_packet_free(&xfr->response);
		return ret;
	}

	/*
	 * The TSIG data should already be stored in 'xfr'.
	 * Now just count the expected size of the TSIG RR and save it
	 * to the response structure.
	 */

	/*! \todo [TSIG] Get the TSIG size from some API function. */
	if (xfr->tsig_size > 0) {
		dbg_ns_verb("Setting TSIG size in packet: %zu\n",
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
		/*! \todo #2176 This should send error response every time. */
		knot_ns_xfr_send_error(nameserver, xfr, KNOT_RCODE_SERVFAIL);
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
		return KNOT_EINVAL;
	}

	// parse rest of the packet (we need the Authority record)
	int ret = knot_packet_parse_rest(xfr->query, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to parse rest of the packet: %s. "
		       "Reply FORMERR.\n", knot_strerror(ret));
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

	/*
	 * The TSIG data should already be stored in 'xfr'.
	 * Now just count the expected size of the TSIG RR and save it
	 * to the response structure. This should be optional, only if
	 * the request contained TSIG, i.e. if there is the data in 'xfr'.
	 */

	/*! \todo [TSIG] Get the TSIG size from some API function. */
	if (xfr->tsig_size > 0) {
		knot_packet_set_tsig_size(xfr->response, xfr->tsig_size);
	}

	ret = ns_ixfr(xfr);

	knot_packet_free(&xfr->response);

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

dbg_ns_exec_verb(
	dbg_ns_verb("Zone db contents: (zone count: %zu)\n",
	            nameserver->zone_db->zone_count);

	/* Warning: may not show updated zone if updated zone that is already
	 *          discarded from zone db (reload with pending transfer). */
	const knot_zone_t **zones = knot_zonedb_zones(nameserver->zone_db);
	for (int i = 0; i < knot_zonedb_zone_count
	     (nameserver->zone_db); i++) {
		dbg_ns_verb("%d. zone: %p\n", i, zones[i]);
		char *name = knot_dname_to_str(zones[i]->name);
		dbg_ns_verb("    zone name: %s\n", name);
		free(name);
	}
	free(zones);
);

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
		knot_packet_free(&xfr->query);
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
					knot_packet_free(&xfr->query);
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
int knot_ns_process_update(const knot_packet_t *query,
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

int knot_ns_create_forward_query(const knot_packet_t *query,
                                 uint8_t *query_wire, size_t *size)
{
	/* Forward UPDATE query:
	 * assign a new packet id
	 */
	int ret = KNOT_EOK;
	if (knot_packet_size(query) > *size) {
		return KNOT_ESPACE;
	}

	memcpy(query_wire, knot_packet_wireformat(query),
	       knot_packet_size(query));
	*size = knot_packet_size(query);
	knot_wire_set_id(query_wire, knot_random_id());

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_forward_response(const knot_packet_t *response,
                                     uint16_t original_id,
                                     uint8_t *response_wire, size_t *size)
{
	// copy the wireformat of the response and set the original ID
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
