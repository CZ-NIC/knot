#include <config.h>

#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/ns_proc_query.h"

#include "libknot/common.h"
#include "libknot/rdata.h"
#include "libknot/util/debug.h"

#define DNSSEC_ENABLED 1

/*! \note #191 There is a lot of duplicate and legacy code here. I have just
 *             divided the API into 3 + 1 basic proofs used and separated the
 *             code to its own file. Still, it should be cleaned up and
 *             each proof should be very briefly documented (what proves what)
 *             with hints to the RFC, as it's not so complicated as it looks here.
 */

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
		res = knot_pkt_put(resp, 0, rrset, KNOT_PF_CHECKDUP);
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
			return KNOT_ERROR; /*servfail */
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
		ret = knot_pkt_put(resp, 0, rrset, 0);
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
		ret = KNOT_ERROR; /* servfail */
	} else {
		ret = ns_put_covering_nsec3(zone, wildcard, resp);

		/* Directly discard wildcard. */
		knot_dname_free(&wildcard);
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
		return KNOT_ERROR; /* servfail */
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

	int ret = knot_pkt_put(resp, 0, rrset, 0);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to add NSEC for NXDOMAIN to response: %s\n",
		       knot_strerror(ret));
		return ret;
	}

	// 2) NSEC proving that there is no wildcard covering the name
	// this is only different from 1) if the wildcard would be
	// before 'previous' in canonical order, i.e. we can
	// search for previous until we find name lesser than wildcard
	assert(closest_encloser != NULL);

	knot_dname_t *wildcard =
		ns_wildcard_child_name(closest_encloser->owner);
	if (wildcard == NULL) {
		return KNOT_ERROR; /* servfail */
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
		ret = knot_pkt_put(resp, 0, rrset, 0);
		if (ret != KNOT_EOK) {
			dbg_ns("Failed to add second NSEC for NXDOMAIN to "
			       "response: %s\n", knot_strerror(ret));
			return ret;
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
static int ns_put_nsec_nsec3_nxdomain(const knot_zone_contents_t *zone,
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
static int ns_put_nsec_nsec3_nodata(const knot_node_t *node,
			     const knot_node_t *closest_encloser,
			     const knot_node_t *previous,
			     const knot_zone_contents_t *zone,
			     const knot_dname_t *qname,
			     knot_pkt_t *resp)
{
	if (!DNSSEC_ENABLED ||
	    !knot_pkt_have_dnssec(resp->query)) {
		return KNOT_EOK;
	}

	if (knot_dname_is_wildcard(node->owner)) {
		return ns_put_nsec_nsec3_wildcard_nodata(node, closest_encloser,
							 previous, zone, qname,
							 resp);
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
			ret = knot_pkt_put(resp, 0, rrset, 0);
		}
	}

	if (ret != KNOT_EOK) {
		return ret;
	}

	return ret;
}

int nsec_prove_wildcards(knot_pkt_t *pkt, struct query_data *qdata)
{
	int ret = KNOT_EOK;
	struct wildcard_hit *item = NULL;

	WALK_LIST(item, qdata->wildcards) {
		ret = ns_put_nsec_nsec3_wildcard_answer(
					item->node,
					knot_node_parent(item->node),
					NULL, qdata->zone->contents,
					item->sname,
					pkt);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	return ret;
}

int nsec_prove_nodata(knot_pkt_t *pkt, struct query_data *qdata)
{
	return ns_put_nsec_nsec3_nodata(qdata->node, qdata->encloser,
	                                qdata->previous, qdata->zone->contents,
	                                qdata->name, pkt);
}

int nsec_prove_nxdomain(knot_pkt_t *pkt, struct query_data *qdata)
{
    return ns_put_nsec_nsec3_nxdomain(qdata->zone->contents, qdata->previous,
                                      qdata->encloser, qdata->name,
                                      pkt);
}

int nsec_prove_dp_security(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Add DS record if present. */
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);
	knot_rrset_t *rrset = knot_node_get_rrset(qdata->node, KNOT_RRTYPE_DS);
	if (rrset != NULL) {
		return knot_pkt_put(pkt, 0, rrset, 0);
	}

	/* DS doesn't exist => NODATA proof. */
	return ns_put_nsec_nsec3_nodata(qdata->node,
	                                qdata->encloser,
	                                qdata->previous,
	                                qdata->zone->contents,
	                                qdata->name, pkt);
}

int nsec_append_rrsigs(knot_pkt_t *pkt, bool optional)
{
	dbg_ns("%s(%p, optional=%d)\n", __func__, pkt, optional);

	int ret = KNOT_EOK;
	uint32_t flags = (optional) ? KNOT_PF_NOTRUNC : KNOT_PF_NULL;
	uint16_t compr_hint = COMPR_HINT_NONE;
	const knot_rrset_t *rr = NULL;
	const knot_pktsection_t *section = knot_pkt_section(pkt, pkt->current);

	/* Append RRSIG for each RR in given section. */
	for (uint16_t i = 0; i < section->count; ++i) {
		rr = section->rr[i];
		compr_hint = section->rrinfo[i].compress_ptr[0];
		if (rr->rrsigs) {
			ret = knot_pkt_put(pkt, compr_hint, rr->rrsigs, flags);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}

	return ret;
}
