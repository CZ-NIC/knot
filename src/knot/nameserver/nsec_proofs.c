#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/internet.h"
#include "knot/dnssec/zone-nsec.h"

#include "libknot/common.h"
#include "libknot/rrset-dump.h"
#include "libknot/rrtype/soa.h"


#include "common/debug.h"
#include "common/base32hex.h"
#include "common/base64.h"




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

	// the common labels should match
	assert(knot_dname_matched_labels(closest_encloser, name)
	       == ce_labels);

	// chop some labels from the qname
	for (int i = 0; i < (qname_labels - ce_labels - 1); ++i) {
		name = knot_wire_next_label(name, NULL);
	}

	return knot_dname_copy(name, NULL);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds NSEC3 RRSet (together with corresponding RRSIGs) from the given
 *        node into the response.
 *
 * \param node Node to get the NSEC3 RRSet from.
 * \param resp Response where to add the RRSets.
 */
static int ns_put_nsec3_from_node(const zone_node_t *node,
                                  struct query_data *qdata,
                                  knot_pkt_t *resp)
{
	knot_rrset_t rrset = node_rrset(node, KNOT_RRTYPE_NSEC3);
	knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);
	if (knot_rrset_empty(&rrset)) {
		// bad zone, ignore
		return KNOT_EOK;
	}

	int res = ns_put_rr(resp, &rrset, &rrsigs, COMPR_HINT_NONE,
	                    KNOT_PF_CHECKDUP, qdata);

	/*! \note TC bit is already set, if something went wrong. */

	// return the error code, so that other code may be skipped
	return res;
}

/*!
 * \brief Adds NSEC5 RRSet (together with corresponding RRSIGs) from the given
 *        node into the response.
 *
 * \param node Node to get the NSEC3 RRSet from.
 * \param resp Response where to add the RRSets.
 */
static int ns_put_nsec5_from_node(const zone_node_t *node,
                                  struct query_data *qdata,
                                  knot_pkt_t *resp)
{
    knot_rrset_t rrset = node_rrset(node, KNOT_RRTYPE_NSEC5);
    knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);
    if (knot_rrset_empty(&rrset)) {
        // bad zone, ignore
        return KNOT_EOK;
    }
    
    /*! \note TC bit is already set, if something went wrong. */
    int res = ns_put_rr(resp, &rrset, &rrsigs, COMPR_HINT_NONE,
                        KNOT_PF_CHECKDUP, qdata);
    
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
static int ns_put_covering_nsec3(const zone_contents_t *zone,
                                 const knot_dname_t *name,
                                 struct query_data *qdata,
                                 knot_pkt_t *resp)
{
    bool use_next = false; //to be set to true when the function is used for existing name
	const zone_node_t *prev, *node;
	/*! \todo Check version. */
    if (knot_is_nsec5_enabled(zone)) {
        uint8_t *nsec5proof = NULL;
        size_t nsec5proof_size =0;
        int match = zone_contents_find_nsec3_for_name(zone, name,
                                                      &node, &prev, &nsec5proof, &nsec5proof_size, true);
        /*uint8_t *b32_digest = NULL;
        printf("************nsec_proofs.c*************\n");
        int32_t b32_length = base64_encode_alloc(nsec5proof, nsec5proof_size, &b32_digest);
        printf("NSEC5PROOF:\n%.*s \n", b32_length,
               b32_digest);
        printf("*********************************\n");*/
        if (match < 0) {
            // ignoring, what can we do anyway?
            return KNOT_EOK;
        }
        if ((match == ZONE_NAME_FOUND && !knot_is_nsec5_enabled(zone))|| prev == NULL){
            // if run-time collision => SERVFAIL
            //printf("PIASTIKA STO CORNER CASE\n");
            return KNOT_EOK;
        }
        if (match == ZONE_NAME_FOUND && knot_is_nsec5_enabled(zone)) {
            use_next = true;
        }
        
        knot_rrset_t nsec5proof_rrset;
        knot_rrset_init(&nsec5proof_rrset, name, KNOT_RRTYPE_NSEC5PROOF, KNOT_CLASS_IN);
        uint8_t *rdata = (uint8_t *)malloc(sizeof(uint8_t) *(2+nsec5proof_size));
        knot_wire_write_u16(rdata, zone->nsec5_key.nsec5_key.keytag); ///HERE PUT KEYTAG!;
        //printf("keytag: %d\n", zone->nsec5_key.nsec5_key.keytag);
        rdata += 2;
        for (int i = 0; i<nsec5proof_size; i++)
        {
            *rdata = nsec5proof[i];
            rdata +=1;
        }
        knot_rrset_t soa_rrset = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
        uint32_t min = knot_soa_minimum(&soa_rrset.rrs);

        knot_rrset_add_rdata(&nsec5proof_rrset, rdata-2-nsec5proof_size, 2+nsec5proof_size, min, NULL);
        
        /*char dst[1000];
        if (knot_rrset_txt_dump(&nsec5proof_rrset, dst, 1000,
                                &KNOT_DUMP_STYLE_DEFAULT) < 0) {
            return KNOT_ENOMEM;
        }
        printf("NSEC5PROOF RECORD = %s\n",dst);*/
        int res = ns_put_rr(resp,&nsec5proof_rrset,NULL,COMPR_HINT_NONE,KNOT_PF_FREE,qdata);
        if (res!=KNOT_EOK)
        {
            printf("ISSUE WITH NSEC5PROOF\n");
            return KNOT_ERROR;
        }
    }
    else {
        int match = zone_contents_find_nsec3_for_name(zone, name,
	                                                   &node, &prev, NULL, NULL, false);
        //assert(match >= 0);
        if (match < 0) {
            // ignoring, what can we do anyway?
            return KNOT_EOK;
        }
        
        if (match == ZONE_NAME_FOUND || prev == NULL){
            // if run-time collision => SERVFAIL
            return KNOT_EOK;
        }
    }
dbg_ns_exec_verb(
	char *name = knot_dname_to_str_alloc(prev->owner);
	dbg_ns_verb("Covering NSEC3 node: %s\n", name);
	free(name);
);
    if (knot_is_nsec5_enabled(zone)) {
        if (use_next) {
            return ns_put_nsec5_from_node(node, qdata, resp);
        }
        return ns_put_nsec5_from_node(prev, qdata, resp);
    }
	return ns_put_nsec3_from_node(prev, qdata, resp);
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
                                         const zone_contents_t *zone,
                                         const zone_node_t **closest_encloser,
                                         const knot_dname_t *qname,
                                         struct query_data *qdata,
                                         knot_pkt_t *resp,
                                         bool only_next)
{
	assert(zone != NULL);
	assert(closest_encloser != NULL);
	assert(*closest_encloser != NULL);
	assert(qname != NULL);
	assert(resp != NULL);

	// this function should be called only if NSEC3 is enabled in the zone
	assert(zone_contents_nsec3params(zone) != NULL || knot_is_nsec5_enabled(zone));

	dbg_ns_verb("Adding closest encloser proof\n");

	if (zone_contents_nsec3params(zone) == NULL) {
dbg_ns_exec_verb(
		char *name = knot_dname_to_str_alloc(zone->apex->owner);
		dbg_ns_verb("No NSEC3PARAM found in zone %s.\n", name);
		free(name);
);
        if(!knot_is_nsec5_enabled(zone)) {
 
            dbg_ns_verb("No NSEC5 either for zone\n");
            return KNOT_EOK;
      

        }
	}

dbg_ns_exec_detail(
	char *name = knot_dname_to_str_alloc((*closest_encloser)->owner);
	dbg_ns_detail("Closest encloser: %s\n", name);
	free(name);
);

	/*
	 * 1) NSEC3 that matches closest provable encloser.
	 */
	const zone_node_t *nsec3_node = NULL;
	const knot_dname_t *next_closer = NULL;
    //printf("ta ekana nullakia\n");
	while ((nsec3_node = (*closest_encloser)->nsec3_node)
	       == NULL) {
        //printf("mpika sto while\n");
		next_closer = (*closest_encloser)->owner;
		*closest_encloser = (*closest_encloser)->parent;
		if (*closest_encloser == NULL) {
			// there are no NSEC3s to add
			return KNOT_EOK;
		}
	}
    //printf("vgika apo to while\n");

	assert(nsec3_node != NULL);

dbg_ns_exec_verb(
	char *name = knot_dname_to_str_alloc(nsec3_node->owner);
	dbg_ns_verb("NSEC3 node: %s\n", name);
	free(name);
	name = knot_dname_to_str_alloc((*closest_encloser)->owner);
	dbg_ns_verb("Closest provable encloser: %s\n", name);
	free(name);
	if (next_closer != NULL) {
		name = knot_dname_to_str_alloc(next_closer);
		dbg_ns_verb("Next closer name: %s\n", name);
		free(name);
	} else {
		dbg_ns_verb("Next closer name: none\n");
	}
);
    int ret = KNOT_EOK;
    if(knot_is_nsec5_enabled(zone)) {
        if (!only_next) {
            //ret = ns_put_nsec5_from_node(nsec3_node, qdata, resp);
            //printf("PSAXNW GIA COVERING TOU: %s\n", knot_dname_to_str_alloc((*closest_encloser)->owner));
            ret = ns_put_covering_nsec3(zone, (*closest_encloser)->owner, qdata, resp);
        }
    }
    else
    {
        ret = ns_put_nsec3_from_node(nsec3_node, qdata, resp);
    }
	if (ret != KNOT_EOK) {
        printf("PIGE STRAVA TO COMPUTATION TOU COVERING NSEC5\n");
		return ret;
	}

	/*
	 * 2) NSEC3 that covers the "next closer" name.
	 */
	if (next_closer == NULL) {
		// create the "next closer" name by appending from qname
		knot_dname_t *new_next_closer = ns_next_closer((*closest_encloser)->owner,
							       qname);

		if (new_next_closer == NULL) {
			return KNOT_ERROR; /*servfail */
		}
dbg_ns_exec_verb(
		char *name = knot_dname_to_str_alloc(new_next_closer);
		dbg_ns_verb("Next closer name: %s\n", name);
		free(name);
);
		ret = ns_put_covering_nsec3(zone, new_next_closer, qdata, resp);
		knot_dname_free(&new_next_closer, NULL);
	} else {
		ret = ns_put_covering_nsec3(zone, next_closer, qdata, resp);
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

	knot_dname_t *wildcard = knot_dname_from_str_alloc("*");
	if (wildcard == NULL) {
		return NULL;
	}

	wildcard = knot_dname_cat(wildcard, name);
	if (wildcard == NULL)
		return NULL;

dbg_ns_exec_verb(
	char *name = knot_dname_to_str_alloc(wildcard);
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
 * \param qdata Query data.
 * \param resp Response to put the NSEC3s into.
 */
static int ns_put_nsec_wildcard(const zone_contents_t *zone,
                                const knot_dname_t *qname,
                                const zone_node_t *previous,
                                struct query_data *qdata,
                                knot_pkt_t *resp)
{
	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {
		previous = zone_contents_find_previous(zone, qname);
		assert(previous != NULL);

		while (previous->flags != NODE_FLAGS_AUTH) {
			previous = previous->prev;
		}
	}

	knot_rrset_t rrset = node_rrset(previous, KNOT_RRTYPE_NSEC);
	int ret = KNOT_EOK;

	if (!knot_rrset_empty(&rrset)) {
		knot_rrset_t rrsigs = node_rrset(previous, KNOT_RRTYPE_RRSIG);
		// NSEC proving that there is no node with the searched name
		ret = ns_put_rr(resp, &rrset, &rrsigs, COMPR_HINT_NONE, 0, qdata);
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
 * \param qdata Query data.
 * \param resp Response where to add the NSEC3s.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec3_no_wildcard_child(const zone_contents_t *zone,
                                          const zone_node_t *node,
                                          struct query_data *qdata,
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
		ret = ns_put_covering_nsec3(zone, wildcard, qdata, resp);

		/* Directly discard wildcard. */
		knot_dname_free(&wildcard, NULL);
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
 * \param qdata Query data.
 * \param resp Response to put the NSEC3s into.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec3_wildcard(const zone_contents_t *zone,
                                 const zone_node_t *closest_encloser,
                                 const knot_dname_t *qname,
                                 struct query_data *qdata,
                                 knot_pkt_t *resp)
{
	assert(closest_encloser != NULL);
	assert(qname != NULL);
	assert(resp != NULL);

	if (!knot_is_nsec3_enabled(zone) && !knot_is_nsec5_enabled(zone)) {
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
	char *name = knot_dname_to_str_alloc(next_closer);
	dbg_ns_verb("Next closer name: %s\n", name);
	free(name);
);
	int ret = ns_put_covering_nsec3(zone, next_closer, qdata, resp);

	/* Duplicate from ns_next_close(), safe to discard. */
	knot_dname_free(&next_closer, NULL);

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
 * \param qdata Query data.
 * \param resp Response where to put the NSECs and NSEC3s.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec_nsec3_wildcard_answer(const zone_node_t *node,
                                             const zone_node_t *closest_encloser,
                                             const zone_node_t *previous,
                                             const zone_contents_t *zone,
                                             const knot_dname_t *qname,
                                             struct query_data *qdata,
                                             knot_pkt_t *resp)
{
	// if wildcard answer, add NSEC / NSEC3

	int ret = KNOT_EOK;
	if (knot_dname_is_wildcard(node->owner)
	    && !knot_dname_is_equal(qname, node->owner)) {
		if (knot_is_nsec3_enabled(zone) || knot_is_nsec5_enabled(zone)) {
            dbg_ns_verb("Adding NSE3/NSEC5 for wildcard answer.\n");
			ret = ns_put_nsec3_wildcard(zone, closest_encloser,
			                            qname, qdata, resp);
        }
        else {
            dbg_ns_verb("Adding NSEC for wildcard answer.\n");
			ret = ns_put_nsec_wildcard(zone, qname, previous, qdata,
			                           resp);
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
 * \param qdata Query data.
 * \param resp Response where to put the NSECs.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec_nxdomain(const knot_dname_t *qname,
                                const zone_contents_t *zone,
                                const zone_node_t *previous,
                                const zone_node_t *closest_encloser,
                                struct query_data *qdata,
                                knot_pkt_t *resp)
{
	knot_rrset_t rrset = { 0 };
	knot_rrset_t rrsigs = { 0 };

	// check if we have previous; if not, find one using the tree
	if (previous == NULL) {
		previous = zone_contents_find_previous(zone, qname);
		assert(previous != NULL);
		while (previous->flags != NODE_FLAGS_AUTH) {
			previous = previous->prev;
		}
	}

dbg_ns_exec_verb(
	char *name = knot_dname_to_str_alloc(previous->owner);
	dbg_ns_verb("Previous node: %s\n", name);
	free(name);
);

	// 1) NSEC proving that there is no node with the searched name
	rrset = node_rrset(previous, KNOT_RRTYPE_NSEC);
	rrsigs = node_rrset(previous, KNOT_RRTYPE_RRSIG);
	if (knot_rrset_empty(&rrset)) {
		// no NSEC records
		//return NS_ERR_SERVFAIL;
		return KNOT_EOK;
	}

	int ret = ns_put_rr(resp, &rrset, &rrsigs, COMPR_HINT_NONE, 0, qdata);
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

	knot_dname_t *wildcard = ns_wildcard_child_name(closest_encloser->owner);
	if (wildcard == NULL) {
		return KNOT_ERROR; /* servfail */
	}

	const zone_node_t *prev_new = zone_contents_find_previous(zone, wildcard);
	while (prev_new->flags != NODE_FLAGS_AUTH) {
		prev_new = prev_new->prev;
	}

	/* Directly discard dname. */
	knot_dname_free(&wildcard, NULL);

	if (prev_new != previous) {
		rrset = node_rrset(prev_new, KNOT_RRTYPE_NSEC);
		rrsigs = node_rrset(prev_new, KNOT_RRTYPE_RRSIG);
		if (knot_rrset_empty(&rrset)) {
			// bad zone, ignore
			return KNOT_EOK;
		}
		ret = ns_put_rr(resp, &rrset, &rrsigs, COMPR_HINT_NONE, 0, qdata);
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
 * \param qdata Query data.
 * \param resp Response where to put the NSEC3s.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec3_nxdomain(const zone_contents_t *zone,
                                 const zone_node_t *closest_encloser,
                                 const knot_dname_t *qname,
                                 struct query_data *qdata,
                                 knot_pkt_t *resp)
{
	// 1) Closest encloser proof
	int ret = ns_put_nsec3_closest_encloser_proof(zone, &closest_encloser,
	                                              qname, qdata, resp, false);
	// 2) NSEC3 covering non-existent wildcard --redundant in NSEC5 due to wildcarad flag
    //printf("Closest encloser flags: %d\n", closest_encloser->flags);
	if (ret == KNOT_EOK && closest_encloser != NULL && !knot_is_nsec5_enabled(zone)) {
		dbg_ns_verb("Putting NSEC3 for no wildcard child of closest "
		            "encloser.\n");
		ret = ns_put_nsec3_no_wildcard_child(zone, closest_encloser,
		                                     qdata, resp);
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
 * \param qdata Query data.
 * \param resp Response where to put the NSECs.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
static int ns_put_nsec_nsec3_nxdomain(const zone_contents_t *zone,
                                      const zone_node_t *previous,
                                      const zone_node_t *closest_encloser,
                                      const knot_dname_t *qname,
                                      struct query_data *qdata,
                                      knot_pkt_t *resp)
{
	int ret = 0;

	if (knot_is_nsec3_enabled(zone) || knot_is_nsec5_enabled(zone)) {
		ret = ns_put_nsec3_nxdomain(zone, closest_encloser,
		                            qname, qdata, resp);
	}
    //else if (knot_is_nsec5_enabled(zone)){
    //    printf("\nNSEC5 is enabled...\n");
    //}
    else {
		ret = ns_put_nsec_nxdomain(qname, zone, previous,
		                           closest_encloser, qdata, resp);
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
 * \param qdata Query data.
 * \param resp Response where to add the NSECs or NSEC3s.
 */
static int ns_put_nsec_nsec3_nodata(const zone_node_t *node,
                                    const zone_node_t *closest_encloser,
                                    const zone_node_t *previous,
                                    const zone_contents_t *zone,
                                    const knot_dname_t *qname,
                                    struct query_data *qdata,
                                    knot_pkt_t *resp)
{
	// This case must be handled first, before handling the wildcard case
	if (node->rrset_count == 0 && !knot_is_nsec3_enabled(zone)
                    && !knot_is_nsec5_enabled(zone)) {
		// node is an empty non-terminal => NSEC for NXDOMAIN
		return ns_put_nsec_nxdomain(qname, zone, previous,
		                            closest_encloser, qdata, resp);
	}

	/*! \todo Maybe distinguish different errors. */
	int ret = KNOT_ERROR;

	if (knot_is_nsec3_enabled(zone)) {

		/* RFC5155 7.2.5 Wildcard No Data Responses */
		if (!knot_dname_is_wildcard(qname) && knot_dname_is_wildcard(node->owner)) {
			dbg_ns("%s: adding NSEC3 wildcard NODATA\n", __func__);
			ns_put_nsec3_closest_encloser_proof(zone,
			                                    &closest_encloser,
			                                    qname, qdata,
			                                    resp, false);
		}

		/* RFC5155 7.2.3-7.2.5 common proof. */
		dbg_ns("%s: adding NSEC3 NODATA\n", __func__);
		const zone_node_t *nsec3_node = node->nsec3_node;
		if (nsec3_node) {
			ret = ns_put_nsec3_from_node(nsec3_node, qdata, resp);
		} else {
			// No NSEC3 node => Opt-out
			return ns_put_nsec3_closest_encloser_proof(zone,
			                                           &node,
			                                           qname,
			                                           qdata,
			                                           resp, false);

		}
	}
    else if (knot_is_nsec5_enabled(zone)) {
            
            /* This must include only next closer proof and wildcard record.
             * The existence of the wildcard record implies the existence of
             * the closest encloser record (not included in response).
             */
            /*
            if (!knot_dname_is_wildcard(qname) && knot_dname_is_wildcard(node->owner)) {
                dbg_ns("%s: adding NSEC5 wildcard NODATA\n", __func__);
                //replace with modified version that only adds next closer proof
                ns_put_nsec3_closest_encloser_proof(zone,
                                                    &closest_encloser,
                                                    qname, qdata,
                                                    resp, true);
            }
            */
            /* RFC5155 7.2.3-7.2.5 common proof. */
            dbg_ns("%s: adding NSEC5 NODATA\n", __func__);
            const zone_node_t *nsec3_node = node->nsec3_node;
            if (nsec3_node) {
                dbg_ns("%s: found NSEC5 node. Going to add it.\n", __func__);
                //ret = ns_put_nsec5_from_node(nsec3_node, qdata, resp);
                ret = ns_put_covering_nsec3(zone,
                                      node->owner,
                                      qdata,
                                      resp);
                
            } else {
                // No NSEC3 node => Opt-out
                return ns_put_nsec3_closest_encloser_proof(zone,
                                                           &node,
                                                           qname,
                                                           qdata,
                                                           resp,
                                                           false);
            }
    }
    else {
		dbg_ns("%s: adding NSEC NODATA\n", __func__);
		knot_rrset_t rrset = node_rrset(node, KNOT_RRTYPE_NSEC);
		if (!knot_rrset_empty(&rrset)) {
			dbg_ns_detail("Putting the RRSet to Authority\n");
			knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);
			ret = ns_put_rr(resp, &rrset, &rrsigs, COMPR_HINT_NONE, 0, qdata);
		}
	}

	return ret;
}

int nsec_prove_wildcards(knot_pkt_t *pkt, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);
	if (qdata->zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	struct wildcard_hit *item = NULL;

	WALK_LIST(item, qdata->wildcards) {
		if (item->node == NULL) {
			return KNOT_EINVAL;
		}
		ret = ns_put_nsec_nsec3_wildcard_answer(
					item->node,
					item->node->parent,
					NULL, qdata->zone->contents,
					item->sname, qdata,
					pkt);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	return ret;
}

int nsec_prove_nodata(knot_pkt_t *pkt, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);
	if (qdata->node == NULL || qdata->encloser == NULL ||
	    qdata->zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	return ns_put_nsec_nsec3_nodata(qdata->node, qdata->encloser,
	                                qdata->previous, qdata->zone->contents,
	                                qdata->name, qdata, pkt);
}

int nsec_prove_nxdomain(knot_pkt_t *pkt, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);
	if (qdata->encloser == NULL || qdata->zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	return ns_put_nsec_nsec3_nxdomain(qdata->zone->contents, qdata->previous,
	                                  qdata->encloser, qdata->name, qdata,
	                                  pkt);
}

int nsec_prove_dp_security(knot_pkt_t *pkt, struct query_data *qdata)
{
	dbg_ns("%s(%p, %p)\n", __func__, pkt, qdata);
	if (qdata->node == NULL || qdata->encloser == NULL ||
	    qdata->zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	/* Add DS record if present. */
	knot_rrset_t rrset = node_rrset(qdata->node, KNOT_RRTYPE_DS);
	if (!knot_rrset_empty(&rrset)) {
		knot_rrset_t rrsigs = node_rrset(qdata->node, KNOT_RRTYPE_RRSIG);
		return ns_put_rr(pkt, &rrset, &rrsigs, COMPR_HINT_NONE, 0, qdata);
	}

	/* DS doesn't exist => NODATA proof. */
	return ns_put_nsec_nsec3_nodata(qdata->node,
	                                qdata->encloser,
	                                qdata->previous,
	                                qdata->zone->contents,
	                                qdata->name, qdata, pkt);
}

int nsec_append_rrsigs(knot_pkt_t *pkt, struct query_data *qdata, bool optional)
{
	dbg_ns("%s(%p, optional=%d)\n", __func__, pkt, optional);

	int ret = KNOT_EOK;
	uint32_t flags = (optional) ? KNOT_PF_NOTRUNC : KNOT_PF_NULL;
	flags |= KNOT_PF_FREE; // Free all RRSIGs, they are synthesized

	/* Append RRSIGs for section. */
	struct rrsig_info *info = NULL;
	WALK_LIST(info, qdata->rrsigs) {
		knot_rrset_t *rrsig = &info->synth_rrsig;
		uint16_t compr_hint = info->rrinfo->compress_ptr[COMPR_HINT_OWNER];
		ret = knot_pkt_put(pkt, compr_hint, rrsig, flags);
		if (ret != KNOT_EOK) {
			break;
		}
		/* RRSIG is owned by packet now. */
		knot_rdataset_init(&info->synth_rrsig.rrs);
	};

	/* Clear the list. */
	nsec_clear_rrsigs(qdata);

	return KNOT_EOK;
}

void nsec_clear_rrsigs(struct query_data *qdata)
{
	if (qdata == NULL) {
		return;
	}

	struct rrsig_info *info = NULL;
	WALK_LIST(info, qdata->rrsigs) {
		knot_rrset_t *rrsig = &info->synth_rrsig;
		knot_rrset_clear(rrsig, qdata->mm);
	};

	ptrlist_free(&qdata->rrsigs, qdata->mm);
	init_list(&qdata->rrsigs);
}
