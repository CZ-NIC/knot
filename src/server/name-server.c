#include <stdio.h>
#include <assert.h>

#include <urcu.h>
#include <ldns/ldns.h>

#include "name-server.h"
#include "zone-node.h"
#include "zone-database.h"
#include "stat.h"

#include "dnslib.h"
#include "dnslib/debug.h"

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

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/

//static void ns_set_edns(const ldns_pkt *query, ldns_pkt *response)
//{
//	if (EDNS_ENABLED && ldns_pkt_edns(query)) {
//		ldns_pkt_set_edns_data(response, NULL);
//		ldns_pkt_set_edns_do(response, ldns_pkt_edns_do(query));
//		ldns_pkt_set_edns_extended_rcode(response, 0);
//		ldns_pkt_set_edns_udp_size(response, MAX_UDP_PAYLOAD_EDNS);

//		uint8_t version = EDNS_VERSION;
//		if (ldns_pkt_edns_version(query) < EDNS_VERSION) {
//			version = ldns_pkt_edns_version(query);
//		}

//		ldns_pkt_set_edns_version(response, version);
//		ldns_pkt_set_edns_z(response, 0);
//	} else {
//		ldns_pkt_set_edns_udp_size(response, 0);
//		assert(!ldns_pkt_edns(response));
//	}
//}

/*----------------------------------------------------------------------------*/

//static void ns_set_max_packet_size(const ldns_pkt *query, ldns_pkt *response)
//{
//	uint16_t esize = ldns_pkt_edns_udp_size(query);
//	if (EDNS_ENABLED && esize > 0) {
//		// set maximum size to the lesser of our and max udp payload
//		if (esize >= MAX_UDP_PAYLOAD_EDNS) {
//			esize = MAX_UDP_PAYLOAD_EDNS;
//		}
//	} else {
//		esize = MAX_UDP_PAYLOAD;
//	}

//	ldns_pkt_set_edns_udp_size(response, esize);
//}

/*----------------------------------------------------------------------------*/

static inline void ns_update_pkt_size(ldns_pkt *pkt, size_t size)
{
	ldns_pkt_set_size(pkt, ldns_pkt_size(pkt) + size);
}

/*----------------------------------------------------------------------------*/

//static dnslib_response_t *ns_create_empty_response(const uint8_t *query_wire,
//                                                   size_t query_size)
//{
//	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);
//	if (resp == NULL) {
//		return NULL;
//	}

//	debug_ns("Created empty response...\n");

//	if (query_wire != NULL) {
//		if (dnslib_response_parse_query(resp, query_wire, query_size)
//		    != 0) {
//			dnslib_response_free(&resp);
//			return NULL;
//		}
//	}

//	return resp;
//}

/*----------------------------------------------------------------------------*/

static inline void ns_set_rcode(uint8_t *flags, uint8_t rcode)
{
	assert(rcode < 11);
	(*flags) = ((*flags) & RCODE_MASK) | rcode;
}

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

//static int ns_fits_into_response(const ldns_pkt *response, size_t size)
//{
//	return ((!ldns_pkt_tc(response)) &&
//		((ldns_pkt_size(response) + size) <=
//		 (ldns_pkt_edns_udp_size(response))));
//}

/*----------------------------------------------------------------------------*/

//static size_t ns_rr_size(ldns_rr *rr)
//{
//	size_t size = 0;
//	size += RR_FIXED_SIZE;
//	size += ldns_rdf_size(ldns_rr_owner(rr));
//	for (int j = 0; j < ldns_rr_rd_count(rr); ++j) {
//		size += ldns_rdf_size(ldns_rr_rdf(rr, j));
//	}
//	return size;
//}

///*----------------------------------------------------------------------------*/

//static size_t ns_rrset_size(ldns_rr_list *rrset)
//{
//	size_t size = 0;
//	for (int i = 0; i < ldns_rr_list_rr_count(rrset); ++i) {
//		ldns_rr *rr = ldns_rr_list_rr(rrset, i);
//		size += RR_FIXED_SIZE;
//		size += ldns_rdf_size(ldns_rr_owner(rr));
//		for (int j = 0; j < ldns_rr_rd_count(rr); ++j) {
//			size += ldns_rdf_size(ldns_rr_rdf(rr, j));
//		}
//	}
//	return size;
//}

/*----------------------------------------------------------------------------*/

dnslib_rrset_t *ns_synth_from_wildcard(const dnslib_rrset_t *wildcard_rrset,
                                       const dnslib_dname_t *qname)
{
	// TODO: test!!
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
	dnslib_rrset_dump(synth_rrset);

	// copy all RDATA
	const dnslib_rdata_t *rdata = dnslib_rrset_rdata(wildcard_rrset);
	while (rdata != NULL) {
		// we could use the RDATA from the wildcard rrset
		// but there is no way to distinguish it when deleting
		// temporary RRSets
		dnslib_rdata_t *rdata_copy = dnslib_rdata_copy(rdata);
		if (rdata_copy == NULL) {
			dnslib_rrset_deep_free(&synth_rrset, 1);
			return NULL;
		}

		debug_ns("Copied RDATA:\n");
		dnslib_rdata_dump(rdata_copy, dnslib_rrset_type(synth_rrset));

		dnslib_rrset_add_rdata(synth_rrset, rdata_copy);
		rdata = dnslib_rrset_rdata_next(wildcard_rrset, rdata);
	}

	return synth_rrset;
}

/*----------------------------------------------------------------------------*/

static void ns_follow_cname(const dnslib_node_t **node,
                            const dnslib_dname_t **qname,
                            dnslib_response_t *resp)
{
	// TODO: test!!

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

		dnslib_response_add_rrset_answer(resp, rrset, 1);

		char *name = dnslib_dname_to_str(dnslib_rrset_owner(rrset));
		debug_ns("CNAME record for owner %s put to answer section.\n",
			 name);
		free(name);

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

static void ns_try_put_rrset(ldns_rr_list *rrset,
                             ldns_pkt_section section,
                             int tc,
                             ldns_pkt *resp)
{
//	if (rrset != NULL) {
//		size_t size = ns_rrset_size(rrset);
//		if (ns_fits_into_response(resp, size)) {
//			ldns_pkt_push_rr_list(resp, section, rrset);
//			ns_update_pkt_size(resp, size);
//		} else {
//			debug_ns("RRSet %s %s omitted due to lack of space "
//			         "in packet.\n",
//			         ldns_rdf2str(ldns_rr_list_owner(rrset)),
//			         ldns_rr_type2str(ldns_rr_list_type(rrset)));
//			ldns_pkt_set_tc(resp, tc);
//		}
//	}
}

/*----------------------------------------------------------------------------*/

static void ns_put_rrset(ldns_rr_list *rrset, const ldns_rdf *name,
                         ldns_pkt_section section, int tc, ldns_pkt *pkt,
                         ldns_rr_list *copied_rrs)
{
	if (rrset) {
		//size_t size = 0;
		if (ldns_dname_is_wildcard(ldns_rr_list_owner(rrset))) {
			/* we must copy the whole list and replace owners
			   with name */
			ldns_rr_list *rrset_new = ldns_rr_list_new();
			int count = ldns_rr_list_rr_count(rrset);
			for (int i = 0; i < count; ++i) {
				ldns_rr *tmp_rr = ldns_rr_list_rr(rrset, i);
				ldns_rr *rr = ldns_rr_clone(tmp_rr);
				ldns_rdf_deep_free(ldns_rr_owner(rr));
				ldns_rr_set_owner(rr, ldns_rdf_clone(name));
				//ldns_pkt_push_rr(pkt, section, rr);
				ldns_rr_list_push_rr(rrset_new, rr);
				//size += ns_rr_size(rr);
				//ns_update_response_size(pkt, rr);
				ldns_rr_list_push_rr(copied_rrs, rr);
			}
			ns_try_put_rrset(rrset_new, section, tc, pkt);
			ldns_rr_list_free(rrset_new);
		} else {
			ns_try_put_rrset(rrset, section, tc, pkt);
		}
	}
}

/*----------------------------------------------------------------------------*/

static void ns_put_answer(const dnslib_node_t *node, const dnslib_dname_t *name,
                          uint16_t type, dnslib_response_t *resp)
{
	char *name_str = dnslib_dname_to_str(node->owner);
	debug_ns("Putting answers from node %s.\n", name_str);
	free(name_str);

	if (type == DNSLIB_RRTYPE_ANY) {
		// TODO
	} else {
		const dnslib_rrset_t *rrset = dnslib_node_rrset(node, type);
		if (rrset != NULL) {
			debug_ns("Found RRSet of type %s\n",
				 dnslib_rrtype_to_string(type));
			if (dnslib_dname_is_wildcard(dnslib_node_owner(node))) {
				dnslib_rrset_t *synth_rrset =
					ns_synth_from_wildcard(rrset, name);
				debug_ns("Synthetized RRSet:\n");
				dnslib_rrset_dump(synth_rrset);
				dnslib_response_add_tmp_rrset(resp,
				                              synth_rrset);
				rrset = synth_rrset;
			}

			dnslib_response_add_rrset_answer(resp, rrset, 1);
		}
	}
	dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
}

/*----------------------------------------------------------------------------*/

static void ns_put_additional(const zn_node_t *node, ldns_pkt *response,
                              ldns_rr_list *copied_rrs)
{
//        debug_ns("ADDITIONAL SECTION PROCESSING (node %p)\n", node);

//	if (zn_has_mx(node)  == 0 &&
//	    zn_has_ns(node)  == 0 &&
//	    zn_has_srv(node) == 0) {
//		// nothing to put
//		return;
//	}

//	// for each answer RR add appropriate additional records
//	int count = ldns_pkt_ancount(response);
//	for (int i = 0; i < count; ++i) {
//		ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response), i);
//		ldns_rdf *name;

//		switch (ldns_rr_get_type(rr)) {
//		case LDNS_RR_TYPE_MX:
//			name = ldns_rr_mx_exchange(rr);
//			break;
//		case LDNS_RR_TYPE_NS:
//			name = ldns_rr_ns_nsdname(rr);
//			break;
//		case LDNS_RR_TYPE_SRV:
//			name = ldns_rr_rdf(rr, 3); // get rid of the number
//			if (ldns_dname_label_count(name) == 0) {
//				continue;
//			}
//			assert(ldns_rdf_get_type(name) == LDNS_RDF_TYPE_DNAME);
//			break;
//		default:
//			continue;
//		}

//		debug_ns("Adding RRSets for name %s\n", ldns_rdf2str(name));
//		const zn_ar_rrsets_t *rrsets = zn_get_ref(node, name);
//		if (rrsets != NULL) {
//			if (rrsets->cname != NULL) {
//				const zn_node_t *cname_node = rrsets->cname;
//				ns_follow_cname(&cname_node, &name, response,
//				                LDNS_SECTION_ADDITIONAL,
//				                copied_rrs);

//				rrsets = zn_get_ref(cname_node, name);
//				if (rrsets == NULL) {
//					continue;
//				}
//			}
//			ns_put_rrset(rrsets->a, name,
//			             LDNS_SECTION_ADDITIONAL, 0, response,
//			             copied_rrs);
//			ns_put_rrset(rrsets->aaaa, name,
//			             LDNS_SECTION_ADDITIONAL, 0, response,
//			             copied_rrs);
//		} else {
//			debug_ns("No referenced RRSets!\n");
//		}
//	}
}

/*----------------------------------------------------------------------------*/

static void ns_put_authority_ns(const zdb_zone_t *zone, ldns_pkt *resp)
{
	ldns_rr_list *rrset = zn_find_rrset(zone->apex, LDNS_RR_TYPE_NS);
	ns_try_put_rrset(rrset, LDNS_SECTION_AUTHORITY, 0, resp);
}

/*----------------------------------------------------------------------------*/

static void ns_put_authority_soa(const zdb_zone_t *zone, ldns_pkt *resp)
{
	ldns_rr_list *rrset = zn_find_rrset(zone->apex, LDNS_RR_TYPE_SOA);
	ns_try_put_rrset(rrset, LDNS_SECTION_AUTHORITY, 0, resp);
}

/*----------------------------------------------------------------------------*/

static void ns_put_glues(const dnslib_node_t *node, dnslib_response_t *resp)
{
	// TODO!!!

//	ldns_rr_list *glues = zn_get_glues(node);

//	if (glues == NULL) {
//		return;
//	}

//	for (int i = 0; i < ldns_rr_list_rr_count(glues); ++i) {
//		ldns_rr *glue_rr = ldns_rr_list_rr(glues, i);

//		/* if owner is wildcard, find appropriate name in
//		   the RDATA fields of authority NS, copy the glue RR and
//		   change the owner */
//		if (ldns_dname_is_wildcard(ldns_rr_owner(glue_rr))) {
//			ldns_rr_list *auth = ldns_pkt_authority(resp);
//			debug_ns("Searching NS record for wildcard glue %s.\n",
//			         ldns_rdf2str(ldns_rr_owner(glue_rr)));
//			int cmp = -1;
//			int j = 0;
//			int count = ldns_rr_list_rr_count(auth);
//			for (; j < count; ++j) {
//				ldns_rr *rr = ldns_rr_list_rr(auth, j);
//				ldns_rdf *nsdname = ldns_rr_ns_nsdname(rr);
//				ldns_rdf *owner = ldns_rr_owner(glue_rr);
//				cmp = ldns_dname_match_wildcard(nsdname, owner);
//				if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_NS
//				    && (cmp == 1)) {
//					break;	// found
//				}
//			}

//			// must have found something if the glue is there
//			assert(cmp == 1);

//			debug_ns("Found NS record for wildcard glue %s:\n%s\n",
//			         ldns_rdf2str(ldns_rr_owner(glue_rr)),
//			         ldns_rr2str(ldns_rr_list_rr(auth, j)));

//			ldns_rr *glue_rr_new = ldns_rr_clone(glue_rr);
//			ldns_rdf_deep_free(ldns_rr_owner(glue_rr_new));
//			ldns_rr *listrr = ldns_rr_list_rr(auth, j);
//			ldns_rdf *nsdname = ldns_rr_ns_nsdname(listrr);
//			ldns_rr_set_owner(ldns_rr_list_rr(glues, i),
//			                  ldns_rdf_clone(nsdname));
//			ldns_rr_list_push_rr(copied_rrs, glue_rr_new);

//			size_t size = ns_rr_size(glue_rr_new);
//			if (ns_fits_into_response(resp, size)) {
//				ldns_pkt_push_rr(resp,
//				                 LDNS_SECTION_ADDITIONAL,
//				                 glue_rr_new);
//				// update size of the packet
//				ns_update_pkt_size(resp, size);
//			} else {
//				ldns_pkt_set_tc(resp, 1);
//				return;
//			}
//		} else {
//			size_t size = ns_rr_size(glue_rr);
//			if (ns_fits_into_response(resp, size)) {
//				ldns_pkt_push_rr(resp,
//				                 LDNS_SECTION_ADDITIONAL,
//				                 glue_rr);
//				ns_update_pkt_size(resp, size);
//			} else {
//				ldns_pkt_set_tc(resp, 1);
//				return;
//			}
//		}
//	}
}

/*----------------------------------------------------------------------------*/

static inline void ns_referral(const dnslib_node_t *node,
                               dnslib_response_t *resp)
{
	debug_ns("Referral response.\n");

	const dnslib_rrset_t *ns_rrset =
		dnslib_node_rrset(node, DNSLIB_RRTYPE_NS);
	assert(ns_rrset != NULL);

	dnslib_response_add_rrset_authority(resp, ns_rrset, 1);
	ns_put_glues(node, resp);
}

/*----------------------------------------------------------------------------*/

static int ns_additional_needed(uint16_t qtype)
{
	return (qtype == DNSLIB_RRTYPE_MX ||
	        qtype == DNSLIB_RRTYPE_NS ||
		qtype == DNSLIB_RRTYPE_SRV);
}

/*----------------------------------------------------------------------------*/

static void ns_answer_from_node(const dnslib_node_t *node,
                                const dnslib_zone_t *zone,
                                const dnslib_dname_t *qname, uint16_t qtype,
                                dnslib_response_t *resp)
{
	// TODO!!!

	debug_ns("Putting answers from found node to the response...\n");
	ns_put_answer(node, qname, qtype, resp);

//	if (ldns_pkt_ancount(response) == 0) {  // if NODATA response, put SOA
//		ns_put_authority_soa(zone, response);
//	} else {  // else put authority NS
//		ns_put_authority_ns(zone, response);
//	}

//	if (ns_additional_needed(qtype)) {
//		ns_put_additional(node, response, copied_rrs);
//	}
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

	char *name = dnslib_dname_to_str(cname);
	debug_ns("CNAME canonical name: %s.\n", name);
	free(name);

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
	char *name = dnslib_dname_to_str(dnslib_rrset_owner(dname_rrset));
	debug_ns("Processing DNAME for owner %s...\n", name);
	free(name);

	// TODO: check the number of RRs in the RRSet??

	// put the DNAME RRSet into the answer
	dnslib_response_add_rrset_answer(resp, dname_rrset, 1);

	if (ns_dname_is_too_long(dname_rrset, qname)) {
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_YXDOMAIN);
		return;
	}

	// synthetize CNAME (no way to tell that client supports DNAME)
	dnslib_rrset_t *synth_cname = ns_cname_from_dname(dname_rrset, qname);
	// add the synthetized RRSet to the Answer
	dnslib_response_add_rrset_answer(resp, synth_cname, 1);
	// add the synthetized RRSet into list of temporary RRSets of response
	dnslib_response_add_tmp_rrset(resp, synth_cname);

	// do not search for the name in new zone (out-of-bailiwick)
}

/*----------------------------------------------------------------------------*/

//static const zn_node_t *ns_strip_and_find(const zdb_zone_t *zone,
//                                          ldns_rdf **qname, uint *labels)
//{
//	const zn_node_t *node = NULL;
//	// search for the name and strip labels until nothing left
//	do {
//		debug_ns("Name %s not found, stripping leftmost label.\n",
//		         ldns_rdf2str(*qname));
//		/* TODO: optimize!!!
//		 *  1) do not copy the name!
//		 *   2) implementation of ldns_dname_left_chop() is inefficient
//		 */
//		ldns_rdf *new_qname = ldns_dname_left_chop(*qname);
//		ldns_rdf_deep_free(*qname);
//		*qname = new_qname;
//		--(*labels);
//		assert(*qname != NULL || (*labels) == 0);
//		node = zdb_find_name_in_zone(zone, *qname);
//	} while ((*labels) > 0 && node == NULL);

//	assert((ldns_dname_label_count(*qname) == 0 && (*labels) == 0)
//	       || (ldns_dname_label_count(*qname) > 0 && (*labels) > 0));

//	return node;
//}

/*----------------------------------------------------------------------------*/

//static void ns_answer_old(zdb_database_t *zdb, const ldns_rr *question,
//                          ldns_pkt *response,ldns_rr_list *copied_rrs)
//{
//	/* copy the QNAME, as we may be stripping labels and the QNAME is
//	   used in a response packet */
//	ldns_rdf *qname = ldns_rdf_clone(ldns_rr_owner(question));

//	debug_ns("Trying to find zone for QNAME %s\n", ldns_rdf2str(qname));
//	// find zone in which to search for the name
//	const zdb_zone_t *zone =
//		ns_get_zone_for_qname(zdb, qname, ldns_rr_get_type(question));

//	// if no zone found, return REFUSED
//	if (zone == NULL) {
//		ldns_pkt_set_rcode(response, LDNS_RCODE_REFUSED);
//		ldns_rdf_deep_free(qname);
//		return;
//	}

//	debug_ns("Found zone for QNAME %s\n", ldns_rdf2str(zone->zone_name));
//	debug_ns("Size of response packet: %u\n", ldns_pkt_size(response));

//	/*const zn_node *node = ns_find_node_in_zone(zone, &qname,
//	                                             &labels_found); */
//	const zn_node_t *node = zdb_find_name_in_zone(zone, qname);
//	int cname = 0;
//	ldns_rdf *qname_old = NULL;

//	while (1) {
//		qname_old = ldns_rdf_clone(qname);
//		uint labels = ldns_dname_label_count(qname);
//		uint labels_found = labels;

//		// whole QNAME not found
//		if (node == NULL) {
//			node = ns_strip_and_find(zone, &qname, &labels_found);

//			if (labels_found == 0 && cname == 0) {
//				log_error("Name %s not found in zone %s! "
//				          "SERVFAIL.\n",
//				          ldns_rdf2str(ldns_rr_owner(question)),
//				          ldns_rdf2str(zone->zone_name));
//				ldns_pkt_set_rcode(response,
//				                   LDNS_RCODE_SERVFAIL);
//				break;
//			} else if (labels_found == 0 && cname != 0) {
//				ldns_pkt_set_rcode(response,
//				                   LDNS_RCODE_NOERROR);
//				break;
//			}
//			assert(node != NULL);
//		}

//		/* if the node is delegation point
//		   (no matter if whole QNAME was found) */
//		if (zn_is_delegation_point(node)) {
//			ns_referral(node, response, copied_rrs);
//			debug_ns("Size of response packet: %u\n",
//			         ldns_pkt_size(response));
//			break;
//		}

//		if (labels_found < labels) {

//			// DNAME?
//			ldns_rr_list *dname_rrset = NULL;
//			if ((dname_rrset = zn_find_rrset(node,
//						LDNS_RR_TYPE_DNAME)) != NULL) {
//				ns_process_dname(dname_rrset, qname_old,
//				                 response, copied_rrs);
//				break;
//			} else {
//				// wildcard child?
//				debug_ns("Trying to find wildcard child of node"
//					 "%s.\n", ldns_rdf2str(qname));
//				ldns_rdf *wildc = ldns_dname_new_frm_str("*");
//				if (ldns_dname_cat(wildc, qname)
//					!= LDNS_STATUS_OK) {
//					log_error("Unknown error occured.\n");
//					ldns_pkt_set_rcode(response,
//					                   LDNS_RCODE_SERVFAIL);
//					ldns_rdf_deep_free(wildc);
//					break;
//				}

//				const zn_node_t *wildcard_node =
//					zdb_find_name_in_zone(zone, wildc);
//				ldns_rdf_deep_free(wildc);

//				debug_ns("Found node: %p\n", wildcard_node);

//				if (wildcard_node == NULL) {
//					if (cname == 0) {
//						// return NXDOMAIN
//						ldns_pkt_set_rcode(response,
//							LDNS_RCODE_NXDOMAIN);
//					} else {
//						ldns_pkt_set_rcode(response,
//							LDNS_RCODE_NOERROR);
//					}
//					break;
//				} else {
//					node = wildcard_node;
//					// renew the qname to be the old one
//					// (not stripped)
//					ldns_rdf_deep_free(qname);
//					qname = ldns_rdf_clone(qname_old);
//					debug_ns("Node's owner: %s\n",
//					         ldns_rdf2str(node->owner));
//				}
//			}
//		}

//		if (zn_has_cname(node)) {
//			debug_ns("Node %s has CNAME record, resolving...\n",
//				 ldns_rdf2str(node->owner));
//			ldns_rdf *act_name = qname;
//			ns_follow_cname(&node, &act_name, response,
//			                LDNS_SECTION_ANSWER, copied_rrs);
//			debug_ns("Canonical name: %s, node found: %p\n",
//			         ldns_rdf2str(act_name), node);
//			if (act_name != qname) {
//				ldns_rdf_deep_free(qname);
//				qname = act_name;
//			}
//			cname = 1;
//			if (node == NULL) {
//				ldns_rdf_deep_free(qname_old);
//				continue; // infinite loop better than goto? :)
//			}
//		}

//		ns_answer_from_node(node, zone, qname,
//			ldns_rr_get_type(question), response, copied_rrs);
//		ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
//		break;
//	}

//	ldns_rdf_deep_free(qname);
//	ldns_rdf_deep_free(qname_old);
//	debug_ns("Size of response packet: %u\n", ldns_pkt_size(response));
//}

/*----------------------------------------------------------------------------*/

static void ns_answer_from_zone(const dnslib_zone_t *zone,
                                const dnslib_dname_t *qname, uint16_t qtype,
                                dnslib_response_t *resp)
{
	const dnslib_node_t *node = NULL;
	const dnslib_node_t *closest_encloser = NULL;
	int cname = 0;
	//dnslib_dname_t *qname_old = NULL;

	while (1) {
		//qname_old = dnslib_dname_copy(qname);

		int exact_match = dnslib_zone_find_dname(zone, qname, &node,
		                                         &closest_encloser);

		char *name = dnslib_dname_to_str(node->owner);
		debug_ns("zone_find_dname() returned node %s ", name);
		free(name);
		name = dnslib_dname_to_str(closest_encloser->owner);
		debug_ns("and closest encloser %s.\n", name);
		free(name);

		if (exact_match == -2) {  // name not in the zone
			// possible only if we followed cname
			assert(cname != 0);
			dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
			break;
		}

//		assert(exact_match == 1
//		       || (exact_match == 0 && closest_encloser == node));

		if (dnslib_node_is_deleg_point(closest_encloser)) {
			ns_referral(closest_encloser, resp);
			break;
		}

		if (!exact_match) {
			// DNAME?
			const dnslib_rrset_t *dname_rrset =
				dnslib_node_rrset(closest_encloser,
				                  DNSLIB_RRTYPE_DNAME);
			if (dname_rrset != NULL) {
				ns_process_dname(dname_rrset, qname, resp);
				break;
			}
			// else check for a wildcard child
			const dnslib_node_t *wildcard_node =
				dnslib_node_wildcard_child(closest_encloser);

			if (wildcard_node == NULL) {
				if (cname == 0) {
					// return NXDOMAIN
					dnslib_response_set_rcode(resp,
						DNSLIB_RCODE_NXDOMAIN);
				} else {
					dnslib_response_set_rcode(resp,
						DNSLIB_RCODE_NOERROR);
				}
				break;
			}
			// else set the node from which to take the answers to
			// the wildcard node
			node = wildcard_node;
		}

		// now we have the node for answering

		if (dnslib_node_rrset(node, DNSLIB_RRTYPE_CNAME) != NULL) {
			char *name = dnslib_dname_to_str(node->owner);
			debug_ns("Node %s has CNAME record, resolving...\n",
				 name);
			free(name);

			const dnslib_dname_t *act_name = qname;
			ns_follow_cname(&node, &act_name, resp);

			name = dnslib_dname_to_str(act_name);
			debug_ns("Canonical name: %s, node found: %p\n",
			         name, node);
			free(name);

			if (act_name != qname) {
				qname = act_name;
			}
			cname = 1;
			if (node == NULL) {
				continue; // infinite loop better than goto? :)
			}
		}

		ns_answer_from_node(node, zone, qname, qtype, resp);
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_NOERROR);
		break;
	}

	//dnslib_dname_free(&qname_old);
}

/*----------------------------------------------------------------------------*/

static void ns_answer(dnslib_zonedb_t *db, dnslib_response_t *resp)
{
	// TODO: the copying is not needed maybe
	dnslib_dname_t *qname = /*dnslib_dname_copy(*/resp->question.qname/*)*/;
	uint16_t qtype = resp->question.qtype;

	char *name_str = dnslib_dname_to_str(qname);
	debug_ns("Trying to find zone for QNAME %s\n", name_str);
	free(name_str);

	// find zone in which to search for the name
	const dnslib_zone_t *zone =
		ns_get_zone_for_qname(db, qname, qtype);

	// if no zone found, return REFUSED
	if (zone == NULL) {
		debug_ns("No zone found.\n");
		dnslib_response_set_rcode(resp, DNSLIB_RCODE_REFUSED);
		//dnslib_dname_free(&qname);
		return;
	}

	name_str = dnslib_dname_to_str(zone->apex->owner);
	debug_ns("Found zone for QNAME %s\n", name_str);
	free(name_str);

	//debug_ns("Size of response packet: %u\n", ldns_pkt_size(response));

	ns_answer_from_zone(zone, qname, qtype, resp);

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
		log_error("Error converting response packet to wire format. "
		          "dnslib returned: %d\n", ret);
		return -1;
	}

	assert(rsize <= *wire_size);
	memcpy(wire, rwire, rsize);
	*wire_size = rsize;
	free(rwire);

	return 0;
}

/*----------------------------------------------------------------------------*/

//static void ns_response_free(ldns_pkt *response)
//{
//	// no RRs should be deallocated, we must free the packet ourselves
//	LDNS_FREE(response->_header);
//	ldns_rr_list_free(response->_question);
//	ldns_rr_list_free(response->_answer);
//	ldns_rr_list_free(response->_authority);
//	ldns_rr_list_free(response->_additional);

//	// TODO: when used, check if we can free it this way:
//	ldns_rr_free(response->_tsig_rr);
//	ldns_rdf_deep_free(response->_edns_data);

//	LDNS_FREE(response);
//}

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
	dnslib_response_t *err = dnslib_response_new_empty(NULL, 0);
	if (err == NULL) {
		return NULL;
	}

	debug_ns("Created default empty response...\n");

	dnslib_response_set_rcode(err, DNSLIB_RCODE_SERVFAIL);
	ns->err_response = NULL;
	ns->err_resp_size = 0;

	debug_ns("Converting default empty response to wire format...\n");

	if (dnslib_response_to_wire(err, &ns->err_response, &ns->err_resp_size)
	    != 0) {
		log_error("Error while converting default error resposne to "
		          "wire format \n");
		dnslib_response_free(&err);
		free(ns);
		return NULL;
	}

	debug_ns("Done..\n");

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
	debug_ns("ns_answer_request() called with query size %d.\n", qsize);
	debug_ns_hex((char *)query_wire, qsize);

	if (qsize < 2) {
		return -1;
	}

//	debug_ns("Sending default error response...\n");

//	ns_error_response(nameserver, query_wire, DNSLIB_RCODE_FORMAT,
//	                  response_wire, rsize);

	// 1) create empty response
	debug_ns("Parsing query using new dnslib structure...\n");
	dnslib_response_t *resp = dnslib_response_new_empty(NULL, 0);

	if (resp == NULL) {
		log_error("Error while creating response packet!\n");
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_SERVFAIL,
		                  response_wire, rsize);
		return 0;
	}

	int ret = 0;

	// 2) parse the query
	if ((ret = dnslib_response_parse_query(resp, query_wire, qsize)) != 0) {
		log_info("Error while parsing query, dnslib returned: %d\n",
			 ret);
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_FORMERR,
		                  response_wire, rsize);
		dnslib_response_free(&resp);
		return 0;
	}

	debug_ns("Query parsed.\n");
	dnslib_response_dump(resp);

	// 3) get the answer for the query
	rcu_read_lock();

	ns_answer(nameserver->zone_db, resp);

	debug_ns("Created response packet.\n");
	dnslib_response_dump(resp);

	// 4) Transform the packet into wire format
	if (ns_response_to_wire(resp, response_wire, rsize) != 0) {
		// send back SERVFAIL (as this is our problem)
		ns_error_response(nameserver, query_wire, DNSLIB_RCODE_SERVFAIL,
		                  response_wire, rsize);
	}

	dnslib_response_free(&resp);
	rcu_read_unlock();

	debug_ns("Returning response with wire size %d\n", *rsize);
	debug_ns_hex((char *)response_wire, *rsize);

	return 0;
}

/*----------------------------------------------------------------------------*/

void ns_destroy(ns_nameserver **nameserver)
{
	// do nothing with the zone database!
	free((*nameserver)->err_response);
	free(*nameserver);
	*nameserver = NULL;
}

