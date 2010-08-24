#include "name-server.h"
#include "zone-node.h"
#include "zone-database.h"
#include <stdio.h>
#include <assert.h>

#include <urcu.h>
#include <ldns/ldns.h>

//#define NS_DEBUG

static const uint8_t RCODE_MASK = 0xf0;
static const int OFFSET_FLAGS2 = 3;

static const size_t RR_FIXED_SIZE = 10;
static const size_t QUESTION_FIXED_SIZE = 4;

static const uint16_t MAX_UDP_PAYLOAD_EDNS = 4096;
static const uint16_t MAX_UDP_PAYLOAD = 512;
static const uint8_t EDNS_VERSION = 0;
static const uint8_t OPT_SIZE = 11;

static const int EDNS_ENABLED = 0;

/*----------------------------------------------------------------------------*/
/* Private functions          					                              */
/*----------------------------------------------------------------------------*/

void ns_set_edns( const ldns_pkt *query, ldns_pkt *response )
{
	if (EDNS_ENABLED) {
		ldns_pkt_set_edns_data(response, NULL);
		ldns_pkt_set_edns_do(response, ldns_pkt_edns_do(query));
		ldns_pkt_set_edns_extended_rcode(response, 0);
		ldns_pkt_set_edns_udp_size(response, MAX_UDP_PAYLOAD_EDNS);
		ldns_pkt_set_edns_version(response, EDNS_VERSION);
		ldns_pkt_set_edns_z(response, 0);
	} else {
		ldns_pkt_set_edns_udp_size(response, 0);
		assert(!ldns_pkt_edns(response));
	}
}

/*----------------------------------------------------------------------------*/

void ns_set_max_packet_size( ldns_pkt *response )
{
	if (EDNS_ENABLED) {
		ldns_pkt_set_edns_udp_size(response, MAX_UDP_PAYLOAD_EDNS);
		// also set the size of the packet to consider the OPT record
		ldns_pkt_set_size(response, ldns_pkt_size(response) + OPT_SIZE);
	} else {
		ldns_pkt_set_edns_udp_size(response, MAX_UDP_PAYLOAD);
	}
}

/*----------------------------------------------------------------------------*/

ldns_pkt *ns_create_empty_response( ldns_pkt *query )
{
	ldns_pkt *response = ldns_pkt_new();
	if (response == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ldns_pkt_set_size(response, LDNS_HEADER_SIZE);

	if (query != NULL) {
		// copy ID
		ldns_pkt_set_id(response, ldns_pkt_id(query));
		// authoritative response
		ldns_pkt_set_aa(response, 1);
		// response
		ldns_pkt_set_qr(response, 1);
		// copy "recursion desired" bit
		ldns_pkt_set_rd(response, ldns_pkt_rd(query));
		// all other flags are by default set to 0
		// save the question section from query (do not copy)
		// save it RR by RR (to get size)
		ldns_rr_list *question = ldns_pkt_question(query);
		for (uint i = 0; i < ldns_rr_list_rr_count(question); ++i) {
			ldns_rr *rr = ldns_rr_list_rr(question, i);
			ldns_pkt_push_rr(response, LDNS_SECTION_QUESTION, rr);

			// there should be no RDATA in the RR
			assert(ldns_rr_rd_count(rr) == 0);

			ldns_pkt_set_size(response, ldns_pkt_size(response) +
							  ldns_rdf_size(ldns_rr_owner(rr))
							  + QUESTION_FIXED_SIZE);
		}
	}

	ns_set_max_packet_size(response);

	return response;
}

/*----------------------------------------------------------------------------*/

static inline void ns_set_rcode( uint8_t *flags, uint8_t rcode )
{
	assert(rcode < 11);
	(*flags) = ((*flags) & RCODE_MASK) | rcode;
}

/*----------------------------------------------------------------------------*/

static inline void ns_error_response( ns_nameserver *nameserver, uint16_t id,
									  uint8_t rcode, uint8_t *response_wire,
									  size_t *rsize )
{
	memcpy(response_wire, nameserver->err_response,
		   nameserver->err_resp_size);
	// copy ID of the query
	memcpy(response_wire, &id, 2);
	// set the RCODE
	ns_set_rcode(response_wire + OFFSET_FLAGS2, rcode);
	*rsize = nameserver->err_resp_size;
}

/*----------------------------------------------------------------------------*/

const zdb_zone *ns_get_zone_for_qname( zdb_database *zdb, const ldns_rdf *qname,
									   const ldns_rr_type qtype )
{
	const zdb_zone *zone;
	/*
	 * Find a zone in which to search.
	 *
	 * In case of DS query, we strip the leftmost label when searching for
	 * the zone (but use whole qname in search for the record), as the DS
	 * records are only present in a parent zone.
	 */
	if (qtype == LDNS_RR_TYPE_DS) {
		/*
		 * TODO: optimize!!!
		 *       1) do not copy the name!
		 *       2) implementation of ldns_dname_left_chop() is inefficient
		 */
		ldns_rdf *name = ldns_dname_left_chop(qname);
		zone = zdb_find_zone_for_name(zdb, name);
		ldns_rdf_deep_free(name);
	} else {
		zone = zdb_find_zone_for_name(zdb, qname);
	}

	return zone;
}

/*----------------------------------------------------------------------------*/

int ns_fits_into_response( const ldns_pkt *response, size_t size )
{
	return (!ldns_pkt_tc(response) &&
		ldns_pkt_size(response) + size <= ldns_pkt_edns_udp_size(response));
}

/*----------------------------------------------------------------------------*/

size_t ns_rr_size( ldns_rr *rr )
{
	size_t size = 0;
	size += RR_FIXED_SIZE;
	size += ldns_rdf_size(ldns_rr_owner(rr));
	for (int j = 0; j < ldns_rr_rd_count(rr); ++j) {
		size += ldns_rdf_size(ldns_rr_rdf(rr, j));
	}
	return size;
}

/*----------------------------------------------------------------------------*/

size_t ns_rrset_size( ldns_rr_list *rrset )
{
	size_t size = 0;
	for (int i = 0; i < ldns_rr_list_rr_count(rrset); ++i) {
		size += RR_FIXED_SIZE;
		size += ldns_rdf_size(ldns_rr_owner(ldns_rr_list_rr(rrset, i)));
		for (int j = 0; j < ldns_rr_rd_count(ldns_rr_list_rr(rrset, i)); ++j) {
			size += ldns_rdf_size(ldns_rr_rdf(ldns_rr_list_rr(rrset, i), j));
		}
	}
	return size;
}

/*----------------------------------------------------------------------------*/

const zn_node *ns_find_node_in_zone( const zdb_zone *zone, ldns_rdf **qname,
									 uint *labels )
{
	const zn_node *node = NULL;
	// search for the name and strip labels until nothing left
	while ((*labels) > 0 &&
		   (node = zdb_find_name_in_zone(zone, *qname)) == NULL) {
		debug_ns("Name %s not found, stripping leftmost label.\n",
				 ldns_rdf2str(*qname));
		/* TODO: optimize!!!
		 *       1) do not copy the name!
		 *       2) implementation of ldns_dname_left_chop() is inefficient
		 */
		ldns_rdf *new_qname = ldns_dname_left_chop(*qname);
		ldns_rdf_deep_free(*qname);
		*qname = new_qname;
		--(*labels);
		assert(*qname != NULL || (*labels) == 0);
	}
	assert((ldns_dname_label_count(*qname) == 0 && (*labels) == 0)
		   || (ldns_dname_label_count(*qname) > 0 && (*labels) > 0));

	return node;
}

/*----------------------------------------------------------------------------*/

void ns_update_response_size( ldns_pkt *response, size_t size )
{
	ldns_pkt_set_size(response, ldns_pkt_size(response) + size);
}

/*----------------------------------------------------------------------------*/

//int ns_push_rr_list( ldns_pkt *response, ldns_pkt_section section,
//					 ldns_rr_list *rrset )
//{
//	//size_t size = ns_rrset_size(rrset);
//	if (ns_fits_into_response(response, size)) {
//		int count = ldns_rr_list_rr_count(rrset);
//		for (int i = 0; i < count; ++i) {
//			if (!ldns_pkt_push_rr(response, section, ldns_rr_list_rr(rrset, i))) {
//				return -1;
//			}
//			ns_update_response_size(response, ldns_rr_list_rr(rrset, i));
//		}
//		return 0;
//	} else {
//		return 1;
//	}
//}

/*----------------------------------------------------------------------------*/
/*!
 * @todo Check return values from push functions!
 */
void ns_follow_cname( const zn_node **node, const ldns_rdf **qname,
					  ldns_pkt *pkt, ldns_pkt_section section,
					  ldns_rr_list *copied_rrs )
{
	debug_ns("Resolving CNAME chain...\n");
	assert(zn_has_cname(*node) > 0);
	do {
		// put the CNAME record to answer, but replace the possible wildcard
		// name with qname
		ldns_rr_list *cname_rrset = zn_find_rrset((*node), LDNS_RR_TYPE_CNAME);
		assert(cname_rrset != NULL);
		// ignoring other than the first record
		ldns_rr *cname_rr;
		if (ldns_dname_is_wildcard((*node)->owner)) {
			// if wildcard node, we must copy the RR and replace its owner
			cname_rr = ldns_rr_clone(ldns_rr_list_rr(cname_rrset, 0));
			ldns_rdf_deep_free(ldns_rr_owner(cname_rr));
			ldns_rr_set_owner(cname_rr, ldns_rdf_clone(*qname));
			ldns_rr_list_push_rr(copied_rrs, cname_rr);
		} else {
			cname_rr = ldns_rr_list_rr(cname_rrset, 0);
		}
		size_t cname_rr_size = ns_rr_size(cname_rr);
		if (ns_fits_into_response(pkt, cname_rr_size)) {
			ldns_pkt_push_rr(pkt, section, cname_rr);
			ns_update_response_size(pkt, cname_rr_size);
		} else {
			// set TC bit (answer records omitted)
			ldns_pkt_set_tc(pkt, 1);
			return;
		}
		debug_ns("CNAME record for owner %s put to answer section.\n",
				 ldns_rdf2str(ldns_rr_owner(cname_rr)));

		(*node) = zn_get_ref_cname(*node);
		// save the new name which should be used for replacing wildcard
		*qname = ldns_rr_rdf(cname_rr, 0);
		assert(ldns_rdf_get_type(*qname) == LDNS_RDF_TYPE_DNAME);
	} while (*node != NULL && zn_has_cname(*node));
}

/*----------------------------------------------------------------------------*/

void ns_try_put_rrset( ldns_rr_list *rrset, ldns_pkt_section section, int tc,
					   ldns_pkt *resp )
{
	if (rrset != NULL) {
		size_t size = ns_rrset_size(rrset);
		if (ns_fits_into_response(resp, size)) {
			ldns_pkt_push_rr_list(resp, section, rrset);
			ns_update_response_size(resp, size);
		} else {
			ldns_pkt_set_tc(resp, tc);
		}
	}
}

/*----------------------------------------------------------------------------*/

void ns_put_rrset( ldns_rr_list *rrset, const ldns_rdf *name,
				   ldns_pkt_section section, int tc, ldns_pkt *pkt,
				   ldns_rr_list *copied_rrs )
{
	if (rrset) {
		size_t size = 0;
		if (ldns_dname_is_wildcard(ldns_rr_list_owner(rrset))) {
			// we must copy the whole list and replace owners with name
			ldns_rr_list *rrset_new = ldns_rr_list_new();
			int count = ldns_rr_list_rr_count(rrset);
			for (int i = 0; i < count; ++i) {
				ldns_rr *rr = ldns_rr_clone(ldns_rr_list_rr(rrset, i));
				ldns_rdf_deep_free(ldns_rr_owner(rr));
				ldns_rr_set_owner(rr, ldns_rdf_clone(name));
				//ldns_pkt_push_rr(pkt, section, rr);
				ldns_rr_list_push_rr(rrset_new, rr);
				size += ns_rr_size(rr);
				//ns_update_response_size(pkt, rr);
				ldns_rr_list_push_rr(copied_rrs, rr);
			}
			ns_try_put_rrset(rrset_new, section, tc, pkt);
//			size = ns_rrset_size(rrset_new);
//			if (ns_fits_into_response(response, size)) {
//				ldns_pkt_push_rr_list(pkt, section, rrset_new);
//				ns_update_response_size(pkt, size);
//			} else {
//				ldns_pkt_set_tc(pkt, 1);
//				return;
//			}
		} else {
			ns_try_put_rrset(rrset, section, tc, pkt);
//			size = ns_rrset_size(rrset);
//			if (ns_fits_into_response(response, size)) {
//				ldns_pkt_push_rr_list(pkt, section, rrset);
//				ns_update_response_size(pkt, size);
//			} else {
//				ldns_pkt_set_tc(pkt, 1);
//				return;
//			}
		}
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * @todo Check return values from push functions!
 */
void ns_put_answer( const zn_node *node, const ldns_rdf *name,
					ldns_rr_type type, ldns_pkt *response,
					ldns_rr_list *copied_rrs )
{
	debug_ns("Putting answers from node %s.\n", ldns_rdf2str(node->owner));
	ns_put_rrset(zn_find_rrset(node, type), name, LDNS_SECTION_ANSWER, 1,
				 response, copied_rrs);
	ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
}

/*----------------------------------------------------------------------------*/

void ns_put_additional( const zn_node *node, ldns_pkt *response,
						ldns_rr_list *copied_rrs )
{
	debug_ns("ADDITIONAL SECTION PROCESSING\n");

	if (zn_has_mx(node) == 0 && zn_has_ns(node) == 0) {
		// nothing to put
		return;
	}

	// for each answer RR add appropriate additional records
	int count = ldns_pkt_ancount(response);
	for (int i = 0; i < count; ++i) {
		ldns_rr *rr = ldns_rr_list_rr(ldns_pkt_answer(response), i);
		const ldns_rdf *name;

		switch (ldns_rr_get_type(rr)) {
		case LDNS_RR_TYPE_MX:
			name = ldns_rr_mx_exchange(rr);
			break;
		case LDNS_RR_TYPE_NS:
			name = ldns_rr_ns_nsdname(rr);
			break;
		default:
			continue;
		}

		debug_ns("Adding RRSets for name %s\n", ldns_rdf2str(name));
		const zn_ar_rrsets *rrsets = zn_get_ref(node, name);
		if (rrsets != NULL) {
			if (rrsets->cname != NULL) {
				const zn_node *cname_node = rrsets->cname;
				ns_follow_cname(&cname_node, &name, response,
								LDNS_SECTION_ADDITIONAL, copied_rrs);
				rrsets = zn_get_ref(cname_node, name);
				if (rrsets == NULL) {
					continue;
				}
			}
			ns_put_rrset(rrsets->a, name, LDNS_SECTION_ADDITIONAL, 0, response,
						 copied_rrs);
			ns_put_rrset(rrsets->aaaa, name, LDNS_SECTION_ADDITIONAL, 0,
						 response, copied_rrs);
		}
	}
}

/*----------------------------------------------------------------------------*/

void ns_put_authority_ns( const zdb_zone *zone, ldns_pkt *resp )
{
	ldns_rr_list *rrset = zn_find_rrset(zone->apex, LDNS_RR_TYPE_NS);
	ns_try_put_rrset(rrset, LDNS_SECTION_AUTHORITY, 0, resp);
}

/*----------------------------------------------------------------------------*/

void ns_put_authority_soa( const zdb_zone *zone, ldns_pkt *resp )
{
	ldns_rr_list *rrset = zn_find_rrset(zone->apex, LDNS_RR_TYPE_SOA);
	ns_try_put_rrset(rrset, LDNS_SECTION_AUTHORITY, 0, resp);
}

/*----------------------------------------------------------------------------*/

void ns_put_glues( const zn_node *node, ldns_pkt *response,
								 ldns_rr_list *copied_rrs )
{
	ldns_rr_list *glues = zn_get_glues(node);

	if (glues == NULL) {
		return;
	}

	for (int i = 0; i < ldns_rr_list_rr_count(glues); ++i) {
		ldns_rr *glue_rr = ldns_rr_list_rr(glues, i);

		// if owner is wildcard, find appropriate name in the RDATA fields of
		// Authority NS, copy the glue RR and change the owner
		if (ldns_dname_is_wildcard(ldns_rr_owner(glue_rr))) {
			ldns_rr_list *auth = ldns_pkt_authority(response);
			debug_ns("Searching for NS record for wildcard glue %s.\n",
					 ldns_rdf2str(ldns_rr_owner(glue_rr)));
			int cmp = -1;
			int j = 0;
			int count = ldns_rr_list_rr_count(auth);
			for (; j < count; ++j) {
				if (ldns_rr_get_type(ldns_rr_list_rr(auth, j))
						== LDNS_RR_TYPE_NS
					&& ((cmp = ldns_dname_match_wildcard(
							ldns_rr_ns_nsdname(ldns_rr_list_rr(auth, j)),
							ldns_rr_owner(glue_rr))) == 1)) {
					break;	// found
				}
			}
			assert(cmp == 1); // must have found something if the glue is there

			debug_ns("Found NS record for wildcard glue %s:\n%s\n",
					 ldns_rdf2str(ldns_rr_owner(glue_rr)),
					 ldns_rr2str(ldns_rr_list_rr(auth, j)));

			ldns_rr *glue_rr_new = ldns_rr_clone(glue_rr);
			ldns_rdf_deep_free(ldns_rr_owner(glue_rr_new));
			ldns_rr_set_owner(ldns_rr_list_rr(glues, i), ldns_rdf_clone(
					ldns_rr_ns_nsdname(ldns_rr_list_rr(auth, j))));
			ldns_rr_list_push_rr(copied_rrs, glue_rr_new);

			size_t size = ns_rr_size(glue_rr_new);
			if (ns_fits_into_response(response, size)) {
				ldns_pkt_push_rr(response, LDNS_SECTION_ADDITIONAL,
							 glue_rr_new);
				// update size of the packet
				ns_update_response_size(response, size);
			} else {
				ldns_pkt_set_tc(response, 1);
				return;
			}
		} else {
			size_t size = ns_rr_size(glue_rr);
			if (ns_fits_into_response(response, size)) {
				ldns_pkt_push_rr(response, LDNS_SECTION_ADDITIONAL, glue_rr);
				ns_update_response_size(response, size);
			} else {
				ldns_pkt_set_tc(response, 1);
				return;
			}
		}
	}
}

/*----------------------------------------------------------------------------*/

static inline void ns_referral( const zn_node *node, ldns_pkt *response,
								ldns_rr_list *copied_rrs )
{
	debug_ns("Referral response.\n");
	ldns_rr_list *rrset = zn_find_rrset(node, LDNS_RR_TYPE_NS);
	if (rrset != NULL) {
		ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);

		ns_try_put_rrset(rrset, LDNS_SECTION_AUTHORITY, 1, response);

//		size_t size = ns_rrset_size(rrset);
//		if (ns_fits_into_response(response, size)) {
//			ldns_pkt_push_rr_list(response, LDNS_SECTION_AUTHORITY, rrset);
//			// update size of the packet
//			ns_update_response_size(response, size);
//		} else {
//			ldns_pkt_set_tc(response, 1);
//			return;
//		}

		ns_put_glues(node, response, copied_rrs);
	}	
}

/*----------------------------------------------------------------------------*/

void ns_answer_from_node( const zn_node *node, const zdb_zone *zone,
						  const ldns_rdf *qname, ldns_rr_type qtype,
						  ldns_pkt *response, ldns_rr_list *copied_rrs )
{
	debug_ns("Putting answers from found node to the response...\n");
	if (zn_has_cname(node) > 0) {
		// resolve the cname chain and copy all CNAME records to the answer
		ns_follow_cname(&node, &qname, response, LDNS_SECTION_ANSWER,
						copied_rrs);
		// node is now set to the canonical name node (if found)
		if (node == NULL) {
			// TODO: add SOA??
			ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
			return;
		}
	}
	//assert(ldns_dname_compare(node->owner, qname) == 0);
	ns_put_answer(node, qname, qtype, response, copied_rrs);
	ns_put_authority_ns(zone, response);
	ns_put_additional(node, response, copied_rrs);
}

/*----------------------------------------------------------------------------*/

void ns_answer( zdb_database *zdb, const ldns_rr *question, ldns_pkt *response,
				ldns_rr_list *copied_rrs )
{
	// copy the QNAME, as we may be stripping labels and the QNAME is used in
	// response packet
	ldns_rdf *qname = ldns_rdf_clone(ldns_rr_owner(question));

	// find zone in which to search for the name
	const zdb_zone *zone =
			ns_get_zone_for_qname(zdb, qname, ldns_rr_get_type(question));

	// if no zone found, return NXDOMAIN
	if (zone == NULL) {
		ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
		ldns_rdf_deep_free(qname);
		return;
	}

	debug_ns("Size of response packet: %u\n", ldns_pkt_size(response));

	// find proper zone node
	uint labels = ldns_dname_label_count(qname);
	uint labels_found = labels;
	const zn_node *node;

	search:
	node = ns_find_node_in_zone(zone, &qname, &labels_found);

	// if the name was not found in the zone something is wrong (SERVFAIL)
	if (labels_found == 0) {
		log_error("Name %s not found in zone %s! Returning SERVFAIL\n",
				  ldns_rdf2str(ldns_rr_owner(question)),
				  ldns_rdf2str(zone->zone_name));
		ldns_pkt_set_rcode(response, LDNS_RCODE_SERVFAIL);
		ldns_rdf_deep_free(qname);
		return;
	}
	assert(node != NULL);

	// if the node is delegation point (no matter if whole QNAME was found)
	if (zn_is_delegation_point(node)) {
		ns_referral(node, response, copied_rrs);
		debug_ns("Size of response packet: %u\n", ldns_pkt_size(response));
		ldns_rdf_deep_free(qname);
		return;
	}

	if (labels_found == labels) {	// whole QNAME found
		ns_answer_from_node(node, zone, qname, ldns_rr_get_type(question),
							response, copied_rrs);
	} else {	// only part of QNAME found
		debug_ns("Found node with name: %s (rest of QNAME: %s).\n",
				 ldns_rdf2str(node->owner), ldns_rdf2str(qname));

		// try to find a wildcard child
		ldns_rdf *wildcard = ldns_dname_new_frm_str("*");
		if (ldns_dname_cat(wildcard, qname) != LDNS_STATUS_OK) {
			log_error("Unknown error occured.\n");
			ldns_rdf_deep_free(wildcard);
			ldns_rdf_deep_free(qname);
			return;	// need some return value??
		}

		const zn_node *wildcard_node = zdb_find_name_in_zone(zone, wildcard);
		if (wildcard_node != NULL) {
			debug_ns("Found wildcard node %s, answering.\n", ldns_rdf2str(
					wildcard_node->owner));
			ns_answer_from_node(wildcard_node, zone, ldns_rr_owner(question),
								ldns_rr_get_type(question), response,
								copied_rrs);
		} else if (zone->apex == node) {
			// if we ended in the zone apex, the name is not in the zone
			ns_put_authority_soa(zone, response);
			ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
		} else {
			debug_ns("DNAME not implemented yet.\n");
			// continue searching for the new qname
			goto search;
			//ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
		}
		ldns_rdf_deep_free(wildcard);
	}

	ldns_rdf_deep_free(qname);
	debug_ns("Size of response packet: %u\n", ldns_pkt_size(response));
}

/*----------------------------------------------------------------------------*/

int ns_response_to_wire( const ldns_pkt *response, uint8_t *wire,
						 size_t *wire_size )
{
	uint8_t *rwire = NULL;
	size_t rsize = 0;
	ldns_status s;

	if ((s = ldns_pkt2wire(&rwire, response, &rsize)) != LDNS_STATUS_OK) {
		log_error("Error converting response packet to wire format.\n"
				  "ldns returned: %s\n", ldns_get_errorstr_by_id(s));
		return -1;
	} else {
		if (rsize > *wire_size) {
			debug_ns("Response in wire format longer than acceptable.\n");
			// TODO: truncation
			// while not implemented, send back SERVFAIL
			log_error("Truncation needed, but not implemented!\n");
			free(rwire);
			return -1;
		} else {
			// everything went well, copy the wire format of the response
			memcpy(wire, rwire, rsize);
			*wire_size = rsize;
			free(rwire);
		}
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

void ns_response_free( ldns_pkt *response )
{
	// no RRs should be deallocated, we must free the packet ourselves
	LDNS_FREE(response->_header);
	ldns_rr_list_free(response->_question);
	ldns_rr_list_free(response->_answer);
	ldns_rr_list_free(response->_authority);
	ldns_rr_list_free(response->_additional);

	// TODO: when used, check if we can free it this way:
	ldns_rr_free(response->_tsig_rr);
	ldns_rdf_deep_free(response->_edns_data);

	LDNS_FREE(response);
}

/*----------------------------------------------------------------------------*/
/* Public functions          					                              */
/*----------------------------------------------------------------------------*/

ns_nameserver *ns_create( zdb_database *database )
{
    ns_nameserver *ns = malloc(sizeof(ns_nameserver));
    if (ns == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }
    ns->zone_db = database;

	// prepare empty response with SERVFAIL error
	ldns_pkt *err = ns_create_empty_response(NULL);
	if (err == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	ldns_pkt_set_rcode(err, LDNS_RCODE_SERVFAIL);

	ldns_status s = ldns_pkt2wire(&ns->err_response, err, &ns->err_resp_size);
	if (s != LDNS_STATUS_OK) {
		log_error("Error while converting default error resposne to wire format"
				"\n");
		ldns_pkt_free(err);
		return NULL;
	}

	ldns_pkt_free(err);

    return ns;
}

/*----------------------------------------------------------------------------*/

int ns_answer_request( ns_nameserver *nameserver, const uint8_t *query_wire,
					   size_t qsize, uint8_t *response_wire, size_t *rsize )
{
    debug_ns("ns_answer_request() called with query size %d.\n", qsize);
	debug_ns_hex((char *)query_wire, qsize);

	ldns_status s = LDNS_STATUS_OK;
	ldns_pkt *query;

	// 1) Parse the query.
	if ((s = ldns_wire2pkt(&query, query_wire, qsize)) != LDNS_STATUS_OK) {
		log_info("Error while parsing query.\nldns returned: %s\n",
				ldns_get_errorstr_by_id(s));
		// malformed question, returning FORMERR in empty packet, but copy ID
		// if there aren't at least those 2 bytes, ignore
		if (qsize < 2) {
			return -1;
		}
		ns_error_response(nameserver, *((const uint16_t *)query_wire),
						  LDNS_RCODE_FORMERR, response_wire, rsize);
		return 0;
	}

	// 2) Prepare empty response (used as an error response as well).
	ldns_pkt *response = ns_create_empty_response(query);
	if (response == NULL) {
		log_error("Error while creating response packet!\n");
		ns_error_response(nameserver, *((const uint16_t *)query_wire),
						  LDNS_RCODE_SERVFAIL, response_wire, rsize);
		ldns_pkt_free(query);
		return 0;
	}

	debug_ns("Query parsed: %s\n", ldns_pkt2str(query));

	// 3) Fill the response according to the lookup algorithm.
	// get the first question entry (other ignored)
	ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(query), 0);
	debug_ns("Question extracted: %s\n", ldns_rr2str(question));

	rcu_read_lock();
	ldns_rr_list *copied_rrs = ldns_rr_list_new();
	ns_answer(nameserver->zone_db, question, response, copied_rrs);

	debug_ns("Created response packet: %s\n", ldns_pkt2str(response));

	// set proper EDNS section (setting here to override the saved max size)
	ns_set_edns(query, response);

	// 4) Transform the packet into wire format
	if (ns_response_to_wire(response, response_wire, rsize) != 0) {
		// send back SERVFAIL (as this is our problem)
		ns_error_response(nameserver, *((const uint16_t *)query_wire),
						  LDNS_RCODE_SERVFAIL, response_wire, rsize);
	}

	ldns_pkt_free(query);
	ns_response_free(response);
	// free the copied RRs
	ldns_rr_list_deep_free(copied_rrs);
	rcu_read_unlock();

	debug_ns("Returning response with wire size %d\n", *rsize);
	debug_ns_hex((char *)response_wire, *rsize);

	return 0;
}

/*----------------------------------------------------------------------------*/

void ns_destroy( ns_nameserver **nameserver )
{
    // do nothing with the zone database!
	free((*nameserver)->err_response);
    free(*nameserver);
    *nameserver = NULL;
}
