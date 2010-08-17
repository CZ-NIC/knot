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

/*----------------------------------------------------------------------------*/
/* Private functions          					                              */
/*----------------------------------------------------------------------------*/

ldns_pkt *ns_create_empty_response( ldns_pkt *query )
{
	ldns_pkt *response = ldns_pkt_new();
	if (response == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

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

		// copy question section (no matter how many items there are)
		// TODO: we could use the question section from query, not copy the items
		//       to save time and space, but then we would need to be careful with
		//       deallocation of query
		ldns_pkt_push_rr_list(response, LDNS_SECTION_QUESTION,
							  ldns_rr_list_clone(ldns_pkt_question(query)));
	}

	return response;
}

/*----------------------------------------------------------------------------*/

void ns_fill_packet( ldns_pkt *response, ldns_rr_list *answer,
						ldns_rr_list *authority, ldns_rr_list *additional )
{
	ldns_pkt_set_answer(response, ldns_rr_list_clone(answer));
	ldns_pkt_set_ancount(response, ldns_rr_list_rr_count(answer));

	ldns_pkt_set_authority(response, (authority == NULL)
											? ldns_rr_list_new()
											: ldns_rr_list_clone(authority));
	ldns_pkt_set_nscount(response, (authority == NULL)
									 ? 0
									 : ldns_rr_list_rr_count(authority));

	ldns_pkt_set_additional(response, (additional == NULL)
											? ldns_rr_list_new()
											: ldns_rr_list_clone(additional));
	ldns_pkt_set_arcount(response, (additional == NULL)
									 ? 0
									 : ldns_rr_list_rr_count(additional));
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

const zn_node *ns_find_node_in_zone( const zdb_zone *zone, ldns_rdf *qname,
									 uint *labels )
{
	const zn_node *node = NULL;
	// search for the name and strip labels until nothing left
	while ((*labels) > 0 &&
		   (node = zdb_find_name_in_zone(zone, qname)) == NULL) {
		/* TODO: optimize!!!
		 *       1) do not copy the name!
		 *       2) implementation of ldns_dname_left_chop() is inefficient
		 */
		ldns_rdf *new_qname = ldns_dname_left_chop(qname);
		ldns_rdf_deep_free(qname);
		qname = new_qname;
		--(*labels);
		assert(qname != NULL || (*labels) == 0);
	}
	assert((ldns_dname_label_count(qname) == 0 && (*labels) == 0)
		   || (ldns_dname_label_count(qname) > 0 && (*labels) > 0));

	return node;
}

/*----------------------------------------------------------------------------*/

void ns_follow_cname( const zn_node **node, ldns_pkt *response ) {
	debug_ns("Resolving CNAME chain...\n");
	while (zn_get_ref_cname(*node) != NULL) {
		assert(zn_find_rrset((*node), LDNS_RR_TYPE_CNAME) != NULL);
		ldns_pkt_push_rr_list(response, LDNS_SECTION_ANSWER,
							  zn_find_rrset((*node), LDNS_RR_TYPE_CNAME));
		(*node) = zn_get_ref_cname(*node);
	}
}

/*----------------------------------------------------------------------------*/

static inline void ns_put_rrset( const zn_node *node, ldns_rr_type type,
								 ldns_pkt_section section, ldns_pkt *response )
{
	ldns_rr_list *rrset = zn_find_rrset(node, type);
	if (rrset != NULL) {
		ldns_pkt_push_rr_list(response, section, rrset);
	}
}

/*----------------------------------------------------------------------------*/

static inline void ns_put_answer( const zn_node *node, ldns_rr_type type,
								  ldns_pkt *response )
{
	ns_put_rrset(node, type, LDNS_SECTION_ANSWER, response);
	ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
}

/*----------------------------------------------------------------------------*/

static inline void ns_put_authority_ns( const zdb_zone *zone, ldns_pkt *resp )
{
	ns_put_rrset(zone->apex, LDNS_RR_TYPE_NS, LDNS_SECTION_AUTHORITY, resp);
}

/*----------------------------------------------------------------------------*/

static inline void ns_put_glues( const zn_node *node, ldns_pkt *response )
{
	ldns_rr_list *glues = zn_get_glues(node);
	if (glues != NULL) {
		ldns_pkt_push_rr_list(response, LDNS_SECTION_ADDITIONAL, glues);
	}
}

/*----------------------------------------------------------------------------*/

static inline void ns_referral( const zn_node *node, ldns_pkt *response )
{
	debug_ns("Referral response.\n");
	ns_put_rrset(node, LDNS_RR_TYPE_NS, LDNS_SECTION_AUTHORITY, response);
	ns_put_glues(node, response);
	ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);
}

/*----------------------------------------------------------------------------*/

void ns_answer( zdb_database *zdb, const ldns_rr *question, ldns_pkt *response )
{
	// copy the QNAME, as we may be stripping labels
	// TODO: maybe not needed, the original form of the question is useless now
	ldns_rdf *qname = ldns_rdf_clone(ldns_rr_owner(question));

	// find zone in which to search for the name
	const zdb_zone *zone =
			ns_get_zone_for_qname(zdb, qname, ldns_rr_get_type(question));

	// if no zone found, return NXDOMAIN
	if (zone == NULL) {
		ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
		return;
	}

	// find proper zone node
	uint labels = ldns_dname_label_count(qname);
	uint labels_found = labels;
	const zn_node *node = ns_find_node_in_zone(zone, qname, &labels_found);

	// if the name was not found in the zone something is wrong (SERVFAIL)
	if (labels_found == 0) {
		log_error("Name %s not found in zone %s! Returning SERVFAIL\n",
				  ldns_rdf2str(qname), ldns_rdf2str(zone->zone_name));
		ldns_pkt_set_rcode(response, LDNS_RCODE_SERVFAIL);
		return;
	}
	assert(node != NULL);

	// if the node is delegation point (no matter if whole QNAME was found)
	if (zn_is_delegation_point(node)) {
		ns_referral(node, response);
		return;
	}

	if (labels_found == labels) {	// whole QNAME found
		if (zn_has_cname(node)) {
			// resolve the cname chain and copy all CNAME records to the answer
			ns_follow_cname(&node, response);
			// node is now set to the canonical name node (if found)
			if (node == NULL) {
				// TODO: add SOA??
				ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
				return;
			}
		}
		//assert(ldns_dname_compare(node->owner, qname) == 0);
		ns_put_answer(node, ldns_rr_get_type(question), response);
		ns_put_authority_ns(zone, response);
	} else {	// only part of QNAME found
		// if we ended in the zone apex, the name is not in the zone
		if (zone->apex == node) {
			debug_ns("Name not found in the zone.\n");
			ns_put_rrset(node, LDNS_RR_TYPE_SOA, LDNS_SECTION_AUTHORITY,
						 response);
			ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
		} else {
			debug_ns("DNAME and Wildcard not implemented yet.\n");
			ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
		}
	}
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
			return -1;
		} else {
			// everything went well, copy the wire format of the response
			memcpy(wire, rwire, rsize);
			*wire_size = rsize;
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
	ns_answer(nameserver->zone_db, question, response);
	ldns_pkt_free(query);

	debug_ns("Created response packet: %s\n", ldns_pkt2str(response));

	// 4) Transform the packet into wire format
	if (ns_response_to_wire(response, response_wire, rsize) != 0) {
		// send back SERVFAIL (as this is our problem)
		ns_error_response(nameserver, *((const uint16_t *)query_wire),
						  LDNS_RCODE_SERVFAIL, response_wire, rsize);
	}

	ns_response_free(response);
	rcu_read_unlock();

	debug_ns("Returning response with wire size %d\n", *rsize);
	debug_ns_hex((char *)response_wire, *rsize);

	return 0;
}

/*----------------------------------------------------------------------------*/

void ns_destroy( ns_nameserver **nameserver )
{
    // do nothing with the zone database!
    free(*nameserver);
    *nameserver = NULL;
}
