#include "name-server.h"
#include "zone-node.h"
#include "dns-simple.h"
#include "zone-database.h"
#include <stdio.h>
#include <assert.h>

#include <urcu.h>
#include <ldns/ldns.h>

//#define NS_DEBUG

/*----------------------------------------------------------------------------*/

ns_nameserver *ns_create( zdb_database *database )
{
    ns_nameserver *ns = malloc(sizeof(ns_nameserver));
    if (ns == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }
    ns->zone_db = database;
    return ns;
}

/*----------------------------------------------------------------------------*/

ldns_pkt *ns_create_response( ldns_pkt *query, ldns_rr_list *answer,
						ldns_rr_list *authority, ldns_rr_list *additional )
{
	ldns_pkt *response = ldns_pkt_clone(query);
	if (response == NULL) {
		return NULL;
	}

	ldns_pkt_set_aa(response, 1);
	ldns_pkt_set_qr(response, 1);
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

	return response;
}

/*----------------------------------------------------------------------------*/

int ns_answer_request( ns_nameserver *nameserver, const uint8_t *query_wire,
					   size_t qsize, uint8_t *response_wire, size_t *rsize )
{
    debug_ns("ns_answer_request() called with query size %d.\n", qsize);
	debug_ns_hex((char *)query_wire, qsize);

	ldns_pkt *query;
	if (ldns_wire2pkt(&query, query_wire, qsize) != LDNS_STATUS_OK) {
		// TODO: create error response
		return -1;
	}

	debug_ns("Query parsed:\n");
	debug_ns("%s", ldns_pkt2str(query));

	rcu_read_lock();

	// get the first question entry
	ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(query), 0);
	debug_ns("Question extracted:\n");
	debug_ns("%s", ldns_rr2str(question));

	// find the appropriate zone node
	const zn_node *node = zdb_find_name(nameserver->zone_db,
										ldns_rr_owner(question));
	if (node == NULL) {
		debug_ns("Name not found in the zone database.\n");
		// TODO: create error response
		ldns_pkt_free(query);
		rcu_read_unlock();
		return -1;
	}

	// get the appropriate RRSet
	ldns_rr_list *answer = skip_find(node->rrsets,
									 (void *)ldns_rr_get_type(question));

	if (answer == NULL) {
		debug_ns("Requested RR TYPE not found in the node.\n");
		// TODO: create error response
		ldns_pkt_free(query);
		rcu_read_unlock();
		return -1;
	}

	// create response packet (RRs are copied)
	ldns_pkt *response = ns_create_response(query, answer, NULL, NULL);
	if (response == NULL) {
		log_error("Error creating response packet.\n");
		// TODO: create error response
		ldns_pkt_free(query);
		rcu_read_unlock();
		return -1;
	}

	debug_ns("Created response packet:\n");
	debug_ns("%s", ldns_pkt2str(response));

	// end of RCU read critical section (all data copied)
	node = NULL;
	rcu_read_unlock();

	uint8_t *resp_wire = NULL;
	size_t resp_size = 0;
	if (ldns_pkt2wire(&resp_wire, response, &resp_size) != LDNS_STATUS_OK) {
		log_error("Error converting response packet to wire format.\n");
		// TODO: create error response
		ldns_pkt_free(query);
		ldns_pkt_free(response);	// watch out, this deletes also the RRs!!
		return -1;
	}

	if (resp_size > *rsize) {
		debug_ns("Response in wire format longer than acceptable.\n");
		// TODO: what about truncation???
		// TODO: create error response
		ldns_pkt_free(query);
		ldns_pkt_free(response);	// watch out, this deletes also the RRs!!
		return -1;
	}

	memcpy(response_wire, resp_wire, resp_size);
	*rsize = resp_size;

	debug_ns("Answering complete, returning response with wire size %d\n",
			 resp_size);
	debug_ns_hex((char *)response_wire, resp_size);

	return 0;
}

/*----------------------------------------------------------------------------*/

void ns_destroy( ns_nameserver **nameserver )
{
    // do nothing with the zone database!
    free(*nameserver);
    *nameserver = NULL;
}
