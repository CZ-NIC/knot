#include "name-server.h"
#include "zone-node.h"
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

ldns_pkt *ns_create_empty_response( ldns_pkt *query )
{
	ldns_pkt *response = ldns_pkt_clone(query);
	if (response == NULL) {
		return NULL;
	}

	ldns_pkt_set_aa(response, 1);
	ldns_pkt_set_qr(response, 1);
	ldns_pkt_set_answer(response, NULL);
	ldns_pkt_set_ancount(response, 0);

	ldns_pkt_set_authority(response, NULL);
	ldns_pkt_set_nscount(response, 0);

	ldns_pkt_set_additional(response, NULL);
	ldns_pkt_set_arcount(response, 0);

	return response;
}

/*----------------------------------------------------------------------------*/

void ns_fill_response( ldns_pkt *response, ldns_rr_list *answer,
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

int ns_answer_request( ns_nameserver *nameserver, const uint8_t *query_wire,
					   size_t qsize, uint8_t *response_wire, size_t *rsize )
{
    debug_ns("ns_answer_request() called with query size %d.\n", qsize);
	debug_ns_hex((char *)query_wire, qsize);

	ldns_status s = LDNS_STATUS_OK;
	ldns_pkt *query;
	if ((s = ldns_wire2pkt(&query, query_wire, qsize)) != LDNS_STATUS_OK) {
		log_info("Error while parsing query.\nldns returned: %s\n",
				ldns_get_errorstr_by_id(s));
		// malformed question => ignore
		// TODO: should somehow return FORMERR ??? we would need to copy the
		// wire format of the query and just set the proper RCODE, AA and QR bit
		return -1;
	}

	debug_ns("Query parsed:\n");
	debug_ns("%s", ldns_pkt2str(query));

	// prepare empty response (used as an error response as well)
	ldns_pkt *response = ns_create_empty_response(query);
	if (response == NULL) {
		log_error("Error while creating response packet!\n");
		ldns_pkt_free(query);
		return -1;
	}

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
		// return NXDOMAIN
		ldns_pkt_set_rcode(response, LDNS_RCODE_NXDOMAIN);
	} else {
		// get the appropriate RRSet
		ldns_rr_list *answer = skip_find(node->rrsets,
										 (void *)ldns_rr_get_type(question));

		if (answer != NULL) {
			// fill the response packet (RRs are copied)
			ns_fill_response(response, answer, NULL, NULL);
			// end of RCU read critical section (all data copied)
			node = NULL;
		}

		// make sure proper RCODE is set
		ldns_pkt_set_rcode(response, LDNS_RCODE_NOERROR);

		// if not found, it means there is no RRSet for given type
		// return "NODATA" response - i.e. empty with NOERROR RCODE
	}
	rcu_read_unlock();
	ldns_pkt_free(query);

	debug_ns("Created response packet:\n");
	debug_ns("%s", ldns_pkt2str(response));

	// transform the packet into wire format
	uint8_t *resp_wire = NULL;
	size_t resp_size = 0;
	if ((s = ldns_pkt2wire(&resp_wire, response, &resp_size))
			!= LDNS_STATUS_OK) {
		log_error("Error converting response packet to wire format.\n"
				  "ldns returned: %s\n", ldns_get_errorstr_by_id(s));
		// send nothing back
		ldns_pkt_free(response);
		return -1;
	}

	ldns_pkt_free(response);

	if (resp_size > *rsize) {
		debug_ns("Response in wire format longer than acceptable.\n");
		// TODO: truncation
		assert(0);
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
