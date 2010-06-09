#include "name-server.h"
#include "zone-node.h"
#include "dns-simple.h"
#include "zone-database.h"
#include <stdio.h>
#include <assert.h>

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

int ns_answer_request( ns_nameserver *nameserver, const char *query_wire,
                       uint qsize, char *response_wire, uint *rsize )
{
    debug_ns("ns_answer_request() called with query size %d.\n", qsize);
    debug_ns_hex(query_wire, qsize);

    dnss_packet *query = dnss_parse_query(query_wire, qsize);
    if (query == NULL || query->header.qdcount <= 0) {
        return -1;
    }

    debug_ns("Query parsed, ID: %u, QNAME: %s\n", query->header.id,
           query->questions[0].qname);
    debug_ns_hex(query->questions[0].qname, strlen(query->questions[0].qname));

//    const ck_hash_table_item *item = ck_find_item(
//            table, query->questions[0].qname,
//            strlen(query->questions[0].qname));
    const zn_node *node =
            zdb_find_name(nameserver->zone_db, query->questions[0].qname);

    dnss_packet *response = dnss_create_empty_packet();
    if (response == NULL) {
        dnss_destroy_packet(&query);
        return -1;
    }

    if (node == NULL) {
        debug_ns("Requested name not found, creating empty response.\n");
        if (dnss_create_response(query, NULL, 0, &response) != 0) {
            dnss_destroy_packet(&query);
            dnss_destroy_packet(&response);
            return -1;
        }
    } else {
        debug_ns("Requested name found.\n");
        if (dnss_create_response(query,
                                 zn_find_rr(node, query->questions[0].qtype),
                                 1, &response) != 0) {
            dnss_destroy_packet(&query);
            dnss_destroy_packet(&response);
            return -1;
        }
    }

    debug_ns("Response ID: %u\n", response->header.id);

    if (dnss_wire_format(response, response_wire, rsize) != 0) {
        debug_ns("Response too long, returning SERVFAIL response.\n");
        if (dnss_create_error_response(query, &response) != 0) {
            dnss_destroy_packet(&query);
            dnss_destroy_packet(&response);
            return -1;
        }
        int res = dnss_wire_format(response, response_wire, rsize);
        assert(res != 0);
    }

    debug_ns("Returning response of size: %u.\n", *rsize);

    dnss_destroy_packet(&query);
    dnss_destroy_packet(&response);

    return 0;
}

/*----------------------------------------------------------------------------*/

void ns_destroy( ns_nameserver **nameserver )
{
    // do nothing with the zone database!
    free(*nameserver);
    *nameserver = NULL;
}
