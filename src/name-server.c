#include "name-server.h"
#include "zone-node.h"
#include "dns-simple.h"
#include <stdio.h>
#include <assert.h>

#define NS_DEBUG

/*----------------------------------------------------------------------------*/

int ns_answer_request( ns_nameserver *nameserver, const char *query_wire,
                       uint qsize, char *response_wire, uint *rsize )
{
#ifdef NS_DEBUG
    printf("ns_answer_request() called with query size %d.\n", qsize);
    hex_print(query_wire, qsize);
#endif

    dnss_packet *query = dnss_parse_query(query_wire, qsize);
    if (query == NULL) {
        return -1;
    }

#ifdef NS_DEBUG
    printf("Query parsed, ID: %u, QNAME: %s\n", query->header.id,
           query->questions[0].qname);
    hex_print(query->questions[0].qname, strlen(query->questions[0].qname));
#endif


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
#ifdef NS_DEBUG
        printf("Requested name not found, returning empty response.\n");
#endif
        if (dnss_create_response(query, NULL, 0, &response) != 0) {
            dnss_destroy_packet(&query);
            dnss_destroy_packet(&response);
            return -1;
        }
        return 0;
    } else {
#ifdef NS_DEBUG
        printf("Requested name found.\n");
#endif
        if (dnss_create_response(query,
                                 zn_find_rr(node, query->questions[0].qtype),
                                 1, &response) != 0) {
            dnss_destroy_packet(&query);
            dnss_destroy_packet(&response);
            return -1;
        }
    }

#ifdef NS_DEBUG
    printf("Response ID: %u\n", response->header.id);
#endif

    if (dnss_wire_format(response, response_wire, rsize) != 0) {
#ifdef NS_DEBUG
        fprintf(stderr, "Response too long, returning SERVFAIL response.\n");
#endif
        if (dnss_create_error_response(query, &response) != 0) {
            dnss_destroy_packet(&query);
            dnss_destroy_packet(&response);
            return -1;
        }
        int res = dnss_wire_format(response, response_wire, rsize);
        assert(res != 0);
    }

#ifdef NS_DEBUG
    printf("Returning response of size: %u.\n", *rsize);
#endif

    dnss_destroy_packet(&query);
    dnss_destroy_packet(&response);

    return 0;
}

/*----------------------------------------------------------------------------*/
