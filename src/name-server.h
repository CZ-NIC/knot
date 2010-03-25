/*!
 * @todo Consider saving pointer to the zdb_find_name() function in the
 *       nameserver structure. Probably not needed, these modules can be
 *       inter-connected.
 */

#ifndef NAME_SERVER
#define NAME_SERVER

#include "common.h"
#include "zone-database.h"

/*----------------------------------------------------------------------------*/

typedef struct ns_nameserver {
    zdb_database *zone_db;
} ns_nameserver;

/*----------------------------------------------------------------------------*/

/*!
 * @param rsize Input: maximum acceptable size of the response. Output: real
 *              size of the response.
 */
int ns_answer_request( ns_nameserver *nameserver, const char *query_wire,
                       uint qsize, char *response_wire, uint *rsize );

#endif
