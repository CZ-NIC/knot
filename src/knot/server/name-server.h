/*!
 * \file name-server.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * Contains the "name server" structure and interface for the main DNS
 * functions. Currently only supports answering simple queries, without any
 * extensions.
 *
 * \todo Consider saving pointer to the zdb_find_name() function in the
 *       nameserver structure. Probably not needed, these modules can be
 *       inter-connected.
 * \todo Provide interface for other DNS functions - zone transfers, dynamic
 *       updates, etc.
 *
 * \addtogroup query_processing
 * @{
 */

#ifndef _KNOT_NAME_SERVER_H_
#define _KNOT_NAME_SERVER_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/zonedb.h"
#include "dnslib/edns.h"

struct conf_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Name server structure. Holds all important data needed for the
 *        supported DNS functions.
 *
 * Currently only holds pointer to the zone database for answering queries.
 */
typedef struct ns_nameserver {
	/*!
	 * \brief Pointer to the zone database structure used for answering
	 *        queries.
	 */
	dnslib_zonedb_t *zone_db;
	uint8_t *err_response; /*!< Prepared generic error response. */
	size_t err_resp_size;  /*!< Size of the prepared error response. */
	dnslib_opt_rr_t *opt_rr;  /*!< OPT RR with the server's EDNS0 info. */
} ns_nameserver;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Allocates and initializes the name server structure for the given
 *        database.
 *
 * \param database Zone database which will be used for the DNS functions.
 *
 * \return Pointer to the name server structure.
 */
ns_nameserver *ns_create(dnslib_zonedb_t *database);

/*!
 * \brief Creates a response for the given query using the data of the name
 *        server.
 *
 * \param nameserver Name server structure to provide the needed data.
 * \param query_wire Query in a wire format.
 * \param qsize Size of the query in octets.
 * \param response_wire Place for the response in wire format.
 * \param rsize Input: maximum acceptable size of the response. Output: real
 *              size of the response.
 *
 * \retval 0 if a valid response was created.
 * \retval -1 if an error occured and the response is not valid.
 *
 * \todo Truncation of the packet.
 */
int ns_answer_request(ns_nameserver *nameserver,
                      const uint8_t *query_wire,
                      size_t qsize,
                      uint8_t *response_wire,
                      size_t *rsize);

/*!
 * \brief Properly destroys the name server structure.
 *
 * \note This functions does not destroy the zone database saved in the
 *       structure. This must be kept and destroyed elsewhere.
 */
void ns_destroy(ns_nameserver **nameserver);

/*!
 * \brief Name server config hook.
 *
 * Routine for dynamic name server reconfiguration.
 */
int ns_conf_hook(const struct conf_t *conf, void *data);


#endif /* _KNOT_NAME_SERVER_H_ */

/*! @} */

