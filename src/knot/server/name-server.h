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
#include "dnslib/response.h"
#include "dnslib/consts.h"

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
} ns_nameserver_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Allocates and initializes the name server structure.
 *
 * \return Pointer to the name server structure.
 */
ns_nameserver_t *ns_create();

/*!
 * \brief Parses the given query into the response structure and recognizes
 *        type of the query.
 *
 * Some query types are distinguished by OPCODE (NOTIFY, UPDATE, etc.), some
 * by QTYPE (AXFR, IXFR). As these information are needed on the same layer
 * to decide what to do with the query, the dnslib_query_t type is used for this
 * purpose.
 *
 * \param query_wire Wire format of the query.
 * \param qsize Size of the query in octets.
 * \param parsed Response structure to be filled with the parsed query.
 * \param type Type of the query.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EMALF if the query is totally unusable. Such query must be
 *                    ignored.
 * \retval DNSLIB_RCODE_SERVFAIL if there was some internal error. Call
 *                               ns_error_response() with \a rcode set to this
 *                               value to get proper error response.
 * \retval DNSLIB_RCODE_FORMERR if the query was malformed, but can be used to
 *                              construct an error response. Call
 *                              ns_error_response() with \a rcode set to this
 *                              value to get proper error response.
 * \retval DNSLIB_RCODE_NOTIMPL if the query has an unsupported type. Call
 *                              ns_error_response() with \a rcode set to this
 *                              value to get proper error response.
 */
int ns_parse_packet(const uint8_t *query_wire, size_t qsize,
                    dnslib_response_t *parsed, dnslib_packet_type_t *type);

/*!
 * \brief Prepares wire format of an error response using generic error template
 *        stored in the nameserver structure.
 *
 * The error response will not contain the Question section from the query, just
 * a header with ID copied from the query and the given RCODE.
 *
 * \param nameserver Nameserver structure containing the error template.
 * \param query_id ID of the query.
 * \param rcode RCODE to set in the response.
 * \param response_wire Place for wire format of the response.
 * \param rsize Size of the error response will be stored here.
 */
void ns_error_response(ns_nameserver_t *nameserver, uint16_t query_id,
                       uint8_t rcode, uint8_t *response_wire, size_t *rsize);

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
 * \retval KNOT_EOK if a valid response was created.
 * \retval KNOT_EMALF if an error occured and the response is not valid.
 *
 * \todo Truncation of the packet.
 */
int ns_answer_request(ns_nameserver_t *nameserver,
                      const uint8_t *query_wire,
                      size_t qsize,
                      uint8_t *response_wire,
                      size_t *rsize);

/*! \brief Callback for sending one packet back through a TCP connection. */
typedef int (*axfr_callback_t)(int session, uint8_t *packet, size_t size);

typedef struct ns_xfr {
	dnslib_response_t *response;
	axfr_callback_t send;
	int session;
	uint8_t *response_wire;
	size_t rsize;
} ns_xfr_t;

/*!
 * \brief Creates a response for the given normal query using the data of the
 *        nameserver.
 *
 * \param nameserver Name server structure to provide the needed data.
 * \param resp Response structure with parsed query.
 * \param response_wire Place for the response in wire format.
 * \param rsize Input: maximum acceptable size of the response. Output: real
 *              size of the response.
 *
 * \retval KNOT_EOK if a valid response was created.
 * \retval KNOT_EMALF if an error occured and the response is not valid.
 */
int ns_answer_normal(ns_nameserver_t *nameserver, dnslib_response_t *resp,
                     uint8_t *response_wire, size_t *rsize);

/*!
 * \brief Processes an AXFR query.
 *
 * This function sequentially creates DNS packets to be sent as a response
 * to the AXFR query and sends each packet using the given callback (\a
 * send_packet).
 *
 * \param namserver Name server structure to provide the data for answering.
 * \param xfr
 *
 * \note Currently only a stub which sends one error response using the given
 *       callback.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 * \retval KNOT_ERROR
 *
 * \todo Implement.
 * \todo Maybe the place for the wire format should be passed in as in
 *       the ns_answer_request() function...?
 */
int ns_answer_axfr(ns_nameserver_t *nameserver, ns_xfr_t *xfr);

/*!
 * \brief Properly destroys the name server structure.
 *
 * \param nameserver Nameserver to destroy.
 */
void ns_destroy(ns_nameserver_t **nameserver);

/*!
 * \brief Name server config hook.
 *
 * Routine for dynamic name server reconfiguration.
 *
 * \param conf Current configuration.
 * \param data Instance of the nameserver structure to update.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL
 * \retval KNOT_ERROR
 */
int ns_conf_hook(const struct conf_t *conf, void *data);


#endif /* _KNOT_NAME_SERVER_H_ */

/*! @} */
