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

#ifndef _KNOTDNAME_SERVER_H_
#define _KNOTDNAME_SERVER_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/zonedb.h"
#include "dnslib/edns.h"
//#include "dnslib/response.h"
#include "dnslib/consts.h"
#include "dnslib/packet.h"
#include "common/sockaddr.h"

struct conf_t;
struct server_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Name server structure. Holds all important data needed for the
 *        supported DNS functions.
 *
 * Currently only holds pointer to the zone database for answering queries.
 */
typedef struct knot_nameserver {
	/*!
	 * \brief Pointer to the zone database structure used for answering
	 *        queries.
	 */
	knot_zonedb_t *zone_db;
	uint8_t *err_response;    /*!< Prepared generic error response. */
	size_t err_resp_size;     /*!< Size of the prepared error response. */
	knot_opt_rr_t *opt_rr;  /*!< OPT RR with the server's EDNS0 info. */
	
	/*! \todo REMOVE */
	struct server_t *server;  /*!< Pointer to server. */
} knot_nameserver_t;

/*! \brief Callback for sending one packet back through a TCP connection. */
typedef int (*xfr_callback_t)(int session, sockaddr_t *addr,
			      uint8_t *packet, size_t size);

/*! \todo Document me. */
typedef struct knot_ns_xfr {
	int type;
	sockaddr_t addr;
	knot_packet_t *query;
	knot_packet_t *response;
	xfr_callback_t send;
	int session;
	uint8_t *wire;
	size_t wire_size;
	void *data;
	knot_zone_t *zone;
} knot_ns_xfr_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Allocates and initializes the name server structure.
 *
 * \return Pointer to the name server structure.
 */
knot_nameserver_t *knot_ns_create();

/*!
 * \brief Parses the given query into the response structure and recognizes
 *        type of the query.
 *
 * Some query types are distinguished by OPCODE (NOTIFY, UPDATE, etc.), some
 * by QTYPE (AXFR, IXFR). As these information are needed on the same layer
 * to decide what to do with the query, the knot_query_t type is used for this
 * purpose.
 *
 * \param query_wire Wire format of the query.
 * \param qsize Size of the query in octets.
 * \param packet Packet structure to be filled with the parsed query.
 * \param type Type of the query.
 *
 * \retval KNOTDEOK
 * \retval KNOTDEMALF if the query is totally unusable. Such query must be
 *                    ignored.
 * \retval KNOT_RCODE_SERVFAIL if there was some internal error. Call
 *                               ns_error_response() with \a rcode set to this
 *                               value to get proper error response.
 * \retval KNOT_RCODE_FORMERR if the query was malformed, but can be used to
 *                              construct an error response. Call
 *                              ns_error_response() with \a rcode set to this
 *                              value to get proper error response.
 * \retval KNOT_RCODE_NOTIMPL if the query has an unsupported type. Call
 *                              ns_error_response() with \a rcode set to this
 *                              value to get proper error response.
 */
int knot_ns_parse_packet(const uint8_t *query_wire, size_t qsize,
                    knot_packet_t *packet, knot_packet_type_t *type);

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
void knot_ns_error_response(knot_nameserver_t *nameserver, uint16_t query_id,
                       uint8_t rcode, uint8_t *response_wire, size_t *rsize);

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
 * \retval KNOTDEOK if a valid response was created.
 * \retval KNOTDEMALF if an error occured and the response is not valid.
 */
int knot_ns_answer_normal(knot_nameserver_t *nameserver, knot_packet_t *query,
                     uint8_t *response_wire, size_t *rsize);

int knot_ns_init_xfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr);

int knot_ns_xfr_send_error(knot_ns_xfr_t *xfr, knot_rcode_t rcode);

/*!
 * \brief Processes an AXFR query.
 *
 * This function sequentially creates DNS packets to be sent as a response
 * to the AXFR query and sends each packet using the given callback (\a
 * send_packet).
 *
 * \param nameserver Name server structure to provide the data for answering.
 * \param xfr Persistent transfer-specific data.
 *
 * \note Currently only a stub which sends one error response using the given
 *       callback.
 *
 * \retval KNOTDEOK
 * \retval KNOTDEINVAL
 * \retval KNOTDENOMEM
 * \retval KNOTDERROR
 *
 * \todo Maybe the place for the wire format should be passed in as in
 *       the ns_answer_request() function...?
 */
int knot_ns_answer_axfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr);

/*!
 * \brief Processes an IXFR query.
 *
 * \param nameserver Name server structure to provide the data for answering.
 * \param xfr Persistent transfer-specific data.
 *
 * \todo Document properly.
 */
int knot_ns_answer_ixfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr);

/*!
 * \brief Processes an AXFR-IN packet.
 *
 * \param nameserver Name server structure to provide the data for answering.
 * \param xfr Persistent transfer-specific data.
 *
 * \todo Document me.
 */
int knot_ns_process_axfrin(knot_nameserver_t *nameserver, 
                             knot_ns_xfr_t *xfr);

int knot_ns_switch_zone(knot_nameserver_t *nameserver, 
                          knot_ns_xfr_t *xfr);

/*!
 * \brief Processes an IXFR-IN packet.
 *
 * \param nameserver Name server structure to provide the data for answering.
 * \param xfr Persistent transfer-specific data.
 *
 * \todo Document me.
 */
int knot_ns_process_ixfrin(knot_nameserver_t *nameserver, 
                             knot_ns_xfr_t *xfr);

/*!
 * \brief Properly destroys the name server structure.
 *
 * \param nameserver Nameserver to destroy.
 */
void knot_ns_destroy(knot_nameserver_t **nameserver);


#endif /* _KNOTDNAME_SERVER_H_ */

/*! @} */
