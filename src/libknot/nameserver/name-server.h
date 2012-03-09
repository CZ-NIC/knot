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
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _KNOT_NAME_SERVER_H_
#define _KNOT_NAME_SERVER_H_

#include <stdint.h>
#include <string.h>

#include "zone/zonedb.h"
#include "edns.h"
#include "consts.h"
#include "tsig.h"
#include "packet/packet.h"
#include "common/sockaddr.h"
#include "updates/changesets.h"

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
	
	void *data;
} knot_nameserver_t;

/*! \brief Callback for sending one packet back through a TCP connection. */
typedef int (*xfr_callback_t)(int session, sockaddr_t *addr,
			      uint8_t *packet, size_t size);

/*!
 * \brief Single XFR operation structure.
 *
 * Used for communication with XFR handler.
 */
typedef struct knot_ns_xfr {
	int type;
	int flags;
	sockaddr_t addr, saddr;
	knot_packet_t *query;
	knot_packet_t *response;
	knot_rcode_t rcode;
	xfr_callback_t send;
	int session;
	
	/*!
	 * XFR-out: Output buffer.
	 * XFR-in: Buffer for query or incoming packet.
	 */
	uint8_t *wire;
	
	/*! 
	 * XFR-out: Size of the output buffer. 
	 * XFR-in: Size of the current packet. 
	 */
	size_t wire_size;
	void *data;
	knot_zone_t *zone;
	char* zname;
	void *owner;
	knot_zone_contents_t *new_contents;
	char *msgpref;
	
	/*! \note [TSIG] TSIG fields */
	/*! \brief Message(s) to sign in wireformat. 
	 *
	 *  This field should be allocated at the start of transfer and 
	 *  freed at the end. During the transfer it is only rewritten.
	 */
	uint8_t *tsig_data;
	size_t tsig_data_size; /*!< Size of the message(s) in bytes */
//	const knot_rrset_t *tsig; /*!< Response TSIG. 
//	                            \todo [TSIG] Replace with separate data. */
	size_t tsig_size;      /*!< Size of the TSIG RR wireformat in bytes.*/
	knot_key_t *tsig_key;  /*!< Associated TSIG key for signing. */
	
	uint8_t *digest;     /*!< Buffer for counting digest. */
	size_t digest_size;  /*!< Size of the digest. */
	size_t digest_max_size; /*!< Size of the buffer. */

	uint16_t tsig_rcode;
	uint64_t tsig_prev_time_signed;
	
	/*! \brief Previous digest or request digest. 
	 *
	 *  Should be allocated before the transfer (known size).
	 */
//	uint8_t *prev_digest;
//	size_t prev_digest_size; /*!< Size of previous digest in bytes. */
	
	/*! 
	 * \brief Number of the packet currently assembled.
	 *
	 * In case of XFR-in, this is not the overall number of packet, just 
	 * number counted from last TSIG check.
	 */
	int packet_nr;
} knot_ns_xfr_t;


static const int KNOT_NS_TSIG_FREQ = 100;

static const size_t KNOT_NS_TSIG_DATA_MAX_SIZE = 100 * 64 * 1024;

/*!
 * \brief XFR request flags.
 */
enum knot_ns_xfr_flag_t {
	XFR_FLAG_TCP = 1 << 0, /*!< XFR request is on TCP. */
	XFR_FLAG_UDP = 1 << 1,  /*!< XFR request is on UDP. */
	XFR_FLAG_AXFR_FINISHED = 1 << 2
};

/*!
 * \brief XFR request types.
 */
typedef enum knot_ns_xfr_type_t {
	/* DNS events. */
	XFR_TYPE_AIN = 1 << 0,   /*!< AXFR-IN request (start transfer). */
	XFR_TYPE_AOUT= 1 << 1,  /*!< AXFR-OUT request (incoming transfer). */
	XFR_TYPE_IIN = 1 << 2,   /*!< IXFR-IN request (start transfer). */
	XFR_TYPE_IOUT = 1 << 3,  /*!< IXFR-OUT request (incoming transfer). */
	XFR_TYPE_SOA = 1 << 4,   /*!< Pending SOA request. */
	XFR_TYPE_NOTIFY = 1 << 5 /*!< Pending NOTIFY query. */
} knot_ns_xfr_type_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Allocates and initializes the name server structure.
 *
 * \return Pointer to the name server structure.
 */
knot_nameserver_t *knot_ns_create();

/*! \todo Document me. */
void knot_ns_set_nsid(knot_nameserver_t *nameserver, const char *nsid,
                      size_t nsid_length);

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
 * \retval KNOT_EOK
 * \retval KNOT_EMALF if the query is totally unusable. Such query must be
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
void knot_ns_error_response(const knot_nameserver_t *nameserver, uint16_t query_id,
                       uint8_t rcode, uint8_t *response_wire, size_t *rsize);

void knot_ns_error_response_full(knot_nameserver_t *nameserver,
                                 knot_packet_t *response, uint8_t rcode,
                                 uint8_t *response_wire, size_t *rsize);

int knot_ns_prep_normal_response(knot_nameserver_t *nameserver,
                                 knot_packet_t *query, knot_packet_t **resp,
                                 const knot_zone_t **zone);

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
int knot_ns_answer_normal(knot_nameserver_t *nameserver, 
                          const knot_zone_t *zone, knot_packet_t *resp,
                          uint8_t *response_wire, size_t *rsize);

int knot_ns_init_xfr(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr);

/*! 
 * \brief Compares two zone serials.
 *
 * \retval < 0 if s1 is less than s2.
 * \retval > 0 if s1 is larger than s2.
 * \retval == 0 if s1 is equal to s2.
 */
int ns_serial_compare(uint32_t s1, uint32_t s2);

int ns_ixfr_load_serials(const knot_ns_xfr_t *xfr, uint32_t *serial_from, 
                         uint32_t *serial_to);

int knot_ns_xfr_send_error(const knot_nameserver_t *nameserver,
                           knot_ns_xfr_t *xfr, knot_rcode_t rcode);

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
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 * \retval KNOT_ERROR
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
 * \retval KNOT_EOK If this packet was processed successfuly and another packet
 *                  is expected. (RFC1995bis, case c)
 * \retval KNOT_ENOXFR If the transfer is not taking place because server's 
 *                     SERIAL is the same as this client's SERIAL. The client
 *                     should close the connection and do no further processing.
 *                     (RFC1995bis case a).
 * \retval KNOT_EAGAIN If the server could not fit the transfer into the packet.
 *                     This should happen only if UDP was used. In this case
 *                     the client should retry the request via TCP. If UDP was
 *                     not used, it should be considered that the transfer was 
 *                     malformed and the connection should be closed.
 *                     (RFC1995bis case b).
 * \retval >0 Transfer successully finished. Changesets are created and furter
 *            processing is needed.
 * \retval Other If any other error occured. The connection should be closed.
 *
 * \todo Document me.
 */
int knot_ns_process_ixfrin(knot_nameserver_t *nameserver, 
                             knot_ns_xfr_t *xfr);

int knot_ns_process_update(knot_nameserver_t *nameserver, knot_packet_t *query,
                           uint8_t *response_wire, size_t *rsize,
                           knot_zone_t **zone, knot_changeset_t **changeset);

int knot_ns_create_forward_query(const knot_packet_t *query,
                                 uint8_t *query_wire, size_t *size);

int knot_ns_process_forward_response(const knot_packet_t *response,
                                     uint16_t original_id,
                                     uint8_t *response_wire, size_t *size);

void *knot_ns_data(knot_nameserver_t *nameserver);

void *knot_ns_get_data(knot_nameserver_t *nameserver);

void knot_ns_set_data(knot_nameserver_t *nameserver, void *data);

int knot_ns_tsig_required(int packet_nr);

/*!
 * \brief Converts the response to wire format.
 *
 * \param resp Response to convert.
 * \param wire Place for the wire format of the response.
 * \param wire_size In: space available for the wire format in bytes.
 *                  Out: actual size of the wire format in bytes.
 *
 * \retval KNOT_EOK
 * \retval NS_ERR_SERVFAIL
 */
int ns_response_to_wire(knot_packet_t *resp, uint8_t *wire,
                        size_t *wire_size);

/*!
 * \brief Properly destroys the name server structure.
 *
 * \param nameserver Nameserver to destroy.
 */
void knot_ns_destroy(knot_nameserver_t **nameserver);


#endif /* _KNOTNAME_SERVER_H_ */

/*! @} */
