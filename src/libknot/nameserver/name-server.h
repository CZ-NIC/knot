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
#include <sys/time.h>

#include "knot/zone/zonedb.h"
#include "libknot/edns.h"
#include "libknot/consts.h"
#include "libknot/tsig.h"
#include "libknot/packet/pkt.h"
#include "common/sockaddr.h"
#include "common/lists.h"
#include "libknot/updates/changesets.h"

struct conf_t;
struct server_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Name server structure. Holds all important data needed for the
 *        supported DNS functions.
 *
 * Currently only holds pointer to the zone database for answering queries.
 * \todo Merge this with server_t
 */
typedef struct knot_nameserver {
	/*!
	 * \brief Pointer to the zone database structure used for answering
	 *        queries.
	 */
	knot_zonedb_t *zone_db;
	knot_pkt_t *err_response;    /*!< Prepared generic error response. */
	knot_opt_rr_t *opt_rr;  /*!< OPT RR with the server's EDNS0 info. */

	const char *identity; //!< RFC 4892, server identity (id.server, hostname.bind).
	const char *version;  //!< RFC 4892, server version (version.{server, bind}).

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
	node_t n;
	int type;
	int flags;
	sockaddr_t addr, saddr;
	knot_pkt_t *query;
	knot_pkt_t *response;
	knot_rcode_t rcode;
	xfr_callback_t send;
	xfr_callback_t recv;
	int session;
	struct timeval t_start, t_end;

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
	size_t wire_maxlen;
	void *data;
	knot_zone_t *zone;
	char* zname;
	knot_zone_contents_t *new_contents;
	char *msg;

	/*! \note [TSIG] TSIG fields */
	/*! \brief Message(s) to sign in wireformat.
	 *
	 *  This field should be allocated at the start of transfer and
	 *  freed at the end. During the transfer it is only rewritten.
	 */
	uint8_t *tsig_data;
	size_t tsig_data_size;	/*!< Size of the message(s) in bytes */
	size_t tsig_size;	/*!< Size of the TSIG RR wireformat in bytes.*/
	knot_tsig_key_t *tsig_key; /*!< Associated TSIG key for signing. */

	uint8_t *digest;     /*!< Buffer for counting digest. */
	size_t digest_size;  /*!< Size of the digest. */
	size_t digest_max_size; /*!< Size of the buffer. */

	/*! \note [DDNS] Update forwarding fields. */
	int fwd_src_fd;           /*!< Query originator fd. */
	sockaddr_t fwd_addr;

	uint16_t tsig_rcode;
	uint64_t tsig_prev_time_signed;

	/*!
	 * \brief Number of the packet currently assembled.
	 *
	 * In case of XFR-in, this is not the overall number of packet, just
	 * number counted from last TSIG check.
	 */
	int packet_nr;

	hattrie_t *lookup_tree;
} knot_ns_xfr_t;

static const int KNOT_NS_TSIG_FREQ = 100;

static const size_t KNOT_NS_TSIG_DATA_MAX_SIZE = 100 * 64 * 1024;

/*!
 * \brief XFR request flags.
 */
enum knot_ns_xfr_flag_t {
	XFR_FLAG_TCP = 1 << 0, /*!< XFR request is on TCP. */
	XFR_FLAG_UDP = 1 << 1,  /*!< XFR request is on UDP. */
	XFR_FLAG_AXFR_FINISHED = 1 << 2, /*!< Transfer is finished. */
	XFR_FLAG_CONNECTING = 1 << 3 /*!< In connecting phase. */
};

typedef enum knot_ns_transport {
	NS_TRANSPORT_UDP = 1 << 0,
	NS_TRANSPORT_TCP = 1 << 1
} knot_ns_transport_t;

/*!
 * \brief XFR request types.
 */
typedef enum knot_ns_xfr_type_t {
	/* DNS events. */
	XFR_TYPE_AIN = 0, /*!< AXFR-IN request (start transfer). */
	XFR_TYPE_IIN,     /*!< IXFR-IN request (start transfer). */
	XFR_TYPE_AOUT,    /*!< AXFR-OUT request (incoming transfer). */
	XFR_TYPE_IOUT,    /*!< IXFR-OUT request (incoming transfer). */
	XFR_TYPE_SOA,     /*!< Pending SOA request. */
	XFR_TYPE_NOTIFY,  /*!< Pending NOTIFY query. */
	XFR_TYPE_UPDATE,  /*!< UPDATE request (incoming UPDATE). */
	XFR_TYPE_FORWARD,  /*!< UPDATE forward request. */
	XFR_TYPE_DNSSEC   /*!< DNSSEC changes. */
} knot_ns_xfr_type_t;

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
int knot_ns_parse_packet(knot_pkt_t *packet, knot_pkt_type_t *type);

/*!
 * \brief Compares two zone serials.
 *
 * \retval < 0 if s1 is less than s2.
 * \retval > 0 if s1 is larger than s2.
 * \retval == 0 if s1 is equal to s2.
 */
int ns_serial_compare(uint32_t s1, uint32_t s2);

/*!
 * \brief Processes an AXFR-IN packet.
 *
 * \param nameserver Name server structure to provide the data for answering.
 * \param xfr Persistent transfer-specific data.
 *
 */
int knot_ns_process_axfrin(knot_nameserver_t *nameserver,
                             knot_ns_xfr_t *xfr);

/*! \todo Document me. */
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

int knot_ns_process_update(const knot_pkt_t *query,
                           knot_zone_contents_t *old_contents,
                           knot_zone_contents_t **new_contents,
                           knot_changesets_t *chgs, knot_rcode_t *rcode,
                           uint32_t new_serial);

int knot_ns_create_forward_query(const knot_pkt_t *query,
                                 uint8_t *query_wire, size_t *size);

int knot_ns_process_forward_response(const knot_pkt_t *response,
                                     uint16_t original_id,
                                     uint8_t *response_wire, size_t *size);

void *knot_ns_data(knot_nameserver_t *nameserver);

void *knot_ns_get_data(knot_nameserver_t *nameserver);

void knot_ns_set_data(knot_nameserver_t *nameserver, void *data);

int knot_ns_tsig_required(int packet_nr);

/*!
 * \brief Properly destroys the name server structure.
 *
 * \param nameserver Nameserver to destroy.
 */
void knot_ns_destroy(knot_nameserver_t **nameserver);

/* ^^^
 * NG processing API below, everything upwards should be slowly moved to appropriate
 * files or removed.
 */

/*! \brief Main packet processing states.
 *         Each state describes the current machine processing step
 *         and determines readiness for next action.
 */
enum ns_proc_state {
	NS_PROC_NOOP = 0,      /* N/A */
	NS_PROC_MORE = 1 << 0, /* More input data. */
	NS_PROC_FULL = 1 << 1, /* Has output data. */
	NS_PROC_DONE = 1 << 2, /* Finished. */
	NS_PROC_FAIL = 1 << 3  /* Error. */
};

/* Forward declarations. */
struct ns_proc_module;

/*! \brief Packte processing context. */
typedef struct ns_proc_context
{
	int state;
	mm_ctx_t mm;
	uint16_t type;

	knot_nameserver_t *ns;
	void *data;

	/* Module implementation. */
	const struct ns_proc_module *module;
} ns_proc_context_t;

/*! \brief Packet processing module API. */
typedef struct ns_proc_module {
	int (*begin)(ns_proc_context_t *ctx, void *module_param);
	int (*reset)(ns_proc_context_t *ctx);
	int (*finish)(ns_proc_context_t *ctx);
	int (*in)(knot_pkt_t *pkt, ns_proc_context_t *ctx);
	int (*out)(knot_pkt_t *pkt, ns_proc_context_t *ctx);
	int (*err)(knot_pkt_t *pkt, ns_proc_context_t *ctx);
} ns_proc_module_t;

/*! \brief Packet signing context.
 *  \todo This should be later moved to TSIG files when refactoring. */
typedef struct ns_sign_context {
	knot_tsig_key_t *tsig_key;
	uint8_t *tsig_buf;
	uint8_t *tsig_digest;
	size_t tsig_buflen;
	size_t tsig_digestlen;
	uint8_t tsig_runlen;
	uint64_t tsig_time_signed;
	size_t pkt_count;
} ns_sign_context_t;

/*!
 * \brief Initialize packet processing context.
 *
 * Allowed from states: NOOP
 *
 * \param ctx Context.
 * \param module_param Parameters for given module.
 * \param module Module API.
 * \return (module specific state)
 */
int ns_proc_begin(ns_proc_context_t *ctx, void *module_param, const ns_proc_module_t *module);

/*!
 * \brief Reset current packet processing context.
 * \param ctx Context.
 * \return (module specific state)
 */
int ns_proc_reset(ns_proc_context_t *ctx);

/*!
 * \brief Finish and close packet processing context.
 *
 * Allowed from states: MORE, FULL, DONE, FAIL
 *
 * \param ctx Context.
 * \return (module specific state)
 */
int ns_proc_finish(ns_proc_context_t *ctx);

/*!
 * \brief Input more data into packet processing.
 *
 * Allowed from states: MORE
 *
 * \param wire Source data.
 * \param wire_len Source data length.
 * \param ctx Context.
 * \return (module specific state)
 */
int ns_proc_in(const uint8_t *wire, uint16_t wire_len, ns_proc_context_t *ctx);

/*!
 * \brief Write out output from packet processing.
 *
 * Allowed from states: FULL, FAIL
 *
 * \param wire Destination.
 * \param wire_len Destination length.
 * \param ctx Context.
 * \return (module specific state)
 */
int ns_proc_out(uint8_t *wire, uint16_t *wire_len, ns_proc_context_t *ctx);

#endif /* _KNOTNAME_SERVER_H_ */

/*! @} */
