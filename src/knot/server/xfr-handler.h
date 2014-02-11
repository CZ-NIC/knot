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
/*!
 * \file xfr-handler.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief XFR requests handler.
 *
 * \addtogroup server
 * @{
 */

#ifndef _KNOTD_XFRHANDLER_H_
#define _KNOTD_XFRHANDLER_H_

#include "common/fdset.h"
#include "common/evsched.h"
#include "knot/server/dthreads.h"
#include "knot/server/socket.h"
#include "libknot/packet/pkt.h"
#include "knot/zone/zone.h"

struct server_t;
struct xfrhandler_t;

/*! \brief Transfer state. */
enum xfrstate_t {
	XFR_IDLE = 0,
	XFR_SCHED,
	XFR_PENDING
};

/*!
 * \brief XFR request flags.
 */
enum knot_ns_xfr_flag_t {
	XFR_FLAG_TCP = 1 << 0, /*!< XFR request is on TCP. */
	XFR_FLAG_UDP = 1 << 1,  /*!< XFR request is on UDP. */
	XFR_FLAG_AXFR_FINISHED = 1 << 2, /*!< Transfer is finished. */
	XFR_FLAG_CONNECTING = 1 << 3 /*!< In connecting phase. */
};

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

/*!
 * \brief XFR handler structure.
 */
typedef struct xfrhandler_t
{
	list_t queue;
	unsigned pending; /*!< \brief Pending transfers. */
	pthread_mutex_t pending_mx;
	pthread_mutex_t mx; /*!< \brief Tasks synchronisation. */
	struct server_t *server;
	dt_unit_t       *unit;  /*!< \brief Threading unit. */
} xfrhandler_t;

/*! \brief Callback for sending one packet back through a TCP connection. */
typedef int (*xfr_callback_t)(int session, struct sockaddr *addr,
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
	struct sockaddr_storage addr, saddr;
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
	zone_t *zone;
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
	struct sockaddr_storage fwd_addr;

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

/*!
 * \brief Create XFR threading unit.
 *
 * Unit can be controlled by standard DThreads API.
 * Unit is created in Idle mode.
 *
 * \param thrcount Requested number of threads.
 * \param server Pointer to nameserver.
 *
 * \retval New handler on success.
 * \retval NULL on error.
 */
xfrhandler_t *xfr_create(size_t thrcount, struct server_t *server);

/*!
 * \brief Delete XFR handler.
 *
 * \warning Threading unit must be stopped and joined.
 *
 * \param xfr XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on NULL handler.
 * \retval KNOT_ERROR on error.
 */
int xfr_free(xfrhandler_t *xfr);

/*!
 * \brief Start XFR handler.
 *
 * \param xfr XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
static inline int xfr_start(xfrhandler_t *xfr) {
	return dt_start(xfr->unit);
}

/*!
 * \brief Stop XFR handler.
 *
 * \param xfr XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
int xfr_stop(xfrhandler_t *xfr);

/*!
 * \brief Wait for XFR handler to finish.
 *
 * \param xfr XFR handler.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
int xfr_join(xfrhandler_t *xfr);

/*!
 * \brief Enqueue XFR request.
 *
 * \param xfr XFR handler instance.
 * \param req XFR request.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on NULL handler or request.
 * \retval KNOT_ERROR on error.
 */
int xfr_enqueue(xfrhandler_t *xfr, knot_ns_xfr_t *rq);

/*!
 * \brief Prepare XFR request.
 *
 * \param z Related zone.
 * \param type Request type.
 * \param flags Request flags.
 *
 * \return new request
 */
knot_ns_xfr_t *xfr_task_create(zone_t *z, int type, int flags);

/*!
 * \brief Free XFR request.
 * \param rq Request.
 * \return KNOT_EOK or KNOT_EINVAL
 */
int xfr_task_free(knot_ns_xfr_t *rq);

/*!
 * \brief Set XFR request destination/source address.
 *
 * \param rq XFR request,
 * \param to Destination address.
 * \param from Source address.
 * \return
 */
int xfr_task_setaddr(knot_ns_xfr_t *rq,
                     const struct sockaddr_storage *to,
                     const struct sockaddr_storage *from);

/*!
 * \brief Return formatted string of the remote as 'ip\@port key $key'.
 *
 * \param addr Remote address.
 * \param keytag Used TSIG key name (or NULL).
 *
 * \return formatted string or NULL.
 */
char *xfr_remote_str(const struct sockaddr_storage *addr, const char *keytag);

#endif // _KNOTD_XFRHANDLER_H_

/*! @} */
