/*!
 * \file udp-handler.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief UDP sockets threading model.
 *
 * The master socket locks one worker thread at a time
 * and saves events in it's own backing store for asynchronous processing.
 * The worker threads work asynchronously in thread pool.
 *
 * \addtogroup server
 * @{
 */

#ifndef _KNOTD_UDPHANDLER_H_
#define _KNOTD_UDPHANDLER_H_

#include "knot/server/socket.h"
#include "knot/server/server.h"
#include "knot/server/dthreads.h"

/*!
 * \brief Handle single packet.
 *
 * Function processses packet and prepares answer to qbuf,
 * response length is set to resp_len.
 *
 * \param sock
 * \param qbuf
 * \param qbuflen
 * \param resp_len
 * \param addr
 * \param ns
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_ERROR
 * \retval KNOTD_ENOMEM
 */
int udp_handle(int sock, uint8_t *qbuf, size_t qbuflen, size_t *resp_len,
	       sockaddr_t* addr, knot_nameserver_t *ns);

/*!
 * \brief UDP handler thread runnable.
 *
 * Listen to DNS datagrams in a loop on a UDP socket and
 * reply to them. This runnable is designed to be used as coherent
 * and implements cancellation point.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL invalid parameters.
 */
int udp_master(dthread_t *thread);

#endif

/*! @} */
