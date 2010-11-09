#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "udp-handler.h"
#include "name-server.h"

int udp_master (dthread_t *thread)
{
    iohandler_t* handler = (iohandler_t *)thread->data;
    ns_nameserver* ns = handler->server->nameserver;
    int sock = handler->fd;

    // Check socket
    if (sock < 0) {
       debug_net("udp_worker: null socket recevied, finishing.\n");
       return 0;
    }

    /*
     * \todo: Make sure stack size is big enough.
     *        Although this is much cheaper,
     *        16kB worth of buffers *may* pose a problem.
     */
    uint8_t inbuf[SOCKET_MTU_SZ];
    uint8_t outbuf[SOCKET_MTU_SZ];
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);

    // Loop until all data is read
    debug_net("udp: thread started (worker %p).\n", thread);
    int n = 0;
    while (n >= 0) {

        // Receive data
        n = socket_recvfrom(sock, inbuf, SOCKET_MTU_SZ, 0,
                            (struct sockaddr *)&faddr, (socklen_t *)&addrsize);

        // Cancellation point
        if (dt_is_cancelled(thread)) {
            break;
        }

        // Error and interrupt handling
        if (n <= 0) {
            if (errno != EINTR && errno != 0) {
                log_error("udp: socket_recfrom() failed: %d - %s\n",
                          errno, strerror(errno));
            }

            if (!(handler->state & Running)) {
                debug_net("udp: bailing out, iohandler is not running");
                break;
            } else {
                continue;
            }
        }

        // Answer request
        debug_net("udp: received %d bytes.\n", n);
        size_t answer_size = SOCKET_MTU_SZ;
        int res = ns_answer_request(ns, inbuf, n, outbuf,
                                    &answer_size);

        debug_net("udp: got answer of size %u.\n", (unsigned) answer_size);

        // Send answer
        if (res == 0) {

            assert(answer_size > 0);
            debug_net("udp: answer wire format (size %u):\n",
                      (unsigned) answer_size);

            debug_net_hex((const char*) outbuf, answer_size);

            // Send datagram
            for (;;) {
                res = socket_sendto(sock, outbuf, answer_size, 0,
                                    (struct sockaddr *) &faddr,
                                    (socklen_t) addrsize);

                // Check result
                if (res != answer_size) {
                    log_error("udp: socket_sendto() failed: %d - %s.\n",
                              res, strerror(res));
                    continue;
                }

                break;
            }
        }
    }

    debug_net("udp: worker %p finished.\n", thread);
    return 0;
}
