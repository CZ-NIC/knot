#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "udp-handler.h"

void* udp_worker( void* obj )
{
    worker_t* worker = (worker_t*) obj;

    // Check socket
    if(worker->socket == NULL) {
       debug_net("udp_worker: null socket recevied, finishing.\n");
       return NULL;
    }

    int sock = worker->socket->socket;
    ns_nameserver* ns = worker->server->nameserver;
    uint8_t inbuf[SOCKET_BUFF_SIZE];
    uint8_t outbuf[SOCKET_BUFF_SIZE];
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);

    // Loop until all data is read
    debug_net("udp_worker: thread started (worker #%d).\n", worker->id);
    int n = 0;
    while(n >= 0) {

        // Receive data
        n = recvfrom(sock, inbuf, SOCKET_BUFF_SIZE, 0, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);

        // Error and interrupt handling
        //fprintf(stderr, "recvfrom(): thread %p ret %d errno %s.\n", (void*)pthread_self(), n, strerror(errno));
        if(n <= 0) {
           if(errno != EINTR && errno != 0) {
              log_error("udp_worker: reading data from the socket failed: %d - %s\n", errno, strerror(errno));
           }

           if(!(worker->state & Running))
              break;
           else
              continue;
        }

        debug_net("udp_worker: received %d bytes.\n", n);
        size_t answer_size = SOCKET_BUFF_SIZE;
        int res = ns_answer_request(ns, inbuf, n, outbuf,
                          &answer_size);

        debug_net("udp_worker: got answer of size %u.\n", (unsigned) answer_size);

        if (res == 0) {
            assert(answer_size > 0);

            debug_net("udp_worker: answer wire format (size %u):\n", (unsigned) answer_size);
            debug_net_hex((const char*) outbuf, answer_size);

            for(;;) {
                res = sendto(sock, outbuf, answer_size, 0,
                             (struct sockaddr *) &faddr,
                             (socklen_t) addrsize);

                //fprintf(stderr, "sendto() in %p: written %d bytes to %d.\n", (void*)pthread_self(), res, ev->fd);
                if(res != answer_size) {
                    log_error("udp_worker: failed to send datagram (errno %d): %s.\n", res, strerror(res));
                    continue;
                }

                break;
            }
        }
    }

    debug_net("udp_worker: worker #%d finished.\n", worker->id);
    return NULL;
}
