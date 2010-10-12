#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "udp-handler.h"

/** Event descriptor.
  */
typedef struct sm_event {
    struct sm_manager* manager;
    int fd;
    void* inbuf;
    void* outbuf;
    size_t size_in;
    size_t size_out;
} sm_event;

static inline void udp_handler(sm_event *ev)
{
    struct sockaddr_in faddr;
    int addrsize = sizeof(faddr);

    int n = 0;

    // Loop until all data is read
    while(n >= 0) {

        // Receive data
        n = recvfrom(ev->fd, ev->inbuf, ev->size_in, 0, (struct sockaddr *)&faddr, (socklen_t *)&addrsize);

        // Error and interrupt handling
        //fprintf(stderr, "recvfrom(): thread %p ret %d errno %s.\n", (void*)pthread_self(), n, strerror(errno));
        if(n <= 0 || !ev->manager->is_running) {
           if(errno != EINTR && errno != 0) {
              log_error("udp: reading data from the socket failed: %d - %s\n", errno, strerror(errno));
           }

           return;
        }

        debug_sm("udp: received %d bytes.\n", n);
        size_t answer_size = ev->size_out;
        int res = ns_answer_request(ev->manager->nameserver, ev->inbuf, n, ev->outbuf,
                          &answer_size);

        debug_sm("udp: got answer of size %u.\n", (unsigned) answer_size);

        if (res == 0) {
            assert(answer_size > 0);

            debug_sm("udp: answer wire format (size %u):\n", answer_size);
            debug_sm_hex(answer, answer_size);

            for(;;) {
                res = sendto(ev->fd, ev->outbuf, answer_size, MSG_DONTWAIT,
                             (struct sockaddr *) &faddr,
                             (socklen_t) addrsize);

                //fprintf(stderr, "sendto() in %p: written %d bytes to %d.\n", (void*)pthread_self(), res, ev->fd);
                if(res != answer_size) {
                    log_error("udp: failed to send datagram (errno %d): %s.\n", res, strerror(res));
                    continue;
                }

                break;
            }
        }
    }
}

void *udp_master( void *obj )
{
    UNUSED(obj);
    return NULL;
}

void *udp_worker( void *obj )
{
    sm_worker* worker = (sm_worker *)obj;
    char buf[SOCKET_BUFF_SIZE];
    char answer[SOCKET_BUFF_SIZE];

    sm_event event;
    event.manager = worker->mgr;
    event.fd = worker->mgr->sockets[0].socket;
    event.inbuf = buf;
    event.outbuf = answer;
    event.size_in = event.size_out = SOCKET_BUFF_SIZE;

    while(worker->mgr->is_running) {

        // Handle UDP socket
        udp_handler(&event);
    }

    debug_sm("udp: worker #%d finished.\n", worker->epfd);
    return NULL;
}
