/**
  * @note As of now, all sockets managed by socket-manager are UDP sockets.
  *       Further (maybe fundamental) changes will be need when TCP is to
  *       be used as well.
  *
  * @todo We will need one mutex for each socket.
  */

#ifndef SOCKET_MANAGER
#define SOCKET_MANAGER

#include <sys/epoll.h>
#include <pthread.h>
#include "common.h"
#include "name-server.h"

//const uint SOCKET_BUFF_SIZE;

/*----------------------------------------------------------------------------*/

typedef enum {
    UDP = 0x00,
    TCP = 0x01,
} socket_t;

/*----------------------------------------------------------------------------*/

typedef struct sm_socket {
    unsigned short port;
    int socket;
    struct sm_socket *next;
} sm_socket;

/*----------------------------------------------------------------------------*/
struct sm_manager;
typedef void (*iohandler_t) (struct sm_manager*, int, void*, size_t, void*, size_t);

typedef struct sm_manager {
    sm_socket *sockets;
//    int socket_count;
    struct epoll_event *events;
    int events_count;
    int events_max;
    int epfd;
    pthread_mutex_t mutex;
    ns_nameserver *nameserver;
    iohandler_t handler;
} sm_manager;

/*----------------------------------------------------------------------------*/

sm_manager *sm_create( ns_nameserver *nameserver );

// TODO: another parameter: type - in / out / something else
int sm_open_socket( sm_manager *manager, unsigned short port, socket_t type);
int sm_close_socket( sm_manager *manager, unsigned short port);
void *sm_listen( void *obj );
void sm_destroy( sm_manager **manager );

// Handlers

static inline void sm_register_handler(sm_manager* manager, iohandler_t handler) {
    manager->handler = handler;
}

static inline iohandler_t sm_handler(sm_manager* manager) {
    return manager->handler;
}

void sm_tcp_handler(sm_manager *manager, int fd, void *buf, size_t bufsize, void* answer, size_t answer_size);
void sm_udp_handler(sm_manager *manager, int fd, void *buf, size_t bufsize, void* answer, size_t answer_size);

#endif
