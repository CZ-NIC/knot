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
#include "dispatcher.h"

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
typedef struct sm_event {
    struct sm_manager* manager;
    int fd;
    uint32_t events;
    void* inbuf;
    void* outbuf;
    size_t size_in;
    size_t size_out;
} sm_event;

typedef void (*iohandler_t) (sm_event*);

typedef struct sm_manager {
    sm_socket *sockets;
    struct epoll_event *events;
    int events_count;
    int events_max;
    int epfd;
    pthread_mutex_t mutex;
    ns_nameserver *nameserver;
    dpt_dispatcher *listener;
    dpt_dispatcher *workers;
    iohandler_t handler;
    volatile int is_running;
} sm_manager;

/*----------------------------------------------------------------------------*/

sm_manager *sm_create( ns_nameserver *nameserver, int thread_count );
int sm_start( sm_manager* manager );
int sm_wait( sm_manager* manager );
void sm_stop( sm_manager *manager );
void sm_destroy( sm_manager **manager );


// TODO: another parameter: type - in / out / something else
int sm_open_socket( sm_manager *manager, unsigned short port, socket_t type);
int sm_close_socket( sm_manager *manager, unsigned short port);

// Handlers

static inline void sm_register_handler(sm_manager* manager, iohandler_t handler) {
    manager->handler = handler;
}

static inline iohandler_t sm_handler(sm_manager* manager) {
    return manager->handler;
}

void *sm_listen( void *obj );
void *sm_worker( void *obj );
void sm_tcp_handler(sm_event *ev);
void sm_udp_handler(sm_event *ev);

#endif
