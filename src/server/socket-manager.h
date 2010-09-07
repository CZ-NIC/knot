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

/*----------------------------------------------------------------------------*/

typedef enum {
    SOCKET_BUFF_SIZE = 4096,  /// \todo <= MTU size
    DEFAULT_EVENTS_COUNT = 1,
} smconst_t;

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

/** Event descriptor.
  */
typedef struct sm_event {
    struct sm_manager* manager;
    int fd;
    uint32_t events;
    void* inbuf;
    void* outbuf;
    size_t size_in;
    size_t size_out;
} sm_event;

/** Handler functio proto. */
typedef void* (*sockhandler_t) (void*);

/** Workers descriptor. */
typedef struct sm_worker {
    int id;
    struct epoll_event *events;
    int events_count;
    int events_size;
    struct sm_manager *mgr;
    pthread_mutex_t mutex;
    pthread_cond_t  wakeup;
} sm_worker;

#define next_worker(current, mgr) \
   (((current) + 1) % (mgr)->workers_dpt->thread_count)

/** \todo Implement notification via Linux eventfd() instead of is_running.
  */
typedef struct sm_manager {
    int epfd;
    int fd_count;
    volatile short is_running;
    sm_socket *sockets;
    sm_worker *workers;
    ns_nameserver *nameserver;
    dpt_dispatcher *master;
    dpt_dispatcher *workers_dpt;
    pthread_mutex_t sockets_mutex;
} sm_manager;

/*----------------------------------------------------------------------------*/

sm_manager *sm_create( ns_nameserver *nameserver, sockhandler_t pmaster, sockhandler_t pworker, int thread_count);
int sm_start( sm_manager* manager );
int sm_wait( sm_manager* manager );
void sm_stop( sm_manager *manager );
void sm_destroy( sm_manager **manager );
int sm_open_socket( sm_manager *manager, unsigned short port, socket_t type);
int sm_close_socket( sm_manager *manager, unsigned short port);

/** \todo Temporary APIs.
  *       Socket manager should only accept Master prototype + non-compulsory Worker prototype.
  */
int sm_reserve_events( sm_worker *worker, uint size );
int sm_remove_event( sm_manager *manager, int socket );
int sm_add_event( sm_manager *manager, int socket, uint32_t events );


#endif
