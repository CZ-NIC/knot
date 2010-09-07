/*!
  * \file socket-manager.h
  *
  * Generic threaded socket manager and APIs for creating custom managers.
  * This virtual socket manager needs at least pointer to master thread routine.
  */

#ifndef SOCKET_MANAGER
#define SOCKET_MANAGER

#include <sys/epoll.h>
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

/** Host socket descriptor.
  *
  * Used only for state-keeping on master sockets.
  */
typedef struct sm_socket {
    unsigned short port;
    int socket;
    struct sm_socket *next;
} sm_socket;

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

/** Handler functio proto.
  \todo Replace with proto from dispatcher.
  */
typedef void* (*sockhandler_t) (void*);

/** Workers descriptor.
  * Contains epoll (inherited from Master or own) and events backing store.
  */
typedef struct sm_worker {
    int id;
    int epfd;
    struct epoll_event *events;
    int events_count;
    int events_size;
    struct sm_manager *mgr;
    pthread_mutex_t mutex;
    pthread_cond_t  wakeup;
} sm_worker;

#define next_worker(current, mgr) \
   (((current) + 1) % (mgr)->workers_dpt->thread_count)

/** Socket manager structure.
  * Contains ptrs to master and worker thread prototypes and built-in epoll.
  */
typedef struct sm_manager {
    int epfd;
    int fd_count;
    volatile short is_running; /// \todo Implement notification via Linux eventfd() instead of is_running.
    dpt_dispatcher *master;
    dpt_dispatcher *workers_dpt;
    sm_worker *workers;
    ns_nameserver *nameserver;
    sm_socket* sockets;
    pthread_mutex_t lock;
} sm_manager;

/*----------------------------------------------------------------------------*/

/* Public APIs for Socket Manager. */

/** Create a socket manager instance.
  * \param nameserver Pointer to given nameserver instance.
  * \param pmaster Master thread routine.
  * \param pworker Worker thread routine (set to NULL if not needed).
  * \param thread_count Number of worker threads.
  * \return New instance or NULL.
  */
sm_manager *sm_create( ns_nameserver *nameserver, sockhandler_t pmaster, sockhandler_t pworker, int thread_count);

/** Start the socket manager instance and run master thread routine (non-blocking).
  * \return >=0 If successful, negative integer on failure.
  */
int sm_start( sm_manager* manager );

/** Open socket in given manager.
  * \param port Socket port number.
  * \param type Socket type (TCP|UDP).
  * \return >=0 If successful, negative integer on failure.
  */
int sm_open( sm_manager *manager, unsigned short port, socket_t type);

/** Close open port.
  * \param port Port number.
  * \return >=0 If successful, negative integer on failure.
  */
int sm_close( sm_manager *manager, unsigned short port);

/** Wait for the socket manager to finish (blocking).
  * \return >=0 If successful, negative integer on failure.
  */
int sm_wait( sm_manager* manager );

/** Stop the socket manager instance (non-blocking).
  */
void sm_stop( sm_manager *manager );

/** Destroy the socket manager instance (blocking).
  * \warning Wait for socket manager to finish before destroying it.
  */
void sm_destroy( sm_manager **manager );

/* APIs for extending Socket Manager.
 * \todo Temporary APIs.
 */

/** Add socket to epoll set.
  * \param epfd Epoll set fd.
  * \param socket Given socket.
  * \param events Epoll flags.
  * \return >=0 If successful, negative integer on failure.
  */
int sm_add_event( int epfd, int socket, uint32_t events);

/** Remove socket from epoll set.
  * \param epfd Epoll set fd.
  * \param socket Given socket.
  * \return >=0 If successful, negative integer on failure.
  */
int sm_remove_event( int epfd, int socket );

/** Reserve worker's backing store.
  * \param worker Given worker ptr.
  * \param size Requested number of events.
  * \return >=0 If successful, negative integer on failure.
  */
int sm_reserve_events( sm_worker *worker, uint size );

#endif
