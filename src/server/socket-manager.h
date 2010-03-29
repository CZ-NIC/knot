/**
  * @note As of now, all sockets managed by socket-manager are UDP sockets.
  *       Further (maybe fundamental) changes will be need when TCP is to
  *       be used as well.
  *
  * @todo Associative array mapping ports to sockets or use a linked list.
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

struct sm_manager {
    unsigned short *ports;
    int *sockets;
    int socket_count;
    int max_sockets;
    struct epoll_event *events;
    int epfd;
    pthread_mutex_t mutex;
    pthread_mutex_t manager_mutex;
    ns_nameserver *nameserver;
};

typedef struct sm_manager sm_manager;

/*----------------------------------------------------------------------------*/

sm_manager *sm_create( ns_nameserver *nameserver );

// TODO: another parameter: type - in / out / something else
int sm_open_socket( sm_manager *manager, unsigned short port );

int sm_close_socket( sm_manager *manager, unsigned short port );

void *sm_listen( void *obj );

void sm_destroy( sm_manager **manager );

#endif
