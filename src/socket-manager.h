#ifndef SOCKET_MANAGER
#define SOCKET_MANAGER

#include <sys/epoll.h>
#include <pthread.h>
#include "common.h"

const uint SOCKET_BUFF_SIZE;

/*----------------------------------------------------------------------------*/

struct sm_manager {
    int socket;         // later use array of sockets?
    struct epoll_event event;
    int epfd;
    void (*answer_fnc)(const char *, uint, char *, uint *);
    pthread_mutex_t mutex;
};

typedef struct sm_manager sm_manager;

/*----------------------------------------------------------------------------*/

sm_manager *sm_create( unsigned short port,
                       void (*answer_fnc)(const char *, uint, char *, uint *) );

void *sm_listen( void *obj );

void sm_destroy( sm_manager **manager );

#endif
