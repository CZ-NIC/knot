#ifndef SOCKET_MANAGER
#define SOCKET_MANAGER

#include <sys/epoll.h>
#include <pthread.h>
#include "common.h"

/*----------------------------------------------------------------------------*/

struct sm_manager {
    int socket;         // later use array of sockets?
    uint thread_count;
    struct epoll_event event;
    int epfd;
    void (*answer_fnc)( const char *, uint, char *, uint );
    pthread_mutex_t mutex;
};

typedef struct sm_manager sm_manager;

/*----------------------------------------------------------------------------*/

sm_manager *sm_create( short port, uint thr_count,
                       void (*answer_fnc)( const char *, uint, char *, uint ) );

void sm_destroy( sm_manager *manager );

int sm_start( sm_manager *manager );

#endif
