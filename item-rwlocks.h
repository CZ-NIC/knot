#ifndef ITEM_RWLOCKS
#define ITEM_RWLOCKS

#include <pthread.h>

/*----------------------------------------------------------------------------*/

typedef struct {
    void *item;
    int waiting;
    pthread_rwlock_t lock;
} irwl_lock;

typedef struct {
    irwl_lock *locks;
    int count;
    pthread_mutex_t mtx;
} irwl_table;

/*----------------------------------------------------------------------------*/

irwl_table *irwl_create( int count );

int irwl_destroy( irwl_table **table );

int irwl_rdlock( irwl_table *table, void *item );

//int irwl_tryrdlock( irwl_table *table, void *item );

int irwl_wrlock( irwl_table *table, void *item );

//int irwl_trywrlock( irwl_table *table, void *item );

int irwl_unlock( irwl_table *table, void *item );

#endif
