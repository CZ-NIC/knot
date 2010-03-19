#include "item-rwlocks.h"
#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define IRWL_DEBUG

/*----------------------------------------------------------------------------*/

irwl_table *irwl_create( int count )
{
    assert(count > 0);
    irwl_table *table = malloc(sizeof(irwl_table));

    if (table == NULL) {
        fprintf(stderr, "irwl_create_table(): Allocation failed.\n");
        return NULL;
    }

    table->locks = malloc(count * sizeof(irwl_lock));

    if (table->locks == NULL) {
        fprintf(stderr, "irwl_create_table(): Allocation failed.\n");
        free(table);
        return NULL;
    }

    int res = 0;
    if ((res = pthread_mutex_init(&table->mtx, NULL)) !=0 ) {
        fprintf(stderr, "ERROR: %d: %s.\n", res, strerror(res) );   // OK??
        free(table->locks);
        free(table);
        return NULL;
    }

    table->count = count;

    for (int i = 0; i < count; ++i) {
        table->locks[i].item = NULL;
        table->locks[i].waiting = 0;
        if ((res = pthread_rwlock_init(&table->locks[i].lock, NULL)) != 0) {
            fprintf(stderr, "ERROR: %d: %s.\n", res, strerror(res) );   // OK??
            free(table->locks);
            free(table);
            return NULL;
        }
    }

    return table;
}

/*----------------------------------------------------------------------------*/

int irwl_destroy( irwl_table **table )
{
    pthread_mutex_lock(&(*table)->mtx);

    // check if all locks are unlocked
    for (int i = 0; i < (*table)->count; ++i) {
        if (pthread_rwlock_trywrlock(&(*table)->locks[i].lock) != 0) {
            return -1;
        }
    }

    int res;

    // if here, all locks are unlocked, so destroy the table
    for (int i = 0; i < (*table)->count; ++i) {
        assert((*table)->locks[i].waiting == 0);
        res = pthread_rwlock_destroy(&(*table)->locks[i].lock);
        assert(res == 0);
    }
    free((*table)->locks);

    pthread_mutex_unlock(&(*table)->mtx);
    // hope noone will lock the mutex between these two commands!!
    res = pthread_mutex_destroy(&(*table)->mtx);
    assert(res == 0);

    free((*table));
    (*table) = NULL;

    return 0;
}

/*----------------------------------------------------------------------------*/

int irwl_rdlock( irwl_table *table, void *item )
{
    pthread_mutex_lock(&table->mtx);

    // try to find lock for this item
    int i = 0;
    int clear = -1;
    while (i < table->count && table->locks[i].item != item) {
        ++i;
        if (table->locks[i].item == NULL && clear == -1) {
            clear = i;
        }
    }
    // the loop ends either by finding the item, then 'i' is its index
    // or by searching through the whole array; then we may have an index of
    // free position in 'clear'

    // no more space for locks
    if (i == table->count && clear == -1) {
        return -1;
    }

    // item already locked
    if (table->locks[i].item == item) {
        // if write-locked, add us to the 'queue' of waiting
        if (pthread_rwlock_tryrdlock(&table->locks[i].lock) != 0) {
            ++table->locks[i].waiting;
        }
        // and unlock mutex to allow the rwlock to be unlocked if write-locked
        pthread_mutex_unlock(&table->mtx);
        // can anything bad happen between these two commands? (such as someone
        // else acquires the lock)
        int res = pthread_rwlock_rdlock(&table->locks[i].lock);
        // can anything bad happen between these two commands? (such as this
        // thread unlocks the lock?)
        pthread_mutex_lock(&table->mtx);
        assert(res == 0);
        --table->locks[i].waiting;
        pthread_mutex_unlock(&table->mtx);
        return 0;
    }

    // item not locked and in 'clear' we have index of the first clear item
    assert(table->locks[clear].item == NULL);

    // lock & save item pointer
    int res = pthread_rwlock_rdlock(&table->locks[clear].lock);
    assert(res == 0);
    table->locks[clear].item = item;

    pthread_mutex_unlock(&table->mtx);
    return 0;
}

/*----------------------------------------------------------------------------*/

int irwl_wrlock( irwl_table *table, void *item )
{
    pthread_mutex_lock(&table->mtx);

    // try to find lock for this item
    int i = 0;
    int clear = -1;
    while (i < table->count && table->locks[i].item != item) {
        ++i;
        if (table->locks[i].item == NULL && clear == -1) {
            clear = i;
        }
    }

    // no more space for locks
    if (i == table->count && clear == -1) {
        return -1;
    }

    // item already locked - cannot be write-locked until unlocked!!
    if (table->locks[i].item == item) {
        assert(pthread_rwlock_trywrlock(&table->locks[i].lock) != 0);
        // add us to the 'queue' of waiting
        ++table->locks[i].waiting;
        // wait for the item to be unlocked
        // must unlock mutex to allow the rwlock to be unlocked
        pthread_mutex_unlock(&table->mtx);
        // can anything bad happen between these two commands? (such as someone
        // else acquires the lock)
        int res = pthread_rwlock_wrlock(&table->locks[i].lock);
        // can anything bad happen between these two commands? (such as this
        // thread unlocks the lock?)
        pthread_mutex_lock(&table->mtx);
        assert(res == 0);
        --table->locks[i].waiting;
        pthread_mutex_unlock(&table->mtx);
        return 0;
    }

    // we assume that the locks are saved in the first items of the array
    // thus here we found a free place for lock
    assert(table->locks[clear].item == NULL);

    // lock & save item pointer
    int res = pthread_rwlock_wrlock(&table->locks[clear].lock);
    assert(res == 0);
    table->locks[clear].item = item;

    pthread_mutex_unlock(&table->mtx);
    return 0;
}

/*----------------------------------------------------------------------------*/

int irwl_unlock( irwl_table *table, void *item )
{
    pthread_mutex_lock(&table->mtx);

    // find lock for this item
    int i = 0;
    while (i < table->count
           && table->locks[i].item != NULL
           && table->locks[i].item != item) {
        ++i;
    }

    // if not found, there is nothing to unlock
    if (i == table->count || table->locks[i].item == NULL) {
        return -1;
    }

    assert(table->locks[i].item == item);

    // found, unlock the lock
    pthread_rwlock_unlock(&table->locks[i].lock);

    // clear the item pointer if noone is waiting for the lock
    if (table->locks[i].waiting == 0) {
        table->locks[i].item = NULL;
    }

    pthread_mutex_unlock(&table->mtx);
    return 0;
}
