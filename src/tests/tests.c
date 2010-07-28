#include "tests.h"
//#include "bitset.h"
#include "common.h"
#include "dynamic-array.h"

#include <urcu.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

static const int THREADS_RCU = 2;
static const int DA_DEF_SIZE = 1000;
static const int DA_OPERATIONS = 100;

/*----------------------------------------------------------------------------*/

//int test_bitset()
//{
//    bitset_t bitset;
//    uint n = 1048576, i, c, err = 0;
//    uint *numbers = malloc(n/2 * sizeof(uint));

//    BITSET_CREATE(&bitset, n);
//    BITSET_CLEAR(bitset, n);

//    printf("New bitset created.\n");

//    // check if empty
//    for (i = 0; i < n; i++) {
//        if (BITSET_GET(bitset, i) != 0) {
//            printf("Bit %u not clear!\n", i);
//            err++;
//        }
//    }

//    srand(1);

//    printf("Setting random bits...\n");

//    // set random bits, but keep track of them
//    for (i = 0; i < n/2; i++) {
//        c = rand() % n;
//        //printf("Setting bit on position %u..\n", c);
//        numbers[i] = c;
//        BITSET_SET(bitset, c);

//        if (!BITSET_ISSET(bitset, c)) {
//            printf("Bit %u not set successfully!\n", c);
//            err++;
//        }

//        BITSET_UNSET(bitset, c);
//    }

//    printf("Testing borders...\n");
//    // setting bits on the borders
//    BITSET_SET(bitset, 0);
//    if (!BITSET_ISSET(bitset, 0)) {
//        printf("Error setting bit on position 0.\n");
//        err++;
//    }
//    BITSET_UNSET(bitset, 0);

//    BITSET_SET(bitset, 31);
//    if (!BITSET_ISSET(bitset, 31)) {
//        printf("Error setting bit on position 31.\n");
//        err++;
//    }
//    BITSET_UNSET(bitset, 31);

//    BITSET_SET(bitset, 32);
//    if (!BITSET_ISSET(bitset, 32)) {
//        printf("Error setting bit on position 32.\n");
//        err++;
//    }
//    BITSET_UNSET(bitset, 32);

//    BITSET_SET(bitset, 33);
//    if (!BITSET_ISSET(bitset, 33)) {
//        printf("Error setting bit on position 33.\n");
//        err++;
//    }
//    BITSET_UNSET(bitset, 33);

//    BITSET_SET(bitset, 1048575);
//    if (!BITSET_ISSET(bitset, 1048575)) {
//        printf("Error setting bit on position 1048575.\n");
//        err++;
//    }
//    BITSET_UNSET(bitset, 1048575);

//    // check if empty
//    for (i = 0; i < n; i++) {
//        if (BITSET_GET(bitset, i) != 0) {
//            printf("Bit %u not clear!\n", i);
//            err++;
//        }
//    }

//    free(numbers);
//    BITSET_DESTROY(&bitset);

//    printf("There were %u errors.\n", err);
//    return 0;
//}

/*----------------------------------------------------------------------------*/

#define LOOPS 10000

void do_some_stuff( int loops )
{
		int i;
		int res = 1;

		for (int j = 1; j <= LOOPS; ++j) {
			for (i = 1; i <= loops; ++i) {
				res *= i;
			}
		}
}

/*----------------------------------------------------------------------------*/

void *test_rcu_thread( void *obj )
{
	rcu_register_thread();
	rcu_read_lock();

	log_debug("Thread %ld entered critical section..\n", pthread_self());

	do_some_stuff(100000);

	log_debug("Thread %ld leaving critical section..\n", pthread_self());

	rcu_read_unlock();
	rcu_unregister_thread();

	return NULL;
}

/*----------------------------------------------------------------------------*/

int test_rcu()
{
	int i;

	pthread_t *threads = malloc(THREADS_RCU * sizeof(pthread_t));
	void *(*routine)(void *) = test_rcu_thread;
	char msg[7] = "blabla\0";
	void *routine_obj = msg;

	log_debug("Testing RCU mechanism.\nCreating %i threads with reader critical"
			  " sections.\nMessage: %s\n\n", THREADS_RCU, msg);

	for (i = 0; i < THREADS_RCU; ++i)
	{
		if (pthread_create(&threads[i], NULL, routine, routine_obj)) {
			log_error("%s: failed to create thread %d", __func__, i);
			return -1;
		}
	}
	for (i = 0; i < THREADS_RCU; ++i)
	{
		if (pthread_detach(threads[i])) {
			log_error("%s: failed to join thread %d", __func__, i);
			return -1;
		}
	}

	log_debug("Main thread after launching threads. Message: %s\n", msg);
	synchronize_rcu();
	log_debug("Main thread after synchronizing RCU. Message: %s\n", msg);

	getchar();
	return 0;
}

/*----------------------------------------------------------------------------*/

void *test_dynamic_array_read( void *obj )
{
	rcu_register_thread();

	rcu_read_lock();

	da_array *array = (da_array *)obj;
	int index = rand() % da_get_count(array);

	log_debug("[Read] Saving pointer to %d. item...\n", index);
	uint *item = &((uint *)da_get_items(array))[index];
	log_debug("[Read] Pointer: %p Item: %u\n", item, *item);

	log_debug("[Read] Waiting...\n");
	do_some_stuff(100000);
	log_debug("[Read] Done.\n");

	log_debug("[Read] Pointer: %p Item: %u\n", item, *item);
	log_debug("[Read] Unlocking RCU lock.\n");
	rcu_read_unlock();

	log_debug("[Read] Pointer: %p Item: %u\n", item, *item);

	log_debug("[Read] Waiting...\n");
	do_some_stuff(10000);
	log_debug("[Read] Done.\n");

	log_debug("[Read] Now the item should be deallocated...\n");
	log_debug("[Read] Pointer: %p Item: %u\n", item, *item);

	rcu_unregister_thread();

	return NULL;
}

/*----------------------------------------------------------------------------*/

int test_dynamic_array()
{
	rcu_init();

	srand(time(NULL));
	da_array array;

	log_debug("Testing dynamic array structure.\n\nInitializing array of size"
			  " %d for type uint.\n", DA_DEF_SIZE);
	da_initialize(&array, DA_DEF_SIZE, sizeof(uint));

	uint allocated = DA_DEF_SIZE;
	uint size = 0;
	int error = 0;

	log_debug("Running %d random operations...\n", DA_OPERATIONS);
	for (int i = 1; i <= DA_OPERATIONS; ++i) {
		int r = rand() % 3;
		int count = rand() % 10 + 1;
		switch (r) {
			case 0:
				log_debug("Reserving place for %d items...", count);
				if (da_reserve(&array, count) >= 0) {
					log_debug("Successful.\n");
					assert(size <= allocated);
					if ((allocated - size) < count) {
						allocated *= 2;
					}
				} else {
					log_debug("Not successful!\n");
					error = -1;
				}
				break;
			case 1:
				log_debug("Occupying place for %d items...", count);
				if (da_occupy(&array, count) == 0) {
					((uint *)da_get_items(&array))[da_get_count(&array) - 1]
							= rand();
					log_debug("Successful, last inserted %u.\n",
							  ((uint *)da_get_items(&array))[
									  da_get_count(&array) - 1]);
					assert(size <= allocated);
					assert((allocated - size) >= count);
					size += count;
				} else {
					log_debug("Not successful!\n");
					error = -1;
				}
				break;
			case 2:
				while (count > array.count) {
					count = rand() % 10;
				}

				log_debug("Releasing place for %d items...", count);
				da_release(&array, count);
				log_debug("Done.\n");

				assert(size <= allocated);
				assert(size >= count);
				size -= count;
				break;
		}

		assert(allocated == array.allocated);
		assert(size == array.count);

		if (error != 0) {
			break;
		}
	}

	log_debug("\nDone. Allocated: %d, Items: %d, Result: %d\n\n",
			  array.allocated, array.count, error);

	if (error != 0) {
		da_destroy(&array);
		return error;
	}

	log_debug("Resizing array while holding an item...\n");
	rcu_register_thread();

	pthread_t reader;

	// create thread for reading
	log_debug("[Main] Creating thread for reading...\n");
	if (pthread_create(&reader, NULL, test_dynamic_array_read, (void *)&array)) {
		log_error("%s: failed to create reading thread.", __func__);
		rcu_unregister_thread();
		return -1;
	}
	log_debug("[Main] Done.\n");

	// wait some time, so the other thread gets the item for reading
	log_debug("[Main] Waiting...\n");
	do_some_stuff(5000);
	log_debug("[Main] Done.\n");

	// force resize
	log_debug("[Main] Forcing array resize...\n");
	da_reserve(&array, array.allocated - array.count + 1);
	log_debug("[Main] Done.\n");

	// wait for the thread
	printf("[Main] Waiting for the reader thread to finish...\n");
	void *ret = NULL;
	if (pthread_join(reader, &ret)) {
		log_error("%s: failed to join reading thread.", __func__);
		da_destroy(&array);
		rcu_unregister_thread();
		return -1;
	}
	printf("[Main] Done.\n");

	da_destroy(&array);
	rcu_unregister_thread();
	return (int)ret;
}
