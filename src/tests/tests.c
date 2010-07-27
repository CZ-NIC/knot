#include "tests.h"
//#include "bitset.h"
#include "common.h"

#include <urcu.h>
#include <pthread.h>

#include <stdlib.h>
#include <stdio.h>

static const int THREADS_RCU = 2;

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

#define LOOPS 1000000000

void do_some_stuff()
{
		int i;
		int res = 1;

		for (i = 1; i <= LOOPS; ++i) {
				res *= i;
		}
}

/*----------------------------------------------------------------------------*/

void *test_rcu_thread( void *obj )
{
	rcu_register_thread();
	rcu_read_lock();

	log_debug("Thread %ld entered critical section..\n", pthread_self());

	do_some_stuff();

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
