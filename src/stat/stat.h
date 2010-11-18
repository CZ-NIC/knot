/*
 * File:     stat.h
 * Date:     01.11.2010 16:57
 * Author:   jan.kadlec@nic.cz
 * Project:  CuteDNS
 */

#ifndef __STAT_H__
#define __STAT_H__

#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "gatherer.h"
#include "common.h"

#ifdef STAT_COMPILE
#define STAT_INIT(x) x = stat_new()
#else
#define STAT_INIT(x) UNUSED(x)
#endif

/* determines how long until the sleeper thread wakes and runs computations */
static uint const SLEEP_TIME = 15;

/* sets threshold for active flow detection, will probably have to be changed*/
static uint const ACTIVE_FLOW_THRESHOLD = 10;

/*!
 * \brief Statistics structure, unique for each UDP/TCP thread.
 */
typedef struct stat_t {
    struct timespec t1, t2;
    protocol_t protocol;
    struct sockaddr_in *s_addr;
//  gatherer_t *gatherer; not needed when using static gatherer.
} stat_t;

/*!
 * \brief Creates new stat_t structure.
 *
 * \return Newly allocated and initialized stat structure, NULL on errror.
 */
stat_t *stat_new();

/*!
 * \brief Sets a protocol for stat_t structure. Options are stat_UDP, stat_TCP.
 *
 * \param stat Stat_t instance (usually newly created).
 * \param protocol Protocol to be assigned to stat structure.
 */
void stat_set_protocol( stat_t *stat, int protocol );

/*!
 * \brief Gets the time from a processing function.
 *
 * \param stat  Current instance of stat_t.
 * \param s_addr Sockaddr structure to be used later for statistics.
 */
void stat_get_first( stat_t *stat, struct sockaddr_in *s_addr );

/*!
 * \brief Gets time from a processing fuction and changes
 *        the corresponding variables.
 *
 * \param stat current stat_t instance
 */
void stat_get_second( stat_t *stat );

/*!
 * \brief Frees stat_t structure.
 *
 * \param stat Pointer to stat structure to be deallocated.
 */
void stat_free( stat_t *stat );

/*!
 * \brief Initializes static gatherer.
 */
void stat_static_gath_init();

/*!
 * \brief Starts static gatherer's sleeper thread.
 */
void stat_static_gath_start();

/*!
 * \brief Frees static gatherer, calls gatherer_free().
 */
void stat_static_gath_free();

#endif

/* end of file stat.h */
