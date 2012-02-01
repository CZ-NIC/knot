/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file stat.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Contains statistics structure and its API.
 *
 * \addtogroup statistics
 * @{
 */

#ifndef _KNOTD_STAT_H_
#define _KNOTD_STAT_H_

#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "knot/stat/gatherer.h"

#ifdef STAT_COMPILE
#define STAT_INIT(x) x = stat_new()
#else
#define STAT_INIT(x) x = NULL //UNUSED(x)
#endif /* STAT_COMPILE */

/* Determines how long until the sleeper thread
 * wakes up and runs computations.
 */
static uint const SLEEP_TIME = 15;

/* Sets threshold for active flow detection, will
 * probably have to be changed. */
static uint const ACTIVE_FLOW_THRESHOLD = 10;

/*!
 * \brief Statistics structure, unique for each UDP/TCP thread.
 */
struct stat_stat {
//	struct timespec t1, t2; /* Currently disabled */
	protocol_t protocol; /*!< Flags. */
	struct sockaddr_in *s_addr;
//  gatherer_t *gatherer; / * not needed when using static gatherer. */
};

typedef struct stat_stat stat_t;

/*!
 * \brief Creates new stat_t structure.
 *
 * \return Newly allocated and initialized stat structure, NULL on errror.
 */
#ifdef STAT_COMPILE
stat_t *stat_new();
#else
static inline inline stat_t *stat_new()
{
	return NULL;
}
#endif /* STAT_COMPILE */

/*!
 * \brief Sets a protocol for stat_t structure. Options are stat_UDP, stat_TCP.
 *
 * \param stat Stat_t instance (usually newly created).
 * \param protocol Protocol to be assigned to stat structure.
 */
#ifdef STAT_COMPILE
void stat_set_protocol(stat_t *stat, int protocol);
#else
static inline void stat_set_protocol(stat_t *stat, int protocol) {}
#endif /* STAT_COMPILE */

/*!
 * \brief Gets the time from a processing function.
 *
 * \param stat  Current instance of stat_t.
 * \param s_addr Sockaddr structure to be used later for statistics.
 */
#ifdef STAT_COMPILE
#warning "stat fixme: pass sockaddr* for generic _in and _in6 support"
void stat_get_first(stat_t *stat, struct sockaddr_in *s_addr);
#else
static inline void stat_get_first(stat_t *stat, struct sockaddr *s_addr) {}
#endif /* STAT_COMPILE */

/*!
 * \brief Gets time from a processing fuction and changes
 *        the corresponding variables.
 *
 * \param stat Current stat_t instance.
 */
#ifdef STAT_COMPILE
void stat_get_second(stat_t *stat);
#else
static inline void stat_get_second(stat_t *stat) {}
#endif /* STAT_COMPILE */

/*!
 * \brief Frees stat_t structure.
 *
 * \param stat Pointer to stat structure to be deallocated.
 */
#ifdef STAT_COMPILE
void stat_free(stat_t *stat);
#else
static inline void stat_free(stat_t *stat) {}
#endif /* STAT_COMPILE */

/*!
 * \brief Initializes static gatherer.
 */
#ifdef STAT_COMPILE
void stat_static_gath_init();
#else
static inline void stat_static_gath_init() {}
#endif /* STAT_COMPILE */

/*!
 * \brief Starts static gatherer's sleeper thread.
 */
#ifdef STAT_COMPILE
void stat_static_gath_start();
#else
static inline void stat_static_gath_start() {}
#endif /* STAT_COMPILE */

/*!
 * \brief Frees static gatherer, calls gatherer_free().
 */
#ifdef STAT_COMPILE
void stat_static_gath_free();
#else
static inline void stat_static_gath_free() {}
#endif /* STAT_COMPILE */

#endif /* _KNOTD_STAT_H_ */

/*! @} */
