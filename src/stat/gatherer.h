/*
 * File:     gatherer.h
 * Date:     08.11.2010 10:10
 * Author:   jan.kadlec@nic.cz
 * Project:  CuteDNS
 */

#ifndef __GATH_H__
#define __GATH_H__

#include <stdint.h>

#include "common.h"

/* the bigger this number, the better the performance of hashing */
enum fbs { FREQ_BUFFER_SIZE = 100000 };

/*!
 * \brief Enum storing protocol codes.
 */
enum protocol {
    stat_UDP,
    stat_TCP
};

typedef enum protocol protocol_t;

/*!
 * \brief Structure used for backward mapping from a simple 
 *        hash back to string representation.
 */
struct flow_data {
    char *addr; /*!< IP adress in string format (IPv4 only at this time) */
    uint16_t port; /*!< TCP/UDP port number */
    protocol_t protocol;
};

typedef struct flow_data flow_data_t;

/**
\brief 
Gatherer structure, used for gathering statistics from multiple threads.
*/
struct gatherer {
    pthread_mutex_t mutex_read;
    double qps; /*!< Queries per second */
    double udp_qps; /*!< Queries per second - UDP */
    double tcp_qps; /*!< Queries per second - TCP */

/*  latency currently disabled */
/*  double mean_latency;
    double udp_mean_latency;
    double tcp_mean_latency;
    uint udp_latency;
    uint tcp_latency; */

    uint udp_queries; /*!< Total number of UDP queries for given SLEEP_TIME */
    uint tcp_queries; /*!< Total number of TCP queries for given SLEEP_TIME */

    /* the following should be much bigger, but sparse array, ideally 2**32 */
    uint freq_array[FREQ_BUFFER_SIZE]; /*!< Array with query frequencies */
    flow_data_t *flow_array[FREQ_BUFFER_SIZE]; /*!< Used for backward mapp. */

    pthread_t sleeper_thread; /*!< Thread used for computation of statistics */
};

typedef struct gatherer gatherer_t;

/*!
 * \brief Creates a new gatherer instance
 *
 * \return pointer to creted structure, NULL otherwise
 */
gatherer_t *new_gatherer();

/*!
 * \brief Frees a gatherer instance
 *
 * \param gatherer gatherer instance to be freed
 */
void gatherer_free( gatherer_t *gatherer );

#endif

/* end of file gatherer.h */
