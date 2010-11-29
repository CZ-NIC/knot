/*!
 * \file gatherer.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Contains gatherer structure and its API.
 * 
 * \addtogroup statistics
 * @{
 */

#ifndef _CUTEDNS_GATHERER_H_
#define _CUTEDNS_GATHERER_H_

#include <stdint.h>

#include "common.h"

/* The bigger this number, the better the performance of hashing. */
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
	char *addr; /*!< IP adress in string format (IP4 only at this time). */
	uint16_t port; /*!< TCP/UDP port number. */
	protocol_t protocol;
};

typedef struct flow_data flow_data_t;

/*!
 * \brief Gatherer structure, used for gathering statistics from 
 *        multiple threads.
 */
struct gatherer {
	pthread_mutex_t mutex_read; /*!< Mutex used when reading values. */
	double qps; /*!< Queries per second. */
	double udp_qps; /*!< Queries per second - UDP. */
	double tcp_qps; /*!< Queries per second - TCP. */

	/*  latency currently disabled */
	/*  double mean_latency;
	    double udp_mean_latency;
	    double tcp_mean_latency;
	    uint udp_latency;
	    uint tcp_latency; */

	uint udp_queries; /*!< Total number of UDP queries for SLEEP_TIME. */
	uint tcp_queries; /*!< Total number of TCP queries for SLEEP_TIME. */
	/*!
	 * \brief this variable should be much bigger, preferably sparse array
	 *        with 2**32 elements (for IPv4). It is an array with query
	 *        query frequencies.
	 */
	uint freq_array[FREQ_BUFFER_SIZE];
	/*!
	 * \brief Used for backward mapping.
	 */
	flow_data_t *flow_array[FREQ_BUFFER_SIZE];
	/*!
	 * \brief Thread used for computation of statistics.
	 */
	pthread_t sleeper_thread;
};

typedef struct gatherer gatherer_t;

/*!
 * \brief Creates a new gatherer instance.
 *
 * \return Pointer to created structure, NULL otherwise.
 */
gatherer_t *new_gatherer();

/*!
 * \brief Frees a gatherer instance.
 *
 * \param gatherer Gatherer instance to be freed.
 */
void gatherer_free(gatherer_t *gatherer);

#endif /* _CUTEDNS_STAT_GATHERER_H_ */

/*! @} */
