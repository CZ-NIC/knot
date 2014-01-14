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

#include <config.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include "knot/stat/stat-common.h"
#include "knot/stat/stat.h"
#include "knot/stat/gatherer.h"

#ifdef STAT_COMPILE

/* Static local gatherer variable, to be used with all functions. */
static gatherer_t *local_gath;

/* CLEANUP */
/*
static void stat_inc_latency( stat_t *stat, uint increment )
{
	if (stat->protocol==stat_UDP) {
		local_gath->udp_latency+=increment;
	} else {
		local_gath->tcp_latency+=increment;
	}
}*/
/*
static uint stat_last_query_time( stat_t *stat )
{
	return (stat->t2).tv_nsec-(stat->t1).tv_nsec;
}*/

/*!
 * \brief Increases query count in the local data gatherer.
 *
 * \param stat Current stat instance.
 */
static void stat_inc_query(stat_t *stat)
{
	if (stat->protocol == stat_UDP) {
		local_gath->udp_queries++;
	} else {
		local_gath->tcp_queries++;
	}
}

/*!
 * \brief Calculates very simple hash from IPv4 address and returns index to
 *        array.
 *
 * \param s_addr Socket address structure.
 * \param protocol Used protocol.
 *
 * \return uint Calculated index.
 */
static uint return_index(struct sockaddr_in *s_addr , protocol_t protocol)
{
	/* TODO IPv6 */
	/* This is the first "hash" I could think of quickly. */
	uint ret = 0;

	char str[24];
	inet_ntop(AF_INET, &s_addr->sin_addr, str, 24);

	for (int i = 0; i < strlen(str); i++) {
		if (str[i] != '.') {
			ret += str[i];
			ret *= (i + 1);
		}
	}

	ret += s_addr->sin_port * 7;
	if (protocol == stat_UDP) {
		ret *= 3;
	} else {
		ret *= 7;
	}
	ret %= FREQ_BUFFER_SIZE;
	/* Effectively uses only end of the hash, maybe hash the
	 * resulting number once again to get 0 <= n < 10000. */
	return ret;
}

/*!
 * \brief Adds data to local gatherer structure.
 *
 * \param stat Current stat variable.
 *
 * \retval 0 on success.
 * \retval -1 on memory error.
 */
static int stat_gatherer_add_data(stat_t *stat)
{
	/* TODO IPv6*/
	uint index = return_index(stat->s_addr, stat->protocol);
	if (!local_gath->freq_array[index]) {
		char addr[24];
		inet_ntop(AF_INET, &stat->s_addr->sin_addr, addr, 24);
		flow_data_t *tmp;
		tmp = malloc(sizeof(flow_data_t));
		if (tmp == NULL) {
			ERR_ALLOC_FAILED;
			return -1;
		}
		tmp->addr = malloc(sizeof(char) * 24);
		if (tmp->addr == NULL) {
			free(tmp)
			ERR_ALLOC_FAILED;
			return -1;
		}
		strcpy(tmp->addr, addr);
		tmp->port = stat->s_addr->sin_port;
		tmp->protocol = stat->protocol;
		local_gath->flow_array[index] = tmp;
	}

	//TODO add a check here, whether hashing fction performs well enough

	local_gath->freq_array[index] += 1;

	return 0;
}

/*!
 * \brief Resets logging array.
 */
static void stat_reset_gatherer_array()
{
	for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
		local_gath->freq_array[i] = 0;
	}
}

/*!
 * \brief Sleeps for given time and then runs all the computations,
 *        results of which are stored in local gatherer.
 */
static void stat_sleep_compute()
{
	while (1) {
		sleep(SLEEP_TIME);

		for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
			if (local_gath->freq_array[i] >
			    ACTIVE_FLOW_THRESHOLD) {
				dbg_st("too much activity at index %d:"
					 " %d queries adress: %s port %d"
					 " protocol %d\n",
					 i, local_gath->freq_array[i],
					 local_gath->flow_array[i]->addr,
					 local_gath->flow_array[i]->port,
					 local_gath->flow_array[i]->protocol);
			}
		}

		pthread_mutex_lock(&(local_gath->mutex_read));

		local_gath->udp_qps = local_gath->udp_queries /
				      (double)SLEEP_TIME;
		local_gath->tcp_qps = local_gath->tcp_queries /
				      (double)SLEEP_TIME;
		local_gath->qps = local_gath->udp_qps + local_gath->tcp_qps;

		/* following code needs usage of
		 * gettimeofday, which is currently disabled */
		/* CLEANUP */
/*		local_gath->udp_mean_latency=((double)local_gath->udp_latency/
		(double)local_gath->udp_queries);
		local_gath->tcp_mean_latency=((double)local_gath->tcp_latency/
		(double)local_gath->tcp_queries);
		local_gath->mean_latency = (local_gath->udp_mean_latency +
		local_gath->tcp_mean_latency)/2; */

		local_gath->udp_queries = 0;
		local_gath->tcp_queries = 0;

		/* same thing as above applies here */

/*		local_gath->tcp_latency = 0;
		local_gath->udp_latency = 0; */

		pthread_mutex_unlock(&(local_gath->mutex_read));

		stat_reset_gatherer_array(local_gath);

		dbg_st("qps_udp: %f\n", local_gath->udp_qps);
/*		dbg_st("mean_lat_udp: %f\n", local_gath->udp_mean_latency); */

		dbg_st("qps_tcp: %f\n", local_gath->tcp_qps);
/*		dbg_st("mean_lat_tcp: %f\n", local_gath->tcp_mean_latency); */

		dbg_st("UDP/TCP ratio %f\n",
			 local_gath->udp_qps / local_gath->tcp_qps);
	}
}

stat_t *stat_new()
{
	stat_t *ret;

	if ((ret = malloc(sizeof(stat_t))) == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	return ret;
}

void stat_set_protocol(stat_t *stat, int protocol)
{
	stat->protocol = protocol;
}

void stat_get_first(stat_t *stat , struct sockaddr_in *s_addr)
{
	/* CLEANUP */
//	gettimeofday(&stat->t2, NULL);
	stat->s_addr = s_addr;
//	check if s_addr does not get overwritten
}

void stat_get_second(stat_t *stat)
{
	/* CLEANUP */
//	gettimeofday(&stat->t2, NULL);
	stat_inc_query(stat);
//	stat_inc_latency(stat, stat_last_query_time(stat));
	stat_gatherer_add_data(stat);
}

void stat_free(stat_t *stat)
{
	free(stat);
}

void stat_static_gath_init()
{
	local_gath = new_gatherer();
}

void stat_static_gath_start()
{
	pthread_create(&(local_gath->sleeper_thread), NULL,
		       (void *) &stat_sleep_compute, NULL);
}

void stat_static_gath_free()
{
	gatherer_free(local_gath);
}

#endif /* STAT_COMPILE */
