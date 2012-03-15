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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "knot/stat/stat-common.h"
#include "common/mempattern.h"
#include "knot/stat/gatherer.h"

gatherer_t *new_gatherer()
{
	gatherer_t *ret;

	if ((ret = malloc(sizeof(gatherer_t))) == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

        pthread_mutex_init(&ret->mutex_read, NULL);

        /* TODO check success */

	for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
		ret->freq_array[i] = 0;
		ret->flow_array[i] = NULL;
	}

	ret->qps = 0.0;
	ret->udp_qps = 0.0;
	ret->tcp_qps = 0.0;

	/* CLEANUP */
	/*  currently disabled */
	/*  ret->mean_latency = 0.0;
	    ret->udp_mean_latency = 0.0;
	    ret->tcp_mean_latency = 0.0;

	    ret->udp_latency = 0;
	    ret->tcp_latency = 0; */

	ret->udp_queries = 0;
	ret->tcp_queries = 0;

	return ret;
}

void gatherer_free(gatherer_t *gath)
{
	for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
		if (gath->flow_array[i] != NULL) {
			free(gath->flow_array[i]->addr);
			free(gath->flow_array[i]);
		}
	}

	pthread_mutex_destroy(&(gath->mutex_read));

	pthread_cancel(gath->sleeper_thread);

	pthread_join((gath->sleeper_thread), NULL);

	free(gath);
}
