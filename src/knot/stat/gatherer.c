#include <config.h>
#include <pthread.h>

#include "knot/stat/stat-common.h"
#include "alloc/malloc.h"
#include "knot/stat/gatherer.h"

gatherer_t *new_gatherer()
{
	gatherer_t *ret;

	if ((ret = malloc(sizeof(gatherer_t))) == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	pthread_mutex_init(&ret->mutex_read, NULL);

	for (int i = 0; i < FREQ_BUFFER_SIZE; i++) {
		ret->freq_array[i] = 0;
		ret->flow_array[i] = NULL;
	}

	ret->qps = 0.0;
	ret->udp_qps = 0.0;
	ret->tcp_qps = 0.0;

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
