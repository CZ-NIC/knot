/*!
 * \file evqueue.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Event queue.
 *
 * \addtogroup data_structures
 * @{
 */
#ifndef _CUTEDNS_EVQUEUE_H_
#define _CUTEDNS_EVQUEUE_H_

#include <pthread.h>

#include "common.h"
#include "lib/lists.h"

/*!
 * \brief Event structure.
 */
typedef struct {
	struct node *next, *prev; /* Compatibility with node */
	void *data; /*!< Usable data ptr. */
} event_t;

/*!
 * \brief Event queue structure.
 */
typedef struct {
	pthread_mutex_t mx;    /*!< Notification mutex. */
	pthread_cond_t notify; /*!< Notification condition. */
	list q;                /*!< Event queue using list. */
} evqueue_t;

evqueue_t *evqueue_new();
int evqueue_init(evqueue_t *q);
void evqueue_free(evqueue_t **q);

int evqueue_clear(evqueue_t *q);
void *evqueue_get(evqueue_t *q);
int evqueue_add(evqueue_t *q, void *item);


#endif /* _CUTEDNS_EVQUEUE_H_ */

/*! @} */
