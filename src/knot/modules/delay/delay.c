#include <netinet/in.h>
#include "contrib/time.h"
#include "knot/include/module.h"
#include "contrib/mempattern.h"
#include "knot/query/layer.h"
#include <pthread.h>
#include <time.h>

/* This module is for demonstation of async mode */

#define MOD_DELAY	"\x05""delay"
#define MOD_ALL 	"\x03""all"
#define MOD_ID		"\x08""identity"

const yp_item_t delay_conf[] = {
	{ MOD_DELAY,     YP_TINT,  YP_VINT = { 1, INT32_MAX, 10} },
	{ MOD_ALL,  YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_ID, YP_TSTR,   YP_VNONE },
};

typedef struct queue_node {
	struct queue_node *next;
	struct timespec wake_time;
	knotd_qdata_t *qdata;
	bool is_in_state;
	int return_state;
} queue_node_t;

typedef struct {
	pthread_mutex_t mutex;
	queue_node_t *head;
	queue_node_t *tail;
} queue_t;

typedef struct {
	char id[64];
	int delay_ms;
	queue_t queue;
	bool exit;
	pthread_t dispatch_thread;
} delay_ctx_t;

static int queue_init(queue_t *queue)
{
	queue->head = queue->tail = NULL;
	if (pthread_mutex_init(&queue->mutex, NULL)) {
		return KNOT_ESYSTEM;
	}

	return KNOT_EOK;
}

static void queue_deinit(queue_t *queue)
{
	pthread_mutex_destroy(&queue->mutex);
}

static int queue_push(queue_t *queue, queue_node_t *node)
{
	if (pthread_mutex_lock(&queue->mutex) != 0) {
		return KNOT_ESYSTEM;
	}

	node->next = NULL;
	if (queue->head == NULL) {
		queue->tail = node;
	} else {
		queue->head->next = node;
	}
	queue->head = node;

	pthread_mutex_unlock(&queue->mutex);
	return KNOT_EOK;
}

static int queue_pop(queue_t *queue, void *ctx, bool (*callback)(queue_node_t *node, void *ctx), queue_node_t **node)
{
	*node = NULL;
	if (pthread_mutex_lock(&queue->mutex) != 0) {
		return KNOT_ESYSTEM;
	}

	if (queue->tail != NULL) {
		if (!callback || callback(queue->tail, ctx)) {
			*node = queue->tail;
			queue->tail = (*node)->next;
			if (queue->tail == NULL) {
				queue->head = NULL;
			}
		}
	}

	pthread_mutex_unlock(&queue->mutex);
	return KNOT_EOK;
}

int delay_conf_check(knotd_conf_check_args_t *args)
{
	return KNOT_EOK;
}

static int delay_query(knotd_qdata_t *qdata, int return_state, bool is_in_state, knotd_mod_t *mod)
{
	struct timespec curr_time;
	int ret = KNOT_EOK;
	if (clock_gettime(CLOCK_MONOTONIC, &curr_time) == 0) {
		delay_ctx_t *ctx = knotd_mod_ctx(mod);
		queue_node_t *node = mm_alloc(qdata->mm, sizeof(*node));
		if (node == NULL) {
			ret = KNOT_ENOMEM;
		}
		else {
			long val = curr_time.tv_nsec + ctx->delay_ms * 1000 * 1000;
			node->wake_time.tv_nsec = val % (1000 * 1000 * 1000);
			node->wake_time.tv_sec = curr_time.tv_sec + val / (1000 * 1000 * 1000);
			node->qdata = qdata;
			node->is_in_state = is_in_state;
			node->return_state = return_state;

			if ((ret = queue_push(&ctx->queue, node)) != KNOT_EOK) {
				mm_free(qdata->mm, node);
				ret = KNOT_ESYSTEM;
			}
		}
	} else {
		ret = KNOT_ESYSTEM;
	}

	return ret;
}

static knotd_state_t delay_message(knotd_state_t state, knot_pkt_t *pkt,
                                 knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	return delay_query(qdata, state, false, mod) == KNOT_EOK ? KNOT_STATE_ASYNC : state;
}

static knotd_in_state_t delay_message_in(knotd_in_state_t state, knot_pkt_t *pkt,
                                 knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	return delay_query(qdata, state, true, mod) == KNOT_EOK ? KNOTD_IN_STATE_ASYNC : state;
}

static bool check_time(queue_node_t *node, void *ctx) {
	struct timespec *delay_time = ctx;
	delay_time->tv_sec = 0;
	delay_time->tv_nsec = 1000 * 1000;
	struct timespec curr_time;
	if (clock_gettime(CLOCK_MONOTONIC, &curr_time) == 0) {
		if (curr_time.tv_sec > node->wake_time.tv_sec
			|| (curr_time.tv_sec == node->wake_time.tv_sec
				&& curr_time.tv_nsec >= node->wake_time.tv_nsec)) {
			return true;
		}

		delay_time->tv_nsec = node->wake_time.tv_nsec - curr_time.tv_nsec;
		delay_time->tv_sec = node->wake_time.tv_sec - curr_time.tv_sec;
		if (node->wake_time.tv_nsec < curr_time.tv_nsec) {
			delay_time->tv_nsec += 1000 * 1000 * 1000;
			delay_time->tv_sec -= 1;
		}
	}

	return false;
}

static struct timespec dispatch_queue(delay_ctx_t *ctx, bool all)
{
	queue_node_t *node;
	struct timespec sleep_time = {0, 1000 * 1000};
	while (true) {
		if (queue_pop(&ctx->queue, &sleep_time, all ? NULL : check_time, &node) != KNOT_EOK) {
			break;
		}

		if (!node) {
			break;
		}

		mm_free(node->qdata->mm, node);

		/* Should be the last call on the object or memory.
		 * Further access to node, qdata or mm will result in race condition as network thread can processs and cleanup */
		if (node->is_in_state) {
			node->qdata->module_async_operation_completed_in(node->qdata, node->return_state);
		} else {
			node->qdata->module_async_operation_completed(node->qdata, node->return_state);
		}
	}

	return sleep_time;
}

static void *dispatch_thread(void *d)
{
	delay_ctx_t *ctx = d;
	while (!ctx->exit) {
		struct timespec delay = dispatch_queue(ctx, false);
		struct timespec remaining;
		nanosleep(&delay, &remaining);
	}

	return d;
}

int delay_load(knotd_mod_t *mod)
{
	/* Create delay context. */
	delay_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	int rc;
	if ((rc = queue_init(&ctx->queue) != KNOT_EOK)) {
		free(ctx);
		return rc;
	}

	if(pthread_create(&ctx->dispatch_thread, NULL, dispatch_thread, ctx) != 0)
	{
		queue_deinit(&ctx->queue);
		free(ctx);
		return KNOT_ESYSTEM;
	}

	/* Set delay. */
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_DELAY);
	ctx->delay_ms = conf.single.integer;

	/* Set id. */
	conf = knotd_conf_mod(mod, MOD_ID);
	if (conf.single.string) {
		strncpy(ctx->id, conf.single.string, sizeof(ctx->id));
		ctx->id[sizeof(ctx->id) - 1] = '\0';
	}

	/* Set scope. */
	conf = knotd_conf_mod(mod, MOD_ALL);
	bool all = conf.single.boolean;

	knotd_mod_ctx_set(mod, ctx);

	knotd_mod_hook(mod, KNOTD_STAGE_END, delay_message);
	if (all) {
		knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, delay_message);
		knotd_mod_in_hook(mod, KNOTD_STAGE_PREANSWER, delay_message_in);
		knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, delay_message_in);
		knotd_mod_in_hook(mod, KNOTD_STAGE_AUTHORITY, delay_message_in);
		knotd_mod_in_hook(mod, KNOTD_STAGE_ADDITIONAL, delay_message_in);
	}

	return KNOT_EOK;
}

void delay_unload(knotd_mod_t *mod)
{
	delay_ctx_t *ctx = knotd_mod_ctx(mod);

	dispatch_queue(ctx, true);
	queue_deinit(&ctx->queue);
	free(ctx);
}

KNOTD_MOD_API(delay, KNOTD_MOD_FLAG_SCOPE_ANY,
              delay_load, delay_unload, delay_conf, delay_conf_check);
