#include <pthread.h>

#include "contrib/mempattern.h"
#include "contrib/time.h"
#include "knot/include/lqueue.h"
#include "knot/include/module.h"

#define MOD_DELAY           "\x05""delay"
#define MOD_THREADS         "\x07""threads"
#define MOD_ALL             "\x03""all"

const yp_item_t delay_conf[] = {
	{ MOD_DELAY,   YP_TINT,  YP_VINT  = { 1, INT32_MAX, 10 } },
	{ MOD_THREADS, YP_TINT,  YP_VINT  = { 1, INT8_MAX, 4 } },
	{ MOD_ALL,     YP_TBOOL, YP_VBOOL = { false } },
	{ NULL },
};

typedef struct {
	struct timespec wake_time;
	knotd_qdata_t *qdata;
	int return_state;
	bool is_in_state;
} queue_node_t;

typedef struct {
	int delay_ms;
	bool exit;
	int thread_count;
	knotd_lockless_queue_t *queue;
	pthread_t dispatch_thread[];
} delay_ctx_t;

static int delay_query(knotd_qdata_t *qdata, int return_state, bool is_in_state, knotd_mod_t *mod)
{
	delay_ctx_t *ctx = knotd_mod_ctx(mod);

	struct timespec curr_time;
	if (clock_gettime(CLOCK_MONOTONIC, &curr_time) != 0) {
		return KNOT_ESYSTEM;
	}

	queue_node_t *node = mm_alloc(qdata->mm, sizeof(*node));
	if (node == NULL) {
		return KNOT_ENOMEM;
	}

	uint64_t val = curr_time.tv_nsec + (uint64_t)ctx->delay_ms * 1000 * 1000;
	node->wake_time.tv_nsec = val % (1000 * 1000 * 1000);
	node->wake_time.tv_sec = curr_time.tv_sec + val / (1000 * 1000 * 1000);
	node->qdata = qdata;
	node->is_in_state = is_in_state;
	node->return_state = return_state;

	bool first;
	if (knotd_lockless_queue_enqueue(ctx->queue, node, &first) != KNOT_EOK) {
		mm_free(qdata->mm, node);
		return KNOT_ESYSTEM;
	}

	return KNOT_EOK;
}

static knotd_state_t
delay_message(knotd_state_t state, knot_pkt_t *pkt, knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	return delay_query(qdata, state, false, mod) == KNOT_EOK ? KNOT_STATE_ASYNC : state;
}

static knotd_in_state_t
delay_message_in(knotd_in_state_t state, knot_pkt_t *pkt, knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	return delay_query(qdata, state, true, mod) == KNOT_EOK ? KNOTD_IN_STATE_ASYNC : state;
}

static bool check_time(queue_node_t *node, struct timespec *delay_time)
{
	delay_time->tv_sec = 0;
	delay_time->tv_nsec = 1000 * 1000;

	struct timespec curr_time;
	if (clock_gettime(CLOCK_MONOTONIC, &curr_time) != 0) {
		return false;
	}

	if (curr_time.tv_sec > node->wake_time.tv_sec ||
	    (curr_time.tv_sec == node->wake_time.tv_sec &&
	     curr_time.tv_nsec >= node->wake_time.tv_nsec)) {
		return true;
	}

	delay_time->tv_nsec = node->wake_time.tv_nsec - curr_time.tv_nsec;
	delay_time->tv_sec = node->wake_time.tv_sec - curr_time.tv_sec;
	if (node->wake_time.tv_nsec < curr_time.tv_nsec) {
		delay_time->tv_nsec += 1000 * 1000 * 1000;
		delay_time->tv_sec -= 1;
	}

	return false;
}

static struct timespec dispatch_queue(delay_ctx_t *ctx)
{
	struct timespec sleep_time = { 0, 1000 * 1000 };
	while (true) {
		queue_node_t *node = knotd_lockless_queue_dequeue(ctx->queue);
		if (node == NULL) {
			break;
		}

		/* Should be the last call on the object or memory.
		 * Further access to node, qdata or mm will result in race condition as network
		 * thread can processs and cleanup */
		if (node->is_in_state) {
			node->qdata->async_in_completed(node->qdata, node->return_state);
		} else {
			node->qdata->async_completed(node->qdata, node->return_state);
		}
	}

	return sleep_time;
}

static void *dispatch_thread(void *d)
{
	delay_ctx_t *ctx = d;
	while (!ctx->exit) {
		queue_node_t *node = knotd_lockless_queue_dequeue(ctx->queue);
		if (node == NULL) {
			struct timespec tenth_ms = { 0, 100000 };
			nanosleep(&tenth_ms, &tenth_ms);
			continue;
		} else {
			struct timespec delay_time;
			if (!check_time(node, &delay_time)) {
				nanosleep(&delay_time, &delay_time);
			}
		}

		/* Should be the last call on the object or memory.
		 * Further access to node, qdata or mm will result in race condition as network
		 * thread can processs and cleanup */
		if (node->is_in_state) {
			node->qdata->async_in_completed(node->qdata, node->return_state);
		} else {
			node->qdata->async_completed(node->qdata, node->return_state);
		}
	}

	return d;
}

static void free_delay_ctx(delay_ctx_t *ctx)
{
	ctx->exit = true;
	for (int i = 0; i < ctx->thread_count; i++) {
		void *retval;
		pthread_join(ctx->dispatch_thread[i], &retval);
	}
	dispatch_queue(ctx);
	knotd_lockless_queue_delete(ctx->queue);
	free(ctx);
}

int delay_load(knotd_mod_t *mod)
{
	knotd_conf_t threads = knotd_conf_mod(mod, MOD_THREADS);

	delay_ctx_t *ctx = calloc(1, sizeof(*ctx) + sizeof(pthread_t) * threads.single.integer);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	if (knotd_lockless_queue_create(&ctx->queue, 16 * 1024) != 0) {
		free(ctx);
		return KNOT_ENOMEM;
	}

	for (int i = 0; i < threads.single.integer; i++) {
		if (pthread_create(&ctx->dispatch_thread[i], NULL, dispatch_thread, ctx) != 0) {
			free_delay_ctx(ctx);
			return KNOT_ESYSTEM;
		}
		ctx->thread_count++;
	}

	knotd_conf_t conf = knotd_conf_mod(mod, MOD_DELAY);
	ctx->delay_ms = conf.single.integer;

	conf = knotd_conf_mod(mod, MOD_ALL);
	bool all = conf.single.boolean;

	knotd_mod_ctx_set(mod, ctx);

	knotd_mod_hook(mod, KNOTD_STAGE_END, delay_message);
	if (all) {
		knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, delay_message);
		knotd_mod_in_hook(mod, KNOTD_STAGE_PREANSWER, delay_message_in);
		knotd_mod_in_hook(mod, KNOTD_STAGE_NAME_LOOKUP, delay_message_in);
		knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, delay_message_in);
		knotd_mod_in_hook(mod, KNOTD_STAGE_AUTHORITY, delay_message_in);
		knotd_mod_in_hook(mod, KNOTD_STAGE_ADDITIONAL, delay_message_in);
	}

	return KNOT_EOK;
}

void delay_unload(knotd_mod_t *mod)
{
	delay_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx != NULL) {
		free_delay_ctx(ctx);
	}
}

KNOTD_MOD_API(delay, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              delay_load, delay_unload, delay_conf, NULL);
