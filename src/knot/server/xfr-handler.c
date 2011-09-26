#include <config.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <urcu.h>

#include "knot/common.h"
#include "knot/server/xfr-handler.h"
#include "libknot/nameserver/name-server.h"
#include "knot/other/error.h"
#include "knot/server/socket.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "libknot/updates/xfr-in.h"
#include "knot/server/zones.h"
#include "libknot/util/error.h"
#include "common/evsched.h"

void xfr_interrupt(xfrhandler_t *h)
{
	for(unsigned i = 0; i < h->unit->size; ++i) {
		evqueue_write(h->workers[i]->q, "", 1);
	}
}

/*!
 * \brief SOA query timeout handler.
 */
static int xfr_udp_timeout(event_t *e)
{
	knot_ns_xfr_t *data = (knot_ns_xfr_t *)e->data;
	if (!data) {
		return KNOTD_EINVAL;
	}

	sockaddr_update(&data->addr);
	char r_addr[SOCKADDR_STRLEN];
	sockaddr_tostr(&data->addr, r_addr, sizeof(r_addr));
	int r_port = sockaddr_portnum(&data->addr);

	/* Close socket. */
	log_zone_info("%s query to %s:%d - timeout exceeded.\n",
		      data->type == XFR_TYPE_SOA ? "SOA" : "NOTIFY",
		      r_addr, r_port);
	knot_ns_xfr_t cr = {};
	cr.type = XFR_TYPE_CLOSE;
	cr.session = data->session;
	cr.data = data;
	xfrworker_t *w = (xfrworker_t *)data->owner;
	if (w) {
		evqueue_write(w->q, &cr, sizeof(knot_ns_xfr_t));
	}

	return KNOTD_EOK;
}

/*!
 * \brief Query reponse event handler function.
 *
 * Handle single query response event.
 *
 * \param loop Associated event pool.
 * \param w Associated socket watcher.
 * \param revents Returned events.
 */
static int xfr_process_udp_query(xfrworker_t *w, int fd, knot_ns_xfr_t *data)
{
	/* Prepare msg header. */
	struct msghdr msg;
	memset(&msg, 0, sizeof(struct msghdr));
	struct iovec iov;
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = data->wire;
	iov.iov_len = data->wire_size;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = data->addr.ptr;
	msg.msg_namelen = data->addr.len;

	/* Receive msg. */
	ssize_t n = recvmsg(data->session, &msg, 0);
	size_t resp_len = data->wire_size;
	if (n > 0) {
		dbg_xfr("xfr: processing UDP query response\n");
		udp_handle(data->wire, n, &resp_len, &data->addr, w->ns);
	}

	/* Disable timeout. */
	evsched_t *sched =
		((server_t *)knot_ns_get_data(w->ns))->sched;
	event_t *ev = (event_t *)data->data;
	if (ev) {
		dbg_xfr("xfr: cancelling UDP query timeout\n");
		evsched_cancel(sched, ev);
		ev = (event_t *)data->data;
		if (ev) {
			evsched_event_free(sched, ev);
			data->data = 0;
		}
	}

	/* Close after receiving response. */
	dbg_xfr("xfr: UDP query response processed\n");
	return KNOTD_ECONNREFUSED;
}

/*! \todo Document me. */
static void xfr_free_task(knot_ns_xfr_t *task)
{
	xfrworker_t *w = (xfrworker_t *)task->owner;
	if (!w) {
		free(task);
		return;
	}
	
	/* Remove from fdset. */
	if (w->fdset) {
		dbg_xfr("xfr_free_task: freeing fd=%d.\n", task->session);
		fdset_remove(w->fdset, task->session);
	}
	
	/* Unlock if XFR/IN.*/
	if (task->type == XFR_TYPE_AIN || task->type == XFR_TYPE_IIN) {
		knot_zone_t *zone = task->zone;
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		if (zd) {
			zd->xfr_in.wrkr = 0;
			pthread_mutex_unlock(&zd->xfr_in.lock);
		}
	}

	/* Remove fd-related data. */
	xfrhandler_t *h = w->master;
	pthread_mutex_lock(&h->tasks_mx);
	skip_remove(h->tasks, (void*)((size_t)task->session), 0, 0);
	pthread_mutex_unlock(&h->tasks_mx);

	/*! \todo Free data. */
	close(task->session);
	free(task);
}

/*! \todo Document me. */
static knot_ns_xfr_t *xfr_register_task(xfrworker_t *w, knot_ns_xfr_t *req)
{
	knot_ns_xfr_t *t = malloc(sizeof(knot_ns_xfr_t));
	if (!t) {
		return 0;
	}

	memcpy(t, req, sizeof(knot_ns_xfr_t));
	sockaddr_update(&t->addr);

	/* Update request. */
	t->wire = 0; /* Invalidate shared buffer. */
	t->wire_size = 0;
	t->data = 0; /* New zone will be built. */

	/* Register data. */
	xfrhandler_t * h = w->master;
	pthread_mutex_lock(&h->tasks_mx);
	skip_insert(h->tasks, (void*)((ssize_t)t->session), t, 0);
	pthread_mutex_unlock(&h->tasks_mx);

	/* Add to set. */
	fdset_add(w->fdset, t->session, OS_EV_READ);
	t->owner = w;
	return t;
}

/*!
 * \brief Finalize XFR/IN transfer.
 *
 * \param w XFR worker.
 * \param data Associated data.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_ERROR
 */
static int xfr_xfrin_finalize(xfrworker_t *w, knot_ns_xfr_t *data)
{
	knot_zone_t *zone = (knot_zone_t *)data->zone;
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	const char *zorigin = zd->conf->name;
	
	int ret = KNOTD_EOK;
	
	switch(data->type) {
	case XFR_TYPE_AIN:
		dbg_xfr("xfr: AXFR/IN saving new zone\n");
		ret = zones_save_zone(data);
		if (ret != KNOTD_EOK) {
			knot_zone_contents_deep_free(
			    (knot_zone_contents_t **)&data->data);
			data->data = 0;
			log_zone_error("AXFR failed to save "
			               "transferred zone '%s/IN' - %s\n",
			               zorigin, knotd_strerror(ret));
		} else {
			dbg_xfr("AXFR/IN new zone saved.\n");
			ret = knot_ns_switch_zone(w->ns, data);
			if (ret != KNOTD_EOK) {
				log_zone_error("AXFR failed to "
				               "switch in-memory zone "
				               "'%s/IN' - %s\n",
				               zorigin,
				               knotd_strerror(ret));
			}
		}
		log_zone_info("AXFR transfer of zone '%s/IN' "
		              "%s.\n", zorigin,
		              ret == KNOTD_EOK ? "finished" : "failed");
		break;
	case XFR_TYPE_IIN:
		/* Save changesets. */
		dbg_xfr("xfr: IXFR/IN saving changesets\n");
		ret = zones_store_changesets(data);
		if (ret != KNOTD_EOK) {
			log_zone_error("IXFR failed to save "
			               "transferred changesets "
			               "for zone '%s/IN' - %s\n",
			               zorigin, knotd_strerror(ret));
		} else {
			/* Update zone. */
			ret = zones_apply_changesets(data);
			if (ret != KNOTD_EOK) {
				log_zone_error("IXFR failed to "
				               "apply changesets to "
				               "zone '%s/IN' - %s\n",
				               zorigin, 
				               knotd_strerror(ret));
			}
		}
		/* Free changesets, but not the data. */
		knot_changesets_t *chs = (knot_changesets_t *)data->data;
		free(chs->sets);
		free(chs);
		data->data = 0;
		log_zone_info("IXFR transfer of zone '%s/IN' "
		              "%s.\n", zorigin,
		              ret == KNOTD_EOK ? "finished" : "failed");
		break;
	default:
		ret = KNOTD_EINVAL;
		break;
	}
	
	return ret;
}

/*!
 * \brief XFR-IN event handler function.
 *
 * Handle single XFR client event.
 *
 * \param w Associated XFR worker.
 * \param fd Associated file descriptor.
 * \param data Transfer data.
 */
int xfr_process_event(xfrworker_t *w, int fd, knot_ns_xfr_t *data)
{
	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Update xfer state. */
	data->wire = buf;
	data->wire_size = sizeof(buf);

	/* Handle SOA/NOTIFY responses. */
	if (data->type == XFR_TYPE_NOTIFY || data->type == XFR_TYPE_SOA) {
		return xfr_process_udp_query(w, fd, data);
	}

	/* Read DNS/TCP packet. */
	int ret = tcp_recv(fd, buf, sizeof(buf), 0);
	if (ret <= 0) {
		dbg_xfr("xfr: recv() failed, ret=%d\n", fd);
		return KNOTD_ERROR;
	}
	data->wire_size = ret;

	/* Process incoming packet. */
	switch(data->type) {
	case XFR_TYPE_AIN:
		ret = knot_ns_process_axfrin(w->ns, data);
		break;
	case XFR_TYPE_IIN:
		ret = knot_ns_process_ixfrin(w->ns, data);
		break;
	default:
		ret = KNOT_EBADARG;
		break;
	}

	/* AXFR-style IXFR. */
	if (ret == KNOT_ENOIXFR) {
		dbg_xfr("xfr: Fallback to AXFR.\n");
		assert(data->type == XFR_TYPE_IIN);
		data->type = XFR_TYPE_AIN;
		ret = knot_ns_process_axfrin(w->ns, data);
	}

	/* Check return code for errors. */
	dbg_xfr_verb("xfr: processed incoming XFR packet (res =  %d)\n", ret);
	
	/* Finished xfers. */
	int xfer_finished = 0;
	if (ret != KNOT_EOK) {
		xfer_finished = 1;
	}

	/* Handle errors. */
	if (ret < 0 && ret != KNOT_ENOXFR) {
		log_server_error("%cXFR/IN request failed - %s\n",
		                 data->type == XFR_TYPE_AIN ? 'A' : 'I',
		                 knot_strerror(ret));
	}


	/* Check finished zone. */
	if (xfer_finished) {
		
		knot_zone_t *zone = (knot_zone_t *)data->zone;
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		const char *zorigin = zd->conf->name;

		/* Only for successful xfers. */
		if (ret > 0) {
			ret = xfr_xfrin_finalize(w, data);
			
			/* AXFR bootstrap timeout. */
			rcu_read_lock();
			if (!knot_zone_contents(zone) && data->type == XFR_TYPE_AIN) {
				/* Schedule request (60 - 90s random delay). */
				int tmr_s = AXFR_BOOTSTRAP_RETRY;
				tmr_s += (30.0 * 1000) * (rand() / (RAND_MAX + 1.0));
				zd->xfr_in.bootstrap_retry = tmr_s;
				log_zone_info("Another attempt to AXFR bootstrap "
				              "zone '%s' in %d seconds.\n",
				              zorigin, tmr_s/1000);
			}
			rcu_read_unlock();
			
			/* Update timers. */
			server_t *server = (server_t *)knot_ns_get_data(w->ns);
			zones_timers_update(zone, zd->conf, server->sched);
			
		} else {
			/*! \todo May need some cleanup to prevent leaks. */
		}
		
		/* Disconnect. */
		ret = KNOTD_ECONNREFUSED; /* Make it disconnect. */
	} else {
		ret = KNOTD_EOK;
	}

	return ret;
}

/*! \todo Document me.
 */
static int xfr_client_start(xfrworker_t *w, knot_ns_xfr_t *data)
{
	/* Fetch associated zone. */
	knot_zone_t *zone = (knot_zone_t *)data->zone;
	if (!zone) {
		return KNOTD_EINVAL;
	}
	
	/* Check if not already processing. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd) {
		return KNOTD_EINVAL;
	}
	
	/* Enqueue to worker that has zone locked for XFR/IN. */
	int ret = pthread_mutex_trylock(&zd->xfr_in.lock);
	if (ret < 0) {
		dbg_xfr("xfr_client_start: switching to another thread, zones"
		        "is already in transfer\n");
		xfrworker_t *nextw = (xfrworker_t *)zd->xfr_in.wrkr;
		assert(nextw != w);
		evqueue_write(nextw->q, data, sizeof(knot_ns_xfr_t));
		return KNOTD_EBUSY;
	} else {
		zd->xfr_in.wrkr = w;
	}

	/* Update address. */
	sockaddr_update(&data->addr);
	char r_addr[SOCKADDR_STRLEN];
	sockaddr_tostr(&data->addr, r_addr, sizeof(r_addr));
	int r_port = sockaddr_portnum(&data->addr);

	/* Connect to remote. */
	if (data->session <= 0) {
		int fd = socket_create(data->addr.family, SOCK_STREAM);
		if (fd < 0) {
			log_server_warning("Failed to create socket "
					   "(type=%s, family=%s).\n",
					   "SOCK_STREAM",
					   data->addr.family == AF_INET ?
					   "AF_INET" : "AF_INET6");
			return KNOTD_ERROR;
		}
		ret = connect(fd, data->addr.ptr, data->addr.len);
		if (ret < 0) {
			log_server_warning("Failed to connect to %cXFR master "
					   "at %s:%d.\n",
					   data->type == XFR_TYPE_AIN ? 'A' : 'I',
					   r_addr, r_port);
			if (!knot_zone_contents(zone)) {
				/* Reschedule request (120 - 240s random delay). */
				int tmr_s = AXFR_BOOTSTRAP_RETRY * 2; /* Malus x2 */
				tmr_s += (int)((120.0 * 1000) * 
				               (rand() / (RAND_MAX + 1.0)));
				event_t *ev = zd->xfr_in.timer;
				if (ev) {
					evsched_cancel(ev->parent, ev);
					evsched_schedule(ev->parent, ev, tmr_s);
				}
				log_zone_notice("Zone AXFR bootstrap failed, "
				                "another attempt in %d seconds."
				                "\n", tmr_s / 1000);
			}
			return KNOTD_ERROR;
		}

		/* Store new socket descriptor. */
		data->session = fd;
	} else {
		/* Duplicate existing socket descriptor. */
		data->session = dup(data->session);
	}

	/* Fetch zone contents. */
	rcu_read_lock();
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	if (!contents && data->type == XFR_TYPE_IIN) {
		rcu_read_unlock();
		log_server_warning("Failed start IXFR on zone with no "
				   "contents\n");
		return KNOTD_ERROR;
	}

	/* Create XFR query. */
	size_t bufsize = data->wire_size;
	switch(data->type) {
	case XFR_TYPE_AIN:
		ret = xfrin_create_axfr_query(zone->name, data->wire, &bufsize);
		break;
	case XFR_TYPE_IIN:
		ret = xfrin_create_ixfr_query(contents, data->wire, &bufsize);
		break;
	default:
		ret = KNOTD_EINVAL;
		break;
	}

	/* Handle errors. */
	if (ret != KNOTD_EOK) {
		dbg_xfr("xfr: failed to create XFR query type %d\n",
		        data->type);
		return ret;
	}

	/* Send XFR query. */
	log_server_info("%cXFR transfer of zone '%s/IN' with %s:%d started.\n",
			data->type == XFR_TYPE_AIN ? 'A' : 'I',
	                zd->conf->name,
			r_addr, r_port);
	
	/* Unlock zone contents. */
	rcu_read_unlock();
	
	ret = data->send(data->session, &data->addr, data->wire, bufsize);
	if (ret != bufsize) {
		log_server_notice("Failed to send %cXFR query.",
				  data->type == XFR_TYPE_AIN ? 'A' : 'I');
		return KNOTD_ERROR;
	}

	/* Add to pending transfers. */
	xfr_register_task(w, data);
	return KNOTD_EOK;
}

static int xfr_fd_compare(void *k1, void *k2)
{
	if (k1 < k2) {
		return -1;
	}
	
	if (k1 > k2) {
		return 1;
	}
	
	return 0;
}

/*
 * Public APIs.
 */

static xfrworker_t* xfr_worker_create(xfrhandler_t *h, knot_nameserver_t *ns)
{
	xfrworker_t *w = malloc(sizeof(xfrworker_t));
	if(!w) {
		return 0;
	}
	
	/* Set nameserver and master. */
	w->ns = ns;
	w->master = h;
	
	/* Create event queue. */
	w->q = evqueue_new();
	if (!w->q) {
		free(w);
		return 0;
	}
	
	/* Create fdset. */
	w->fdset = fdset_new();
	if (!w->fdset) {
		evqueue_free(&w->q);
		free(w);
		return 0;
	}
	
	/* Add evqueue to fdset. */
	fdset_add(w->fdset, evqueue_pollfd(w->q), OS_EV_READ);
	
	return w;
}

static void xfr_worker_free(xfrworker_t *w) {
	if (w) {
		evqueue_free(&w->q);
		fdset_destroy(w->fdset);
		free(w);
	}
}

xfrhandler_t *xfr_create(size_t thrcount, knot_nameserver_t *ns)
{
	/* Create XFR handler data. */
	xfrhandler_t *data = malloc(sizeof(xfrhandler_t));
	if (!data) {
		return 0;
	}
	memset(data, 0, sizeof(xfrhandler_t));
	
	/* Create RR mutex. */
	pthread_mutex_init(&data->rr_mx, 0);

	/* Create tasks structure and mutex. */
	pthread_mutex_init(&data->tasks_mx, 0);
	data->tasks = skip_create_list(xfr_fd_compare);
	
	/* Initialize threads. */
	data->workers = malloc(thrcount * sizeof(xfrhandler_t*));
	if(data->workers == 0) {
		pthread_mutex_destroy(&data->rr_mx);
		free(data);
	}
	
	/* Create threading unit. */
	dt_unit_t *unit = dt_create(thrcount);
	if (!unit) {
		pthread_mutex_destroy(&data->rr_mx);
		free(data->workers);
		free(data);
		return 0;
	}
	data->unit = unit;
	
	/* Create worker threads. */
	unsigned initialized = 0;
	for (unsigned i = 0; i < thrcount; ++i) {
		data->workers[i] = xfr_worker_create(data, ns);
		if(data->workers[i] == 0) {
			break;
		}
		++initialized;
	}
	
	/* Check for initialized. */
	if (initialized != thrcount) {
		for (unsigned i = 0; i < initialized; ++i) {
			xfr_worker_free(data->workers[i]);
		}
		pthread_mutex_destroy(&data->rr_mx);
		free(data->workers);
		free(data->unit);
		free(data);
		return 0;
	}
	
	/* Assign worker threads. */
	for (unsigned i = 0; i < thrcount; ++i) {
		dt_repurpose(unit->threads[i], xfr_worker, data->workers[i]);
	}
	
	data->interrupt = xfr_interrupt;

	return data;
}

int xfr_free(xfrhandler_t *handler)
{
	if (!handler) {
		return KNOTD_EINVAL;
	}
	
	/* Free RR mutex. */
	pthread_mutex_destroy(&handler->rr_mx);

	/* Free tasks and mutex. */
	skip_destroy_list(&handler->tasks, 0,
	                  (void(*)(void*))xfr_free_task);
	pthread_mutex_destroy(&handler->tasks_mx);
	
	/* Free workers. */
	for (unsigned i = 0; i < handler->unit->size; ++i) {
		xfr_worker_free(handler->workers[i]);
	}
	free(handler->workers);

	/* Delete unit. */
	dt_delete(&handler->unit);
	free(handler);

	return KNOTD_EOK;
}

int xfr_stop(xfrhandler_t *handler)
{
	/* Break loop. */
	dt_stop(handler->unit);
	return KNOTD_EOK;
}

int xfr_join(xfrhandler_t *handler) {
	return dt_join(handler->unit);
}

int xfr_request(xfrhandler_t *handler, knot_ns_xfr_t *req)
{
	if (!handler || !req) {
		return KNOTD_EINVAL;
	}
	
	/* Get next worker in RR fashion */
	pthread_mutex_lock(&handler->rr_mx);
	evqueue_t *q = handler->workers[handler->rr]->q;
	handler->rr = get_next_rr(handler->rr, handler->unit->size);
	pthread_mutex_unlock(&handler->rr_mx);

	/* Delegate request. */
	int ret = evqueue_write(q, req, sizeof(knot_ns_xfr_t));
	if (ret < 0) {
		return KNOTD_ERROR;
	}

	return KNOTD_EOK;
}

static int xfr_process_request(xfrworker_t *w, uint8_t *buf, size_t buflen)
{
	/* Read single request. */
	knot_ns_xfr_t xfr = {};
	int ret = evqueue_read(w->q, &xfr, sizeof(knot_ns_xfr_t));
	if (ret != sizeof(knot_ns_xfr_t)) {		
		dbg_xfr("xfr_process_request: queue read returned %d.\n", ret);
		return KNOTD_ENOTRUNNING;
	}

	/* Update request. */
	sockaddr_update(&xfr.addr);
	xfr.wire = buf;
	xfr.wire_size = buflen;
	char r_addr[SOCKADDR_STRLEN];
	sockaddr_tostr(&xfr.addr, r_addr, sizeof(r_addr));
	int r_port = sockaddr_portnum(&xfr.addr);

	/* Handle request. */
	knot_ns_xfr_t *task = 0;
	evsched_t *sch = 0;
	const char *req_type = "";
	knot_rcode_t rcode = 0;
	knot_zone_t *zone = xfr.zone;
	zonedata_t *zd = zone->data;
	
	dbg_xfr("xfr_process_request: request type %d.\n", xfr.type);
	switch(xfr.type) {
	case XFR_TYPE_AOUT:
		req_type = "AXFR/OUT";
		
		ret = knot_ns_init_xfr(w->ns, &xfr);
		if (ret != KNOT_EOK) {
			log_server_notice("AXFR transfer of zone '%s/OUT' "
			                  "%s:%d - initialization failed: %s\n",
			                  zd->conf->name,
					  r_addr, r_port,
					  knot_strerror(ret));
			socket_close(xfr.session);
		}

		int init_failed = ret != KNOT_EOK;
		ret = zones_xfr_check_zone(&xfr, &rcode);
		if (ret != KNOTD_EOK) {
			if (!init_failed) {
				knot_ns_xfr_send_error(&xfr, rcode);
				socket_close(xfr.session);
				log_server_notice("AXFR transfer of zone '%s/OUT' "
				                  "%s:%d - check failed: %s\n",
				                  zd->conf->name,
						  r_addr, r_port,
						  knotd_strerror(ret));
			}
		} else {

			ret = knot_ns_answer_axfr(w->ns, &xfr);
			dbg_xfr("xfr_master: ns_answer_axfr() = %d.\n", ret);
			if (ret != KNOTD_EOK) {
				socket_close(xfr.session);
			} else {
				log_server_info("AXFR transfer of zone '%s/OUT' "
						"to %s:%d successful.\n",
				                zd->conf->name,
						r_addr, r_port);
			}
		}
		
		free(xfr.query->wireformat);
		xfr.query->wireformat = 0;
		knot_packet_free(&xfr.query); /* Free query. */
		break;
	case XFR_TYPE_IOUT:
		req_type = "IXFR/OUT";
		
		ret = knot_ns_init_xfr(w->ns, &xfr);
		if (ret != KNOT_EOK) {
			dbg_xfr("xfr: failed to init XFR: %s\n",
			          knotd_strerror(ret));
			socket_close(xfr.session);
		}
		
		ret = zones_xfr_check_zone(&xfr, &rcode);
		if (ret != KNOTD_EOK) {
			knot_ns_xfr_send_error(&xfr, rcode);
			socket_close(xfr.session);
		}
		
		ret = zones_xfr_load_changesets(&xfr);
		if (ret != KNOTD_EOK) {
			knot_ns_xfr_send_error(&xfr, KNOT_RCODE_SERVFAIL);
			socket_close(xfr.session);
		}
		
		ret = knot_ns_answer_ixfr(w->ns, &xfr);
		free(xfr.query->wireformat);
		knot_packet_free(&xfr.query); /* Free query. */
		dbg_xfr("xfr: ns_answer_ixfr() = %d.\n", ret);
		if (ret != KNOTD_EOK) {
			socket_close(xfr.session);
		} else{
			log_server_info("IXFR transfer of zone '%s/OUT'"
					"to %s:%d successful.\n",
			                zd->conf->name,
					r_addr, r_port);
		}
		break;
	case XFR_TYPE_AIN:
	case XFR_TYPE_IIN:
		req_type = "AXFR/IN";
		if (xfr.type == XFR_TYPE_IIN) {
			req_type = "IXFR/IN";
		}
		
		xfr_client_start(w, &xfr);
		ret = KNOTD_EOK;
		break;
	case XFR_TYPE_SOA:
	case XFR_TYPE_NOTIFY:
		/* Register task. */
		task = xfr_register_task(w, &xfr);
		if (!task) {
			ret = KNOTD_ENOMEM;
			break;
		}

		req_type = "SOA or NOTIFY";
		dbg_xfr("xfr: waiting for %s query response\n",
			  xfr.type == XFR_TYPE_SOA ? "SOA" : "NOTIFY");

		/* Add timeout. */
		sch = ((server_t *)knot_ns_get_data(w->ns))->sched;
		task->data = evsched_schedule_cb(sch, xfr_udp_timeout,
						 task, SOA_QRY_TIMEOUT);
		ret = KNOTD_EOK;
		break;
	/* Socket close event. */
	case XFR_TYPE_CLOSE:
		xfr_free_task((knot_ns_xfr_t *)xfr.data);
		return KNOTD_EOK;
	default:
		break;
	}

	/* Report. */
	if (ret != KNOTD_EOK && ret != KNOTD_EACCES) {
		log_server_error("%s request from %s:%d failed: %s\n",
				 req_type, r_addr, r_port,
				 knotd_strerror(ret));
	}
	
	return ret;
}

int xfr_worker(dthread_t *thread)
{
	xfrworker_t *w = (xfrworker_t *)thread->data;	

	/* Check data. */
	if (w < 0) {
		dbg_xfr("xfr_worker: NULL worker data, finishing.\n");
		return KNOTD_EINVAL;
	}

	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Accept requests. */
	int ret = 0;
	dbg_xfr("xfr_worker: thread started.\n");
	for (;;) {
		
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}
		
		/* Poll fdset. */
		int nfds = fdset_wait(w->fdset);
		if (nfds <= 0) {
			continue;
		}
		
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}
		
		/* Iterate fdset. */
		xfrhandler_t *h = w->master;
		knot_ns_xfr_t *data = 0;
		int rfd = evqueue_pollfd(w->q);
		fdset_it_t it;
		fdset_begin(w->fdset, &it);
		while(1) {
			
			/* Check if it request. */
			if (it.fd == rfd) {
				dbg_xfr("xfr_worker: processing request\n");
				ret = xfr_process_request(w, buf, sizeof(buf));
				if (ret == KNOTD_ENOTRUNNING) {
					break;
				}
			} else {
				/* Find data. */
				pthread_mutex_lock(&h->tasks_mx);
				data = skip_find(h->tasks, (void*)((size_t)it.fd));
				pthread_mutex_unlock(&h->tasks_mx);
				dbg_xfr_verb("xfr_worker: processing event on "
				             "fd=%d data=%p.\n", it.fd, data);
				ret = xfr_process_event(w, it.fd, data);
				if (ret != KNOTD_EOK) {
					xfr_free_task(data);
				}
			}
			
			/* Next fd. */
			if (fdset_next(w->fdset, &it) < 0) {
				break;
			}
		}
	}


	/* Stop whole unit. */
	dbg_xfr("xfr_worker: finished.\n");
	thread->data = 0;
	return KNOTD_EOK;
}
