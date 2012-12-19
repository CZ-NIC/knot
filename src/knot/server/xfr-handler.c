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
#include <unistd.h>
#include <fcntl.h>
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
#include "knot/server/socket.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "libknot/updates/xfr-in.h"
#include "libknot/util/wire.h"
#include "knot/server/zones.h"
#include "libknot/tsig-op.h"
#include "common/evsched.h"
#include "common/prng.h"

/* Constants */
#define XFR_SWEEP_INTERVAL 2 /*! [seconds] between sweeps. */
#define XFR_BUFFER_SIZE 65535 /*! Do not change this - maximum value for UDP packet length. */
#define XFR_MSG_DLTTR 9 /*! Index of letter differentiating IXFR/AXFR in log msg. */

/*! \brief Send interrupt to all workers. */
void xfr_interrupt(xfrhandler_t *h)
{
	for(unsigned i = 0; i < h->unit->size; ++i) {
		evqueue_t *q = h->workers[i]->q;
		if (evqueue_write(q, "", 1) == 1) {
			close(q->fds[EVQUEUE_WRITEFD]);
			q->fds[EVQUEUE_WRITEFD] = -1;
		} else {
			dt_stop_id(h->unit->threads[i]);
		}
	}
}

/*! \brief Deinitialize allocated values from xfer descriptor. */
static void xfr_request_deinit(knot_ns_xfr_t *r)
{
	if (r) {
		free(r->msgpref);
		r->msgpref = NULL;
	}
}

/*!
 * \brief Clean pending transfer data.
 */
static int xfr_xfrin_cleanup(xfrworker_t *w, knot_ns_xfr_t *data)
{
	int ret = KNOT_EOK;
	knot_changesets_t *chs = 0;

	dbg_xfr_verb("Cleaning up after XFR-in.\n");
	
	switch(data->type) {
	case XFR_TYPE_AIN:
		if (data->flags & XFR_FLAG_AXFR_FINISHED) {
			knot_zone_contents_deep_free(
				&data->new_contents, 1);
		} else {
			if (data->data) {
				xfrin_constructed_zone_t *constr_zone =
					(xfrin_constructed_zone_t *)data->data;
				knot_zone_contents_deep_free(
						&(constr_zone->contents), 0);
				xfrin_free_orphan_rrsigs(&(constr_zone->rrsigs));
				free(data->data);
				data->data = 0;
			}
		}
		break;
	case XFR_TYPE_IIN:
		if (data->data) {
			chs = (knot_changesets_t *)data->data;
			knot_free_changesets(&chs);
			data->data = NULL;
		}

		// this function is called before new contents are created
		assert(data->new_contents == NULL);

		break;
	}

	/* Cleanup other data - so that the structure may be reused. */
	data->packet_nr = 0;
	data->tsig_data_size = 0;

	dbg_xfr_detail("Done.\n");
	
	return ret;
}

/*! \brief Free allocated xfer descriptor (also deinitializes). */
static void xfr_free_task(knot_ns_xfr_t *task)
{
	if (!task) {
		return;
	}
	
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
	int is_xfer = task->type == XFR_TYPE_AIN || task->type == XFR_TYPE_IIN;
	if (is_xfer) {
		knot_zone_t *zone = task->zone;
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		if (zd) {
			zd->xfr_in.wrkr = 0;
			pthread_mutex_unlock(&zd->xfr_in.lock);
		}
	}
	
	/* Free TSIG buffers. */
	if (task->digest) {
		free(task->digest);
		task->digest = NULL;
		task->digest_size = 0;
	}
	if (task->tsig_data) {
		free(task->tsig_data);
		task->tsig_data = NULL;
		task->tsig_data_size = 0;
	}
	
	if (!task->session_closed) {
		/* Cleanup pending request. */
		if (is_xfer) {
			xfr_xfrin_cleanup(w, task);
		}
		
		/* Remove fd-related data. */
		xfrhandler_t *h = w->master;
		pthread_mutex_lock(&h->tasks_mx);
		skip_remove(h->tasks, (void*)((size_t)task->session), 0, 0);
		pthread_mutex_unlock(&h->tasks_mx);
		close(task->session);
	}
	
	/* No further access to zone. */
	knot_zone_release(task->zone);
	
	/* Deinitialize */
	xfr_request_deinit(task);
	free(task);
}

/*!
 * \brief Return xfer descriptor associated with given fd.
 *
 * \param w Current worker.
 * \param fd Requested descriptor.
 *
 * \retval xfer descriptor if found.
 * \retval NULL if no descriptor found.
 */
static knot_ns_xfr_t *xfr_handler_task(xfrworker_t *w, int fd)
{
	xfrhandler_t *h = w->master;
	pthread_mutex_lock(&h->tasks_mx);
	knot_ns_xfr_t *data = skip_find(h->tasks, (void*)((size_t)fd));
	pthread_mutex_unlock(&h->tasks_mx);
	
	if (data == NULL) {
		dbg_xfr_verb("xfr: worker=%p processing event on "
			     "fd=%d got empty data.\n",
			     w, fd);
		fdset_remove(w->fdset, fd);
		close(fd); /* Always dup()'d or created. */
		return NULL;
	}
	
	return data;
}

/*!
 * \brief SOA query timeout handler.
 */
static int xfr_udp_timeout(knot_ns_xfr_t *data)
{
	/* Close socket. */
	rcu_read_lock();
	knot_zone_t *z = data->zone;
	if (z && knot_zone_get_contents(z) && knot_zone_data(z)) {
		if (!(knot_zone_flags(z) & KNOT_ZONE_DISCARDED)) {
			log_zone_info("%s Failed, timeout exceeded.\n",
				      data->msgpref);
		}
	}
	rcu_read_unlock();
	
	/* Invalidate pending query. */
	xfr_free_task(data);
	return KNOT_EOK;
}

/*!
 * \brief Query response event handler function.
 *
 * Handle single query response event.
 *
 * \param loop Associated event pool.
 * \param w Associated socket watcher.
 * \param revents Returned events.
 */
static int xfr_process_udp_resp(xfrworker_t *w, int fd, knot_ns_xfr_t *data)
{
	/* Check if zone is valid. */
	int ret = KNOT_ECONNREFUSED;
	rcu_read_lock();
	if (knot_zone_flags(data->zone) & KNOT_ZONE_DISCARDED) {
		rcu_read_unlock();
		return KNOT_ECONNREFUSED;
	}
	rcu_read_unlock();
	
	/* Receive msg. */
	ssize_t n = -1;
	size_t resp_len = data->wire_size;
	if (data->flags & XFR_FLAG_TCP) {
		n = tcp_recv(data->session, data->wire, resp_len, &data->addr);
	} else {
		n = recvfrom(data->session, data->wire, resp_len,
		             0, data->addr.ptr, &data->addr.len);
	}
	
	if (n <= 0) {
		return ret;
	}

	// parse packet
	knot_packet_t *re = knot_packet_new(KNOT_PACKET_PREALLOC_RESPONSE);
	if (re == NULL) {
		return KNOT_ENOMEM;
	}
	
	knot_packet_type_t rt = KNOT_RESPONSE_NORMAL;
	ret = knot_ns_parse_packet(data->wire, n, re, &rt);
	if (ret != KNOT_EOK) {
		knot_packet_free(&re);
		return KNOT_EOK; /* Ignore */
	}

	/* Ignore other packets. */
	switch(rt) {
	case KNOT_RESPONSE_NORMAL:
	case KNOT_RESPONSE_NOTIFY:
	case KNOT_RESPONSE_UPDATE:
		break;
	default:
		knot_packet_free(&re);
		return KNOT_EOK; /* Ignore */
	}

	ret = knot_packet_parse_rest(re);
	if (ret != KNOT_EOK) {
		knot_packet_free(&re);
		return KNOT_EOK; /* Ignore */
	}
	
	// check TSIG
	const knot_rrset_t * tsig_rr = knot_packet_tsig(re);
	if (data->tsig_key != NULL) {
		/*! \todo Not sure about prev_time_signed, but this is the first
		 *        reply and we should pass query sign time as the time
		 *        may be different. Leaving to 0.
		 */
		ret = knot_tsig_client_check(tsig_rr, data->wire, n,
		                             data->digest, data->digest_size,
		                             data->tsig_key, 0);
		if (ret != KNOT_EOK) {
			log_server_error("%s %s\n",
			                 data->msgpref, knot_strerror(ret));
			knot_packet_free(&re);
			return KNOT_ECONNREFUSED;
		}
		
	}
	
	// process response
	size_t qlen = n;
	switch(rt) {
	case KNOT_RESPONSE_NORMAL:
		ret = zones_process_response(w->ns, &data->addr, re,
		                             data->wire, &resp_len);
		break;
	case KNOT_RESPONSE_NOTIFY:
		ret = notify_process_response(w->ns, re, &data->addr,
		                              data->wire, &resp_len);
		break;
	case KNOT_RESPONSE_UPDATE:
		ret = zones_process_update_response(data, data->wire, &qlen);
		if (ret == KNOT_EOK) {
			log_server_info("%s Forwarded response.\n",
			                data->msgpref);
		}
		break;
	default:
		break;
	}
	
	knot_packet_free(&re);
	
	/* Check up-to-date zone. */
	if (ret == KNOT_EUPTODATE) {
		log_server_info("%s %s\n", data->msgpref, knot_strerror(ret));
		ret = KNOT_ECONNREFUSED;
	}
	
	/* Invalidate pending query. */
	if (ret == KNOT_EOK) {
		ret = KNOT_ECONNREFUSED;
	}
	return ret;
}

/*! \brief Sweep non-replied connection. */
static void xfr_sweep(fdset_t *set, int fd, void *data)
{
	dbg_xfr("xfr: sweeping fd=%d\n", fd);
	
	if (!set || !data) {
		dbg_xfr("xfr: invalid sweep operation on NULL worker or set\n");
		return;
	}
	knot_ns_xfr_t *t = xfr_handler_task((xfrworker_t *)data, fd);
	if (!t) {
		dbg_xfr("xfr: NULL data to sweep\n");
		return;
	}
	
	/* Skip non-sweepable types. */
	switch(t->type) {
	case XFR_TYPE_SOA:
	case XFR_TYPE_NOTIFY:
	case XFR_TYPE_FORWARD:
		xfr_udp_timeout(t);
		break;
	default:
		dbg_xfr("xfr: sweep request on unsupported type\n");
		break;
	}
}

/*!
 * \brief Register task in given worker.
 * 
 * \warning Must be freed with xfr_free_task() when finished.
 *
 * \param w Given worker.
 * \param req Pointer to template xfer descriptor.
 *
 * \retval Newly allocated xfer descriptor if success.
 * \retval NULL on error.
 */
static knot_ns_xfr_t *xfr_register_task(xfrworker_t *w, const knot_ns_xfr_t *req)
{
	knot_ns_xfr_t *t = malloc(sizeof(knot_ns_xfr_t));
	if (!t) {
		return NULL;
	}

	memcpy(t, req, sizeof(knot_ns_xfr_t));
	sockaddr_update(&t->addr);
	sockaddr_update(&t->saddr);

	/* Update request. */
	t->wire = 0; /* Invalidate shared buffer. */
	t->wire_size = 0;
	t->data = 0; /* New zone will be built. */
	t->msgpref = strdup(t->msgpref); /* Copy message. */

	/* Register data. */
	xfrhandler_t * h = w->master;
	pthread_mutex_lock(&h->tasks_mx);
	int ret = skip_insert(h->tasks, (void*)((ssize_t)t->session), t, 0);
	pthread_mutex_unlock(&h->tasks_mx);

	/* Add to set. */
	if (ret == 0) {
		ret = fdset_add(w->fdset, t->session, OS_EV_READ);
	}
	/* Evaluate final return code. */
	if (ret == 0) {
		t->owner = w;
	} else {
		/* Attempt to remove from list anyway. */
		skip_remove(h->tasks, (void*)((ssize_t)t->session), NULL, NULL);
		free(t);
		t = NULL;
	}
	return t;
}

/*!
 * \brief Finalize XFR/IN transfer.
 *
 * \param w XFR worker.
 * \param data Associated data.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR
 */
static int xfr_xfrin_finalize(xfrworker_t *w, knot_ns_xfr_t *data)
{

	int ret = KNOT_EOK;
//	int apply_ret = KNOT_EOK;
	int switch_ret = KNOT_EOK;
	knot_changesets_t *chs = NULL;
//	journal_t *transaction = NULL;
	
	switch(data->type) {
	case XFR_TYPE_AIN:
		dbg_xfr("xfr: %s Saving new zone file.\n", data->msgpref);
		ret = zones_save_zone(data);
		if (ret != KNOT_EOK) {
			xfr_xfrin_cleanup(w, data);
			log_zone_error("%s Failed to save transferred zone - %s\n",
			               data->msgpref, knot_strerror(ret));
		} else {
			dbg_xfr("xfr: %s New zone saved.\n", data->msgpref);
			switch_ret = knot_ns_switch_zone(w->ns, data);
			if (switch_ret != KNOT_EOK) {
				log_zone_error("%s Failed to switch in-memory "
				               "zone - %s\n",  data->msgpref,
				               knot_strerror(switch_ret));
				xfr_xfrin_cleanup(w, data);
				ret = KNOT_ERROR;
			}
		}
		if (ret == KNOT_EOK) {
			log_zone_info("%s Finished.\n", data->msgpref);
		}
		break;
	case XFR_TYPE_IIN:
		chs = (knot_changesets_t *)data->data;
		ret = zones_store_and_apply_chgsets(chs, data->zone,
		                                    &data->new_contents,
		                                    data->msgpref, 
		                                    XFR_TYPE_IIN);
		data->data = NULL;
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	return ret;
}

/*!
 * \brief Check TSIG if exists.
 */
static int xfr_check_tsig(knot_ns_xfr_t *xfr, knot_rcode_t *rcode, char **tag)
{
	/* Parse rest of the packet. */
	int ret = KNOT_EOK;
	knot_packet_t *qry = xfr->query;
	knot_key_t *key = 0;
	const knot_rrset_t *tsig_rr = 0;
	ret = knot_packet_parse_rest(qry);
	if (ret == KNOT_EOK) {
		
		/* Find TSIG key name from query. */
		const knot_dname_t* kname = 0;
		int tsig_pos = knot_packet_additional_rrset_count(qry) - 1;
		if (tsig_pos >= 0) {
			tsig_rr = knot_packet_additional_rrset(qry, tsig_pos);
			if (knot_rrset_type(tsig_rr) == KNOT_RRTYPE_TSIG) {
				dbg_xfr("xfr: found TSIG in AR\n");
				kname = knot_rrset_owner(tsig_rr);
				if (tag) {
					*tag = knot_dname_to_str(kname);
					
				}
			} else {
				tsig_rr = 0;
			}
		}
		if (!kname) {
			dbg_xfr("xfr: TSIG not found in AR\n");
			char *name = knot_dname_to_str(
						knot_zone_name(xfr->zone));
			free(name);

			// return REFUSED
			xfr->tsig_key = 0;
			*rcode = KNOT_RCODE_REFUSED;
			return KNOT_EXFRDENIED;
		}
		if (tsig_rr) {
			tsig_algorithm_t alg = tsig_rdata_alg(tsig_rr);
			if (tsig_alg_digest_length(alg) == 0) {
				*rcode = KNOT_RCODE_NOTAUTH;
				xfr->tsig_key = NULL;
				xfr->tsig_rcode = KNOT_TSIG_RCODE_BADKEY;
				xfr->tsig_prev_time_signed =
				                tsig_rdata_time_signed(tsig_rr);
				return KNOT_TSIG_EBADKEY;
			}
		}

		/* Evaluate configured key for claimed key name.*/
		key = xfr->tsig_key; /* Expects already set key (check_zone) */
		xfr->tsig_key = 0;
		if (key && kname && knot_dname_compare(key->name, kname) == 0) {
			dbg_xfr("xfr: found claimed TSIG key for comparison\n");
		} else {
			
			/* TSIG is mandatory if configured for interface. */
			/* Configured, but doesn't match. */
			dbg_xfr("xfr: no claimed key configured or not received"
			        ", treating as bad key\n");
			*rcode = KNOT_RCODE_NOTAUTH;
			ret = KNOT_TSIG_EBADKEY;
			xfr->tsig_rcode = KNOT_TSIG_RCODE_BADKEY;
			key = 0; /* Invalidate, ret already set to BADKEY */
		}

		/* Validate with TSIG. */
		if (key) {
			/* Prepare variables for TSIG */
			xfr_prepare_tsig(xfr, key);
			
			/* Copy MAC from query. */
			dbg_xfr("xfr: validating TSIG from query\n");
			const uint8_t* mac = tsig_rdata_mac(tsig_rr);
			size_t mac_len = tsig_rdata_mac_length(tsig_rr);
			if (mac_len > xfr->digest_max_size) {
				ret = KNOT_EMALF;
				dbg_xfr("xfr: MAC length %zu exceeds digest "
					"maximum size %zu\n",
					mac_len, xfr->digest_max_size);
			} else {
				memcpy(xfr->digest, mac, mac_len);
				xfr->digest_size = mac_len;
				
				/* Check query TSIG. */
				ret = knot_tsig_server_check(
						tsig_rr,
						knot_packet_wireformat(qry),
						knot_packet_size(qry),
						key);
				dbg_xfr("knot_tsig_server_check() returned %s\n",
					knot_strerror(ret));
			}
			
			/* Evaluate TSIG check results. */
			switch(ret) {
			case KNOT_EOK:
				*rcode = KNOT_RCODE_NOERROR;
				break;
			case KNOT_TSIG_EBADKEY:
				xfr->tsig_rcode = KNOT_TSIG_RCODE_BADKEY;
				xfr->tsig_key = NULL;
				*rcode = KNOT_RCODE_NOTAUTH;
				break;
			case KNOT_TSIG_EBADSIG:
				xfr->tsig_rcode = KNOT_TSIG_RCODE_BADSIG;
				xfr->tsig_key = NULL;
				*rcode = KNOT_RCODE_NOTAUTH;
				break;
			case KNOT_TSIG_EBADTIME:
				xfr->tsig_rcode = KNOT_TSIG_RCODE_BADTIME;
				// store the time signed from the query
				assert(tsig_rr != NULL);
				xfr->tsig_prev_time_signed =
				                tsig_rdata_time_signed(tsig_rr);
				*rcode = KNOT_RCODE_NOTAUTH;
				break;
			case KNOT_EMALF:
				*rcode = KNOT_RCODE_FORMERR;
				break;
			default:
				*rcode = KNOT_RCODE_SERVFAIL;
			}
		}
	} else {
		dbg_xfr("xfr: failed to parse rest of the packet\n");
		*rcode = KNOT_RCODE_FORMERR;
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
int xfr_process_event(xfrworker_t *w, int fd, knot_ns_xfr_t *data, uint8_t *buf, size_t buflen)
{
	/* Update xfer state. */
	knot_zone_t *zone = (knot_zone_t *)data->zone;
	data->wire = buf;
	data->wire_size = buflen;

	/* Handle SOA/NOTIFY responses. */
	switch(data->type) {
	case XFR_TYPE_NOTIFY:
	case XFR_TYPE_SOA:
	case XFR_TYPE_FORWARD:
		return xfr_process_udp_resp(w, fd, data);
	default:
		break;
	}

	/* Read DNS/TCP packet. */
	int ret = 0;
	int rcvd = tcp_recv(fd, buf, buflen, 0);
	
	/* Raise read-lock and check if zone is still valid. */
	rcu_read_lock();
	int zone_discarded = (knot_zone_flags(zone) & KNOT_ZONE_DISCARDED);

	/* Handle incoming packet. */
	data->wire_size = rcvd;
	if (rcvd <= 0 || zone_discarded) {
		data->wire_size = 0;
		ret = KNOT_ECONN;
	} else {

		/* Process incoming packet. */
		switch(data->type) {
		case XFR_TYPE_AIN:
			ret = knot_ns_process_axfrin(w->ns, data);
			break;
		case XFR_TYPE_IIN:
			ret = knot_ns_process_ixfrin(w->ns, data);
			break;
		default:
			ret = KNOT_EINVAL;
			break;
		}
	}

	/* AXFR-style IXFR. */
	if (ret == KNOT_ENOIXFR) {
		assert(data->type == XFR_TYPE_IIN);
		log_server_notice("%s Fallback to AXFR.\n", data->msgpref);
		data->type = XFR_TYPE_AIN;
		data->msgpref[XFR_MSG_DLTTR] = 'A';
		ret = knot_ns_process_axfrin(w->ns, data);
	}

	/* Check return code for errors. */
	dbg_xfr_verb("xfr: processed incoming XFR packet (%s)\n",
	             knot_strerror(ret));
	
	/* Finished xfers. */
	int xfer_finished = 0;
	if (ret != KNOT_EOK) {
		xfer_finished = 1;
	}
	
	/* IXFR refused, try again with AXFR. */
	if (data->type == XFR_TYPE_IIN && ret == KNOT_EXFRREFUSED) {
		log_server_notice("%s Transfer failed, fallback to AXFR.\n",
				  data->msgpref);
		size_t bufsize = buflen;
		data->wire_size = buflen; /* Reset maximum bufsize */
		ret = xfrin_create_axfr_query(zone->name, data,
		                              &bufsize, 1);
		/* Send AXFR/IN query. */
		if (ret == KNOT_EOK) {
			ret = data->send(data->session, &data->addr,
			                 data->wire, bufsize);
			/* Switch to AIN type XFR and return now. */
			if (ret == bufsize) {
				rcu_read_unlock();
				xfr_xfrin_cleanup(w, data);
				data->type = XFR_TYPE_AIN;
				data->msgpref[XFR_MSG_DLTTR] = 'A';
				return KNOT_EOK;
			}
		}
	}
	
	rcu_read_unlock();

	/* Handle errors. */
	if (!zone_discarded) {
		if (ret == KNOT_ENOXFR) {
			log_server_warning("%s Finished, %s\n",
					   data->msgpref, knot_strerror(ret));
		} else if (ret < 0) {
			log_server_error("%s %s\n",
					 data->msgpref, knot_strerror(ret));
		}
	}

	/* Check finished zone. */
	int result = KNOT_EOK;
	if (xfer_finished) {
		
		/* Close early to free up fd for storing zone. */
		data->session_closed = 1;
		close(data->session);
		
		/* Remove fd-related data. */
		xfrhandler_t *h = w->master;
		pthread_mutex_lock(&h->tasks_mx);
		skip_remove(h->tasks, (void*)((size_t)data->session), 0, 0);
		pthread_mutex_unlock(&h->tasks_mx);
		
		knot_zone_t *zone = (knot_zone_t *)data->zone;
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);

		/* Only for successful xfers on non-discarded zones. */
		if (ret > 0 && !zone_discarded) {
			ret = xfr_xfrin_finalize(w, data);
			
			/* AXFR bootstrap timeout. */
			if (ret != KNOT_EOK && !knot_zone_contents(zone)) {
				/* Schedule request (60 - 90s random delay). */
				int tmr_s = AXFR_BOOTSTRAP_RETRY;
				tmr_s += (30.0 * 1000) * (tls_rand());
				zd->xfr_in.bootstrap_retry = tmr_s;
				log_zone_info("%s Next attempt to bootstrap "
				              "in %d seconds.\n",
				              data->msgpref, tmr_s / 1000);
			}

			/* Update timers. */
			server_t *server = (server_t *)knot_ns_get_data(w->ns);
			zones_timers_update(zone, zd->conf, server->sched);
		} else {
			/* Cleanup */
			xfr_xfrin_cleanup(w, data);
		}
		
		/* Disconnect. */
		result = KNOT_ECONNREFUSED; /* Make it disconnect. */
	}

	return result;
}

/*!
 * \brief Start incoming transfer (applicable to AXFR/IN or IXFR/IN).
 *
 * \warning xfer descriptor will be registered if successful.
 * \warning data->fd will be duplicated if successful.
 * 
 * \param w Given worker.
 * \param data xfer descriptor.
 */
static int xfr_client_start(xfrworker_t *w, knot_ns_xfr_t *data)
{
	/* Fetch associated zone. */
	knot_zone_t *zone = (knot_zone_t *)data->zone;
	if (!zone) {
		return KNOT_EINVAL;
	}
	
	/* Check if not already processing. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd) {
		return KNOT_EINVAL;
	}
	
	/* Enqueue to worker that has zone locked for XFR/IN. */
	int ret = pthread_mutex_trylock(&zd->xfr_in.lock);
	rcu_read_lock();
	if (ret != 0) {
		dbg_xfr_verb("xfr: XFR/IN switching to another thread, "
		             "zone '%s' is already in transfer\n",
		             zd->conf->name);
		xfrworker_t *nextw = (xfrworker_t *)zd->xfr_in.wrkr;
		if (nextw == 0) {
			nextw = w;
		}
		
		/* Free data updated in this processing. */
		ret = evqueue_write(nextw->q, data, sizeof(knot_ns_xfr_t));
		if (ret != sizeof(knot_ns_xfr_t)) {
			char ebuf[256] = {0};
			strerror_r(errno, ebuf, sizeof(ebuf));
			dbg_xfr("xfr: couldn't write request to evqueue: %s\n",
			        ebuf);
			rcu_read_unlock();
			return KNOT_ERROR;
		}
		
		rcu_read_unlock();
		return KNOT_EOK;
	} else {
		zd->xfr_in.wrkr = w;
		--zd->xfr_in.scheduled;
	}

	/* Connect to remote. */
	if (data->session <= 0) {
		int fd = socket_create(data->addr.family, SOCK_STREAM);
		if (fd >= 0) {
			/* Bind to specific address - if set. */
			sockaddr_update(&data->saddr);
			if (data->saddr.len > 0) {
				/* Presume port is already preset. */
				ret = bind(fd, data->saddr.ptr, data->saddr.len);
			}
			if (ret < 0) {
				log_server_warning("%s Failed to create socket.\n",
				                   data->msgpref);
			} else {
				ret = connect(fd, data->addr.ptr, data->addr.len);
				if (ret < 0) {
					dbg_xfr("%s: couldn't connect to "
					        "remote host\n", data->msgpref);
				}
			}
		} else {
			ret = -1;
			dbg_xfr("%s: couldn't create socket err=%d\n",
			        data->msgpref, errno);
		}
		
		if (ret < 0) {
			rcu_read_unlock();
			pthread_mutex_unlock(&zd->xfr_in.lock);
			if (fd >= 0) {
				close(fd);
			}
			return KNOT_ECONNREFUSED;
		}

		/* Store new socket descriptor. */
		data->session = fd;
	} else {
		/* Duplicate existing socket descriptor. */
		data->session = dup(data->session);
		if (data->session < 0) {
			rcu_read_unlock();
			pthread_mutex_unlock(&zd->xfr_in.lock);
			log_server_warning("Not enough memory to duplicate \n"
			                   "sockets.\n");
			return KNOT_ENOMEM;
		}
	}

	/* Fetch zone contents. */
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	if (!contents && data->type == XFR_TYPE_IIN) {
		pthread_mutex_unlock(&zd->xfr_in.lock);
		rcu_read_unlock();
		log_server_warning("%s Refusing to start IXFR on zone with no "
				   "contents.\n", data->msgpref);
		close(data->session);
		data->session = -1;
		return KNOT_EINVAL;
	}

	/* Prepare TSIG key if set. */
	int add_tsig = 0;
	if (data->tsig_key) {
		if (xfr_prepare_tsig(data, data->tsig_key) == KNOT_EOK) {
			size_t data_bufsize = KNOT_NS_TSIG_DATA_MAX_SIZE;
			data->tsig_data = malloc(data_bufsize);
			if (data->tsig_data) {
				dbg_xfr("xfr: using TSIG for XFR/IN\n");
				add_tsig = 1;
				data->tsig_data_size = 0;
			} else {
				dbg_xfr("xfr: failed to allocate TSIG data "
					"buffer (%zu kB)\n",
					data_bufsize / 1024);
			}
		}
	}

	/* Create XFR query. */
	size_t bufsize = data->wire_size;
	switch(data->type) {
	case XFR_TYPE_AIN:
		ret = xfrin_create_axfr_query(zone->name, data, &bufsize, add_tsig);
		break;
	case XFR_TYPE_IIN:
		ret = xfrin_create_ixfr_query(contents, data, &bufsize, add_tsig);
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	/* Handle errors. */
	if (ret != KNOT_EOK) {
		pthread_mutex_unlock(&zd->xfr_in.lock);
		rcu_read_unlock();
		dbg_xfr("xfr: failed to create XFR query type %d: %s\n",
		        data->type, knot_strerror(ret));
		close(data->session);
		data->session = -1;
		return KNOT_ERROR;
	}

	/* Unlock zone contents. */
	rcu_read_unlock();
	
	/* Start transfer. */
	ret = data->send(data->session, &data->addr, data->wire, bufsize);
	if (ret != bufsize) {
		char ebuf[256] = {0};
		strerror_r(errno, ebuf, sizeof(ebuf));
		log_server_info("%s Failed to send query (%s).\n",
		                data->msgpref, ebuf);
		pthread_mutex_unlock(&zd->xfr_in.lock);
		close(data->session);
		data->session = -1;
		return KNOT_ECONNREFUSED;
	}
	
	/* Add to pending transfers. */
	knot_ns_xfr_t *task = xfr_register_task(w, data);
	if (task == NULL) {
		log_server_warning("%s Couldn't start connection.\n",
		                   data->msgpref);
		close(data->session);
		data->session = -1;
		return KNOT_ERROR;
	}
	
	/* Send XFR query. */
	log_server_info("%s Started.\n", data->msgpref);
	return KNOT_EOK;
}

/*!
 * \brief Compare file descriptors.
 * 
 * \note Return values of {-1,0,1} are required by skip-list structure.
 */
static int xfr_fd_compare(void *k1, void *k2)
{
	if (k1 > k2) return 1;
	if (k1 < k2) return -1;
	return 0;
}

/*! \brief Return I/A character depending on xfer type. */
static inline char xfr_strtype(knot_ns_xfr_t *xfr) {
	if (xfr->type == XFR_TYPE_IOUT) {
		return 'I';
	} else {
		return 'A';
	}
}

/*! \brief Wrapper function for answering AXFR/OUT. */
static int xfr_answer_axfr(knot_nameserver_t *ns, knot_ns_xfr_t *xfr)
{
	int ret = knot_ns_answer_axfr(ns, xfr);
	dbg_xfr("xfr: ns_answer_axfr() = %d.\n", ret);
	return ret;
}

/*! \brief Wrapper function for answering IXFR/OUT. */
static int xfr_answer_ixfr(knot_nameserver_t *ns, knot_ns_xfr_t *xfr)
{
	/* Check serial differeces. */
	int ret = KNOT_EOK;
	uint32_t serial_from = 0;
	uint32_t serial_to = 0;
	ret = ns_ixfr_load_serials(xfr, &serial_from, &serial_to);
	dbg_xfr_verb("xfr: loading changesets for IXFR %u-%u\n",
	             serial_from, serial_to);
	if (ret != KNOT_EOK) {
		return ret;
	}
	
	/* Load changesets from journal. */
	int chsload = zones_xfr_load_changesets(xfr, serial_from, serial_to);
	if (chsload != KNOT_EOK) {
		/* History cannot be reconstructed, fallback to AXFR. */
		if (chsload == KNOT_ERANGE || chsload == KNOT_ENOENT) {
			log_server_info("%s Failed to load data from journal: "
			                " Incomplete history. "
			                "Fallback to AXFR.\n",
			                xfr->msgpref);
			xfr->type = XFR_TYPE_AOUT;
			xfr->msgpref[XFR_MSG_DLTTR] = 'A';
			return xfr_answer_axfr(ns, xfr);
		} else if (chsload == KNOT_EMALF) {
			xfr->rcode = KNOT_RCODE_FORMERR;
		} else {
			xfr->rcode = KNOT_RCODE_SERVFAIL;
		}
		
		/* Mark all as generic error. */
		ret = KNOT_ERROR;
	}
	
	/* Finally, answer. */
	if (chsload == KNOT_EOK) {
		ret = knot_ns_answer_ixfr(ns, xfr);
		dbg_xfr("xfr: ns_answer_ixfr() = %s.\n", knot_strerror(ret));
	}
	
	return ret;
}

/*! \brief Build string for logging related to given xfer descriptor. */
static int xfr_update_msgpref(knot_ns_xfr_t *req, const char *keytag)
{
	/* Check */
	if (req == NULL) {
		return KNOT_EINVAL;
	}
	
	rcu_read_lock();
	char *r_key = NULL;
	if (keytag) {
		r_key = xfr_remote_str(&req->addr, keytag);
	} else if (req->tsig_key) {
		char *tag = knot_dname_to_str(req->tsig_key->name);
		r_key = xfr_remote_str(&req->addr, tag);
		free(tag);
	} else {
		r_key = xfr_remote_str(&req->addr, NULL);
	}

	/* Prepare log message. */
	const char *zname = req->zname;
	if (zname == NULL && req->zone != NULL) {
		zonedata_t *zd = (zonedata_t *)knot_zone_data(req->zone);
		if (zd == NULL) {
			free(r_key);
			rcu_read_unlock();
			return KNOT_EINVAL;
		} else {
			zname = zd->conf->name;
		}
	}
	const char *pformat = NULL;
	switch (req->type) {
	case XFR_TYPE_AIN:
		pformat = "Incoming AXFR transfer of '%s' with %s:";
		break;
	case XFR_TYPE_IIN:
		pformat = "Incoming IXFR transfer of '%s' with %s:";
		break;
	case XFR_TYPE_AOUT:
		pformat = "Outgoing AXFR transfer of '%s' to %s:";
		break;
	case XFR_TYPE_IOUT:
		pformat = "Outgoing IXFR transfer of '%s' to %s:";
		break;
	case XFR_TYPE_NOTIFY:
		pformat = "NOTIFY query of '%s' to %s:";
		break;
	case XFR_TYPE_SOA:
		pformat = "SOA query of '%s' to %s:";
		break;
	case XFR_TYPE_FORWARD:
		pformat = "UPDATE forwarded query of '%s' to %s:";
		break;
	default:
		pformat = "UNKNOWN query '%s' from %s:";
		break;
	}

	char *msg = sprintf_alloc(pformat, zname, r_key ? r_key : "'unknown'");
	if (msg) {
		req->msgpref = msg;
	}
	
	rcu_read_unlock();
	free(r_key);
	return KNOT_EOK;
}

/*! \brief Create XFR worker. */
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

/*! \brief Free created XFR worker. */
static void xfr_worker_free(xfrworker_t *w) {
	if (w) {
		evqueue_free(&w->q);
		fdset_destroy(w->fdset);
		free(w);
	}
}

/*
 * Public APIs.
 */

xfrhandler_t *xfr_create(size_t thrcount, knot_nameserver_t *ns)
{
	/* Create XFR handler data. */
	xfrhandler_t *data = malloc(sizeof(xfrhandler_t));
	if (data == NULL) {
		return NULL;
	}
	memset(data, 0, sizeof(xfrhandler_t));

	/* Create RR mutex. */
	pthread_mutex_init(&data->rr_mx, 0);

	/* Create tasks structure and mutex. */
	pthread_mutex_init(&data->tasks_mx, 0);
	data->tasks = skip_create_list(xfr_fd_compare);
	
	/* Initialize threads. */
	data->workers = malloc(thrcount * sizeof(xfrhandler_t*));
	if(data->workers == NULL) {
		pthread_mutex_destroy(&data->rr_mx);
		free(data);
		return NULL;
	}
	
	/* Create threading unit. */
	dt_unit_t *unit = dt_create(thrcount);
	if (unit == NULL) {
		pthread_mutex_destroy(&data->rr_mx);
		free(data->workers);
		free(data);
		return NULL;
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
		return NULL;
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
		return KNOT_EINVAL;
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

	return KNOT_EOK;
}

int xfr_stop(xfrhandler_t *handler)
{
	/* Break loop. */
	dt_stop(handler->unit);
	return KNOT_EOK;
}

int xfr_join(xfrhandler_t *handler) {
	return dt_join(handler->unit);
}

int xfr_request_init(knot_ns_xfr_t *r, int type, int flags, knot_packet_t *pkt)
{
	if (!r || type < 0 || flags < 0) {
		return KNOT_EINVAL;
	}
	
	/* Blank and init. */
	memset(r, 0, sizeof(knot_ns_xfr_t));
	r->type = type;
	r->flags = flags;
	
	/* Copy packet if applicable. */
	if (pkt != 0) {
		uint8_t *wire_copy = malloc(sizeof(uint8_t) * pkt->size);
		if (!wire_copy) {
			ERR_ALLOC_FAILED;
			return KNOT_ENOMEM;
		}
		memcpy(wire_copy, pkt->wireformat, pkt->size);
		pkt->wireformat = wire_copy;
		r->query = pkt;
	}
	
	return KNOT_EOK;
}

int xfr_request(xfrhandler_t *handler, knot_ns_xfr_t *req)
{
	if (!handler || !req) {
		return KNOT_EINVAL;
	}
	
	/* Assign UDP requests to handler 0. */
	evqueue_t *q = handler->workers[0]->q;
	if (!(req->flags & XFR_FLAG_UDP)) {
		/* Get next worker in RR fashion */
		pthread_mutex_lock(&handler->rr_mx);
		q = handler->workers[handler->rr + 1]->q;
		handler->rr = get_next_rr(handler->rr, handler->unit->size - 1);
		pthread_mutex_unlock(&handler->rr_mx);
	}
	
	/* Delegate request. */
	int ret = evqueue_write(q, req, sizeof(knot_ns_xfr_t));
	if (ret < 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int xfr_answer(knot_nameserver_t *ns, knot_ns_xfr_t *xfr)
{
	if (ns == NULL || xfr == NULL) {
		return KNOT_EINVAL;
	}
	
	rcu_read_lock();
	int ret = knot_ns_init_xfr(ns, xfr);

	int xfr_failed = (ret != KNOT_EOK);
	const char *errstr = knot_strerror(ret);
	
	// use the QNAME as the zone name to get names also for
	// zones that are not in the server
	const knot_dname_t *qname = knot_packet_qname(xfr->query);
	if (qname != NULL) {
		xfr->zname = knot_dname_to_str(qname);
	} else {
		xfr->zname = strdup("(unknown)");
	}

	/* Check requested zone. */
	if (!xfr_failed) {
		int zcheck_ret = zones_xfr_check_zone(xfr, &xfr->rcode);
		xfr_failed = (zcheck_ret != KNOT_EOK);
		errstr = knot_strerror(zcheck_ret);
	}

	/* Check TSIG. */
	char *keytag = NULL;
	if (!xfr_failed && xfr->tsig_key != NULL) {
		ret = xfr_check_tsig(xfr, &xfr->rcode, &keytag);
		xfr_failed = (ret != KNOT_EOK);
		errstr = knot_strerror(ret);
	}
	
	if (xfr_update_msgpref(xfr, keytag) != KNOT_EOK) {
		xfr->msgpref = strdup("XFR:");
	}
	free(keytag);
	
	/* Announce. */
	log_server_info("%s Started.\n", xfr->msgpref);
	switch (ret) {
	case KNOT_EXFRDENIED:
		log_server_info("%s TSIG required, but not found in query.\n",
		                xfr->msgpref);
		break;
	case KNOT_TSIG_EBADKEY:
		log_server_info("%s Unsupported digest "
		                "algorithm requested, "
		                "treating as bad key.\n",
		                xfr->msgpref);
		break;
	default:
		break;
	}
	
	/* Prepare place for TSIG data */
	xfr->tsig_data = malloc(KNOT_NS_TSIG_DATA_MAX_SIZE);
	if (xfr->tsig_data) {
		dbg_xfr("xfr: TSIG data allocated: %zu.\n",
		        KNOT_NS_TSIG_DATA_MAX_SIZE);
		xfr->tsig_data_size = 0;
	} else {
		dbg_xfr("xfr: failed to allocate TSIG data "
		        "buffer (%zu kB)\n",
		        KNOT_NS_TSIG_DATA_MAX_SIZE / 1024);
	}
	
	/* Finally, answer AXFR/IXFR. */
	if (!xfr_failed) {
		switch(xfr->type) {
		case XFR_TYPE_AOUT:
			ret = xfr_answer_axfr(ns, xfr);
			break;
		case XFR_TYPE_IOUT:
			ret = xfr_answer_ixfr(ns, xfr);
			break;
		default:
			ret = KNOT_ENOTSUP;
			break;
		}
		
		xfr_failed = (ret != KNOT_EOK);
		errstr = knot_strerror(ret);
	} else {
		knot_ns_error_response_from_query(ns, xfr->query,  xfr->rcode,
		                                  xfr->wire, &xfr->wire_size);
		/*! \todo Sign with TSIG for some errors. */
		ret = xfr->send(xfr->session, &xfr->addr, xfr->wire, xfr->wire_size);
	}
	
	/* Check results. */
	if (xfr_failed) {
		log_server_notice("%s %s\n", xfr->msgpref, errstr);
	} else {
		log_server_info("%s Finished.\n", xfr->msgpref);
	}
	
	/* Free allocated data. */
	free(xfr->tsig_data);
	xfr->tsig_data = NULL;
	xfr_request_deinit(xfr);
	rcu_read_unlock();
	
	/* Cleanup. */
	free(xfr->digest);
	free(xfr->query->wireformat);   /* Free wireformat. */
	knot_packet_free(&xfr->query);  /* Free query. */
	knot_packet_free(&xfr->response);  /* Free response. */
	knot_free_changesets((knot_changesets_t **)(&xfr->data));
	free(xfr->zname);
	if (xfr_failed) {
		return KNOT_ERROR;
	}
	
	return KNOT_EOK;
}

static int xfr_process_request(xfrworker_t *w, uint8_t *buf, size_t buflen)
{
	/* Read single request. */
	knot_ns_xfr_t xfr = {};
	int ret = evqueue_read(w->q, &xfr, sizeof(knot_ns_xfr_t));
	if (ret != sizeof(knot_ns_xfr_t)) {
		dbg_xfr_verb("xfr: evqueue_read() returned %d.\n", ret);
		return KNOT_ENOTRUNNING;
	}
	
	rcu_read_lock();
	
	/* Update request. */
	xfr.wire = buf;
	xfr.wire_size = buflen;
	
	/* Update XFR message prefix. */
	xfr_update_msgpref(&xfr, NULL);
	
	/* Check if not already processing. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(xfr.zone);
	
	/* Check if the zone is not discarded. */
	if (knot_zone_flags(xfr.zone) & KNOT_ZONE_DISCARDED) {
		xfr_request_deinit(&xfr);
		knot_zone_release(xfr.zone);
		rcu_read_unlock();
		return KNOT_EOK;
	}

	/* Handle request. */
	knot_ns_xfr_t *task = NULL;
	dbg_xfr("%s processing request type '%d'\n", xfr.msgpref, xfr.type);
	dbg_xfr_verb("%s query ptr: %p\n", xfr.msgpref, xfr.query);
	switch(xfr.type) {
	case XFR_TYPE_AIN:
	case XFR_TYPE_IIN:
		ret = xfr_client_start(w, &xfr);
		
		/* Report. */
		if (ret != KNOT_EOK && ret != KNOT_EACCES) {
			if (zd != NULL && !knot_zone_contents(xfr.zone)) {
				/* Reschedule request delay. */
				int tmr_s = AXFR_BOOTSTRAP_RETRY;
				tmr_s += (int)((tmr_s) * tls_rand());
				event_t *ev = zd->xfr_in.timer;
				if (ev) {
					evsched_cancel(ev->parent, ev);
					evsched_schedule(ev->parent, ev, tmr_s);
				}
				log_zone_notice("%s Bootstrap failed, next "
				                "attempt in %d seconds.\n",
				                xfr.msgpref, tmr_s / 1000);
			} else {
				log_server_error("%s %s\n",
				                 xfr.msgpref, knot_strerror(ret));
			}
			knot_zone_release(xfr.zone); /* No further access to zone. */
		}
		
		break;
	case XFR_TYPE_SOA:
	case XFR_TYPE_NOTIFY:
	case XFR_TYPE_FORWARD:
		/* Register task. */
		task = xfr_register_task(w, &xfr);
		if (!task) {
			knot_zone_release(xfr.zone); /* No further access to zone. */
			ret = KNOT_ENOMEM;
		} else {
			/* Add timeout. */
			rcu_read_lock();
			fdset_set_watchdog(w->fdset, task->session,
			                   conf()->max_conn_reply);
			rcu_read_unlock();
			if (xfr.type == XFR_TYPE_FORWARD) {
				log_server_info("%s Forwarded query.\n",
				                xfr.msgpref);
			} else {
				log_server_info("%s Query issued.\n",
				                xfr.msgpref);
			}
			ret = KNOT_EOK;
		}
		break;
	default:
		log_server_error("Unknown XFR request type (%d).\n", xfr.type);
		break;
	}

	rcu_read_unlock();
	
	/* Deinitialize (it is already registered, or discarded).
	 * Right now, this only frees temporary msgpref.
	 */
	xfr_request_deinit(&xfr);
	
	return ret;
}

int xfr_worker(dthread_t *thread)
{
	xfrworker_t *w = (xfrworker_t *)thread->data;	

	/* Check data. */
	if (w < 0) {
		dbg_xfr("xfr: NULL worker data, worker cancelled\n");
		return KNOT_EINVAL;
	}

	/* Buffer for answering. */
	size_t buflen = XFR_BUFFER_SIZE;
	uint8_t* buf = malloc(buflen);
	if (buf == NULL) {
		dbg_xfr("xfr: failed to allocate buffer for XFR worker\n");
		return KNOT_ENOMEM;
	}
	
	/* Next sweep time. */
	timev_t next_sweep;
	time_now(&next_sweep);
	next_sweep.tv_sec += XFR_SWEEP_INTERVAL;

	/* Accept requests. */
	int ret = 0;
	dbg_xfr_verb("xfr: worker=%p starting\n", w);
	for (;;) {
		
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}
		
		/* Poll fdset. */
		int nfds = fdset_wait(w->fdset, (XFR_SWEEP_INTERVAL * 1000)/2);
		if (nfds < 0) {
			continue;
		}
		
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}
		
		/* Iterate fdset. */
		knot_ns_xfr_t *data = 0;
		int rfd = evqueue_pollfd(w->q);
		fdset_it_t it = {0};
		fdset_begin(w->fdset, &it);
		int rfd_event = 0;
		while(nfds > 0) {
			/* Check if it request. */
			if (it.fd == rfd) {
				rfd_event = 1; /* Delay new tasks after processing. */
			} else {
				/* Find data. */
				data = xfr_handler_task(w, it.fd);
				if (data == NULL) {
					/* Next fd. */
					if (fdset_next(w->fdset, &it) < 0) {
						break;
					} else {
						continue;
					}
				}
				dbg_xfr_verb("xfr: worker=%p processing event on "
				             "fd=%d data=%p.\n",
				             w, it.fd, data);
				ret = xfr_process_event(w, it.fd, data, buf, buflen);
				if (ret != KNOT_EOK) {
					xfr_free_task(data);
					/*! \todo Refactor to allow erase on iterator.*/
					break;
				}
			}
			
			/* Next fd. */
			if (fdset_next(w->fdset, &it) < 0) {
				break;
			}
		}
		
		/* Lazily process new tasks. */
		if (rfd_event) {
			dbg_xfr_verb("xfr: worker=%p processing request\n",  w);
			ret = xfr_process_request(w, buf, buflen);
		}
		
		/* Sweep inactive. */
		timev_t now;
		if (time_now(&now) == 0) {
			if (now.tv_sec >= next_sweep.tv_sec) {
				fdset_sweep(w->fdset, &xfr_sweep, w);
				memcpy(&next_sweep, &now, sizeof(next_sweep));
				next_sweep.tv_sec += XFR_SWEEP_INTERVAL;
			}
		}
		
		/* Check for interrupt request. */
		if (ret == KNOT_ENOTRUNNING) {
			break;
		}
	}

	/* Stop whole unit. */
	free(buf);
	dbg_xfr_verb("xfr: worker=%p finished.\n", w);
	thread->data = 0;
	return KNOT_EOK;
}

int xfr_prepare_tsig(knot_ns_xfr_t *xfr, knot_key_t *key)
{
	if (xfr == NULL || key == NULL) {
		return KNOT_EINVAL;
	}
	
	int ret = KNOT_EOK;
	xfr->tsig_key = key;
	xfr->tsig_size = tsig_wire_maxsize(key);
	xfr->digest_max_size = tsig_alg_digest_length(
				key->algorithm);
	xfr->digest = malloc(xfr->digest_max_size);
	if (xfr->digest == NULL) {
		xfr->tsig_key = NULL;
		xfr->tsig_size = 0;
		xfr->digest_max_size = 0;
		return KNOT_ENOMEM;
	}
	memset(xfr->digest, 0 , xfr->digest_max_size);
	dbg_xfr("xfr: found TSIG key (MAC len=%zu), adding to transfer\n",
		xfr->digest_max_size);
	
	return ret;
}

char *xfr_remote_str(const sockaddr_t *addr, const char *key)
{
	if (!addr) {
		return NULL;
	}
	
	/* Prepare address strings. */
	char r_addr[SOCKADDR_STRLEN];
	int r_port = sockaddr_portnum(addr);
	sockaddr_tostr(addr, r_addr, sizeof(r_addr));
	
	/* Prepare key strings. */
	char *tag = "";
	char *q = "'";
	if (key) {
		tag = " key "; /* Prefix */
	} else {
		key = tag; /* Both empty. */
		q = tag;
	}
	
	return sprintf_alloc("'%s@%d'%s%s%s%s", r_addr, r_port, tag, q, key, q);
}
