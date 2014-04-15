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

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <urcu.h>

#include "knot/server/xfr-handler.h"
#include "knot/server/server.h"
#include "knot/server/net.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/updates/xfr-in.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/ixfr.h"
#include "knot/server/zones.h"
#include "knot/knot.h"
#include "libknot/tsig-op.h"
#include "common/evsched.h"
#include "common/descriptor.h"
#include "libknot/rrset.h"
#include "libknot/dnssec/random.h"

/* Constants */

#define XFR_MAX_TASKS 1024 /*! Maximum pending tasks. */
#define XFR_CHUNKLEN 16 /*! Number of requests assigned in a single pass. */
#define XFR_SWEEP_INTERVAL 2 /*! [seconds] between sweeps. */
#define XFR_MSG_DLTTR 9 /*! Index of letter differentiating IXFR/AXFR in log msg. */
#define XFR_TSIG_DATA_MAX_SIZE (100 * 64 * 1024) /*! Naximum size of TSIG buffers. */

/* Messages */

static knot_lookup_table_t xfr_type_table[] = {
        { XFR_TYPE_AIN, "Incoming AXFR of '%s' with %s:" },
        { XFR_TYPE_IIN, "Incoming IXFR of '%s' with %s:" },
        { XFR_TYPE_AOUT, "Outgoing AXFR of '%s' to %s:" },
        { XFR_TYPE_IOUT, "Outgoing IXFR of '%s' to %s:" },
        { XFR_TYPE_NOTIFY, "NOTIFY of '%s' to %s:" },
        { XFR_TYPE_SOA, "SOA query of '%s' to %s:" },
        { XFR_TYPE_FORWARD, "UPDATE forwarded query of '%s' to %s:" },
        { XFR_TYPE_AIN, NULL }
};
static knot_lookup_table_t xfr_result_table[] = {
        { XFR_TYPE_AIN, "Started." },
        { XFR_TYPE_IIN, "Started." },
        { XFR_TYPE_SOA, "Query issued." },
        { XFR_TYPE_NOTIFY, "Query issued." },
        { XFR_TYPE_FORWARD, "Forwarded query." },
        { XFR_TYPE_AIN, NULL }
};

/* Limits. */
static bool xfr_pending_incr(xfrhandler_t *xfr)
{
	bool ret = false;
	pthread_mutex_lock(&xfr->pending_mx);
	rcu_read_lock();
	if (xfr->pending < conf()->xfers) {
		++xfr->pending;
		ret = true;
	}
	rcu_read_unlock();
	pthread_mutex_unlock(&xfr->pending_mx);

	return ret;
}

static void xfr_pending_decr(xfrhandler_t *xfr)
{
	pthread_mutex_lock(&xfr->pending_mx);
	--xfr->pending;
	pthread_mutex_unlock(&xfr->pending_mx);
}

/* I/O wrappers */

static int xfr_send_tcp(int fd, struct sockaddr *addr, uint8_t *msg, size_t msglen)
{ return tcp_send(fd, msg, msglen); }

static int xfr_send_udp(int fd, struct sockaddr *addr, uint8_t *msg, size_t msglen)
{ return sendto(fd, msg, msglen, 0, addr, sockaddr_len((struct sockaddr_storage *)addr));  }

static int xfr_recv_tcp(int fd, struct sockaddr *addr, uint8_t *buf, size_t buflen)
{ return tcp_recv(fd, buf, buflen, addr); }

static int xfr_recv_udp(int fd, struct sockaddr *addr, uint8_t *buf, size_t buflen)
{ return recv(fd, buf, buflen, 0); }

/*! \brief Create forwarded query. */
static int forward_packet(knot_ns_xfr_t *data, knot_pkt_t *pkt)
{
	knot_pkt_t *query = data->query;
	memcpy(pkt->wire, query->wire, query->size);
	pkt->size = query->size;

	/* Assign new message id. */
	data->packet_nr = knot_wire_get_id(pkt->wire);
	knot_wire_set_id(pkt->wire, knot_random_uint16_t());

	return KNOT_EOK;
}

/*! \brief Forwarded packet response. */
static int forward_packet_response(knot_ns_xfr_t *data, knot_pkt_t *pkt)
{
	/* Restore message id. */
	knot_wire_set_id(pkt->wire, (uint16_t)data->packet_nr);

	/* Restore TSIG. */
	int ret = KNOT_EOK;
	if (pkt->tsig_rr) {
		ret = knot_tsig_append(pkt->wire, &pkt->size, pkt->max_size,
		                       pkt->tsig_rr);
	}

	/* Forward the response. */
	if (ret == KNOT_EOK) {
		ret = data->send(data->fwd_src_fd, (struct sockaddr *)&data->fwd_addr,
		                 pkt->wire, pkt->size);
		if (ret != pkt->size) {
			ret = KNOT_ECONN;
		} else {
			ret = KNOT_EOK;
		}
	}

	/* Invalidate response => do not reply to master. */
	pkt->size = 0;
	return ret;
}

/*! \brief Build string for logging related to given xfer descriptor. */
static int xfr_task_setmsg(knot_ns_xfr_t *rq, const char *keytag)
{
	/* Check */
	if (rq == NULL) {
		return KNOT_EINVAL;
	}

	knot_lookup_table_t *xd = knot_lookup_by_id(xfr_type_table, rq->type);
	if (!xd) {
		return KNOT_EINVAL;
	}

	/* Zone is refcounted, no need for RCU. */
	char *kstr = NULL;
	if (keytag) {
		kstr = xfr_remote_str(&rq->addr, keytag);
	} else if (rq->tsig_key) {
		char *tag = knot_dname_to_str(rq->tsig_key->name);
		kstr = xfr_remote_str(&rq->addr, tag);
		free(tag);
	} else {
		kstr = xfr_remote_str(&rq->addr, NULL);
	}

	/* Prepare log message. */
	const char *zname = rq->zone->conf->name;
	rq->msg = sprintf_alloc(xd->name, zname, kstr ? kstr : "'unknown'");
	free(kstr);
	return KNOT_EOK;
}

static int xfr_task_setsig(knot_ns_xfr_t *rq, knot_tsig_key_t *key)
{
	if (rq == NULL || key == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	rq->tsig_key = key;
	rq->tsig_size = tsig_wire_maxsize(key);
	rq->digest_max_size = knot_tsig_digest_length(key->algorithm);
	rq->digest = malloc(rq->digest_max_size);
	if (rq->digest == NULL) {
		rq->tsig_key = NULL;
		rq->tsig_size = 0;
		rq->digest_max_size = 0;
		return KNOT_ENOMEM;
	}
	memset(rq->digest, 0 , rq->digest_max_size);
	rq->tsig_data = malloc(XFR_TSIG_DATA_MAX_SIZE);
	if (rq->tsig_data) {
		dbg_xfr("xfr: using TSIG for XFR/IN\n");
		rq->tsig_data_size = 0;
	} else {
		free(rq->digest);
		rq->digest = NULL;
		rq->tsig_key = NULL;
		rq->tsig_size = 0;
		rq->digest_max_size = 0;
		return KNOT_ENOMEM;
	}
	dbg_xfr("xfr: found TSIG key (MAC len=%zu), adding to transfer\n",
		rq->digest_max_size);

	return ret;
}

static int xfr_task_connect(knot_ns_xfr_t *rq)
{
	/* Create socket by type. */
	int stype = (rq->flags & XFR_FLAG_TCP) ? SOCK_STREAM : SOCK_DGRAM;
	int ret = net_connected_socket(stype, &rq->addr, &rq->saddr);
	if (ret < 0) {
		return ret;
	}

	/* Set up for UDP as well to trigger 'send query' event. */
	rq->session = ret;
	rq->flags |= XFR_FLAG_CONNECTING;

	return KNOT_EOK;
}

/*! \brief Clean pending transfer data. */
static void xfr_task_cleanup(knot_ns_xfr_t *rq)
{
	dbg_xfr_verb("Cleaning up after XFR-in.\n");
	if (rq->type == XFR_TYPE_AIN) {
		if (rq->flags & XFR_FLAG_AXFR_FINISHED) {
			knot_zone_contents_deep_free(&rq->new_contents);
		} else if (rq->data) {
			knot_zone_contents_t *zone = rq->data;
			knot_zone_contents_deep_free(&zone);
			rq->data = NULL;
		}
	} else if (rq->type == XFR_TYPE_IIN) {
		knot_changesets_t *chs = (knot_changesets_t *)rq->data;
		knot_changesets_free(&chs);
		rq->data = NULL;
		assert(rq->new_contents == NULL);
	} else if (rq->type == XFR_TYPE_FORWARD) {
		knot_pkt_free(&rq->query);
	}

	/* Cleanup other data - so that the structure may be reused. */
	rq->packet_nr = 0;
	rq->tsig_data_size = 0;
}

/*! \brief End task properly and free it. */
static int xfr_task_close(knot_ns_xfr_t *rq)
{
	zone_t *zone = rq->zone;

	/* Update xfer state. */
	if (rq->type == XFR_TYPE_AIN || rq->type == XFR_TYPE_IIN) {
		pthread_mutex_lock(&zone->lock);
		if (zone->xfr_in.state == XFR_PENDING) {
			zone->xfr_in.state = XFR_IDLE;
		}
		pthread_mutex_unlock(&zone->lock);
	}

	/* Reschedule failed bootstrap. */
	if (rq->type == XFR_TYPE_AIN && !rq->zone->contents) {
		/* Progressive retry interval up to AXFR_RETRY_MAXTIME */
		zone->xfr_in.bootstrap_retry *= 2;
		zone->xfr_in.bootstrap_retry += knot_random_uint32_t() % AXFR_BOOTSTRAP_RETRY;
		if (zone->xfr_in.bootstrap_retry > AXFR_RETRY_MAXTIME) {
			zone->xfr_in.bootstrap_retry = AXFR_RETRY_MAXTIME;
		}

		evsched_cancel(zone->xfr_in.timer);
		evsched_schedule(zone->xfr_in.timer, zone->xfr_in.bootstrap_retry);

		log_zone_notice("%s Bootstrap failed, next attempt in %d seconds.\n",
		                rq->msg, zone->xfr_in.bootstrap_retry / 1000);
	}

	/* Close socket and free task. */
	xfr_task_free(rq);
	return KNOT_EOK;
}

/*! \brief Timeout handler. */
static int xfr_task_expire(fdset_t *set, int i, knot_ns_xfr_t *rq)
{
	/* Fetch related zone (refcounted, no RCU). */
	zone_t *zone = (zone_t *)rq->zone;

	/* Process timeout. */
	switch(rq->type) {
	case XFR_TYPE_NOTIFY:
		if ((long)--rq->data > 0) { /* Retries */
			rq->send(rq->session, (struct sockaddr *)&rq->addr, rq->wire, rq->wire_size);
			log_zone_info("%s Query issued (serial %u).\n",
			              rq->msg, knot_zone_serial(zone->contents));
			fdset_set_watchdog(set, i, NOTIFY_TIMEOUT);
			return KNOT_EOK; /* Keep state. */
		}
		break;
	default:
		break;
	}

	log_zone_info("%s Failed, timeout exceeded.\n", rq->msg);
	return KNOT_ECONNREFUSED;
}

/*! \brief Start pending request. */
static int xfr_task_start(knot_ns_xfr_t *rq)
{
	/* Zone is refcounted, no need for RCU. */
	int ret = KNOT_EOK;
	zone_t *zone = (zone_t *)rq->zone;

	/* Fetch zone contents. */
	if (!zone->contents && rq->type == XFR_TYPE_IIN) {
		log_zone_warning("%s Refusing to start IXFR on zone with no "
		                 "contents.\n", rq->msg);
		return KNOT_ECONNREFUSED;
	}

	/* Create query packet. */
	knot_pkt_t *pkt = knot_pkt_new(rq->wire, rq->wire_maxlen, NULL);
	CHECK_ALLOC_LOG(pkt, KNOT_ENOMEM);
	knot_pkt_clear(pkt);
	knot_wire_set_id(pkt->wire, knot_random_uint16_t());

	/* Prepare TSIG key if set. */
	if (rq->tsig_key) {
		/* Reserve space for TSIG. */
		knot_pkt_reserve(pkt, tsig_wire_maxsize(rq->tsig_key));
		ret = xfr_task_setsig(rq, rq->tsig_key);
		if (ret != KNOT_EOK) {
			knot_pkt_free(&pkt);
			return ret;
		}
	}

	switch(rq->type) {
	case XFR_TYPE_AIN:
		ret = xfrin_create_axfr_query(zone, pkt);
		break;
	case XFR_TYPE_IIN:
		ret = xfrin_create_ixfr_query(zone, pkt);
		break;
	case XFR_TYPE_SOA:
		ret = xfrin_create_soa_query(zone, pkt);
		break;
	case XFR_TYPE_NOTIFY:
		ret = notify_create_request(zone, pkt);
		break;
	case XFR_TYPE_FORWARD:
		ret = forward_packet(rq, pkt);
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	/* Write back size and finish packet writer. */
	rq->wire_size = pkt->size;
	knot_pkt_free(&pkt);

	/* Handle errors. */
	if (ret != KNOT_EOK) {
		dbg_xfr("xfr: failed to create XFR query type %d: %s\n",
		        rq->type, knot_strerror(ret));
		return ret;
	}

	/* Sign query if secured. */
	if (rq->tsig_key) {
		rq->digest_size = rq->digest_max_size;
		ret = knot_tsig_sign(rq->wire, &rq->wire_size, rq->wire_maxlen, NULL, 0,
		                     rq->digest, &rq->digest_size, rq->tsig_key,
		                     0, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* Start transfer. */
	gettimeofday(&rq->t_start, NULL);
	if (rq->wire_size > 0) {

		ret = rq->send(rq->session, (struct sockaddr *)&rq->addr, rq->wire, rq->wire_size);
		if (ret != rq->wire_size) {
			char ebuf[256] = {0};
			if (strerror_r(errno, ebuf, sizeof(ebuf)) == 0) {
				log_zone_info("%s Failed to send query (%s).\n",
				              rq->msg, ebuf);
			}
			return KNOT_ECONNREFUSED;
		}
	}

	/* If successful. */
	if (rq->type == XFR_TYPE_SOA || rq->type == XFR_TYPE_NOTIFY) {
		rq->packet_nr = knot_wire_get_id(rq->wire);
	}

	return KNOT_EOK;
}

static int xfr_task_is_transfer(knot_ns_xfr_t *rq)
{
	return rq->type == XFR_TYPE_AIN || rq->type == XFR_TYPE_IIN;
}

static void xfr_async_setbuf(knot_ns_xfr_t *rq, uint8_t *buf, size_t buflen)
{
	/* Update request. */
	rq->wire = buf;
	rq->wire_size = buflen;
	rq->wire_maxlen = buflen;
	rq->send = &xfr_send_udp;
	rq->recv = &xfr_recv_udp;
	if (rq->flags & XFR_FLAG_TCP) {
		rq->send = &xfr_send_tcp;
		rq->recv = &xfr_recv_tcp;
	}
}

static int xfr_async_start(fdset_t *set, knot_ns_xfr_t *rq)
{
	/* Update XFR message prefix. */
	int ret = KNOT_EOK;
	xfr_task_setmsg(rq, NULL);

	/* Connect to remote. */
	if (rq->session <= 0)
		ret = xfr_task_connect(rq);

	/* Add to set. */
	if (ret == KNOT_EOK) {
		unsigned flags = POLLIN;
		if (rq->flags & XFR_FLAG_CONNECTING)
			flags = POLLOUT;
		int next_id = fdset_add(set, rq->session, flags, rq);
		if (next_id >= 0) {
			/* Set default connection timeout. */
			rcu_read_lock();
			fdset_set_watchdog(set, next_id, conf()->max_conn_reply);
			rcu_read_unlock();
		} else {
			/* Or refuse if failed. */
			ret = KNOT_ECONNREFUSED;
		}
	}

	return ret;
}

static int xfr_async_state(knot_ns_xfr_t *rq)
{
	/* Check socket status. */
	int err = EINVAL;
	socklen_t len = sizeof(int);
	if (getsockopt(rq->session, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
		return KNOT_ERROR;
	if (err != 0)
		return knot_map_errno(err);
	return KNOT_EOK;
}

static int xfr_async_finish(fdset_t *set, unsigned id)
{
	/* Drop back to synchronous mode. */
	int ret = KNOT_EOK;
	knot_ns_xfr_t *rq = (knot_ns_xfr_t *)set->ctx[id];
	if ((ret = xfr_async_state(rq)) == KNOT_EOK) {
		rq->flags &= ~XFR_FLAG_CONNECTING;
		set->pfd[id].events = POLLIN;
		if (fcntl(set->pfd[id].fd, F_SETFL, 0) < 0)
			;
	} else {
		/* Do not attempt to start on broken connection. */
		return KNOT_ECONNREFUSED;
	}

	zone_t *zone = rq->zone;

	/* Check if the zone is not discarded. */
	if (zone->flags & ZONE_DISCARDED) {
		dbg_xfr_verb("xfr: request on a discarded zone, ignoring\n");
		return KNOT_EINVAL;
	}

	/* Handle request. */
	dbg_xfr("%s processing request type '%d'\n", rq->msg, rq->type);
	ret = xfr_task_start(rq);
	const char *msg = knot_strerror(ret);
	knot_lookup_table_t *xd = knot_lookup_by_id(xfr_result_table, rq->type);
	if (xd && ret == KNOT_EOK) {
		msg = xd->name;
	}

	switch(rq->type) {
	case XFR_TYPE_AIN:
	case XFR_TYPE_IIN:
		if (ret != KNOT_EOK) {
			pthread_mutex_lock(&zone->lock);
			zone->xfr_in.state = XFR_IDLE;
			pthread_mutex_unlock(&zone->lock);
		}
		break;
	case XFR_TYPE_NOTIFY:
	case XFR_TYPE_SOA:
	case XFR_TYPE_FORWARD:
	default:
		break;
	}

	/* NOTIFY is special. */
	if (rq->type == XFR_TYPE_NOTIFY) {
		log_zone_info("%s Query issued (serial %u).\n",
		              rq->msg, knot_zone_serial(rq->zone->contents));
	} else if (ret == KNOT_EOK) {
		log_zone_info("%s %s\n", rq->msg, msg);
	} else {
		log_zone_error("%s %s\n", rq->msg, msg);
	}

	return ret;
}

/*! \brief Switch zone contents with new. */
int knot_ns_switch_zone(knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || xfr->new_contents == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_contents_t *zone = (knot_zone_contents_t *)xfr->new_contents;

	dbg_xfr("Replacing zone by new one: %p\n", zone);
	if (zone == NULL) {
		dbg_xfr("No new zone!\n");
		return KNOT_ENOZONE;
	}

	/* Zone must not be looked-up from server, as it may be a different zone if
	 * a reload occurs when transfer is pending. */
	zone_t *z = xfr->zone;
	if (z == NULL) {
		char *name = knot_dname_to_str(zone->apex->owner);
		dbg_xfr("Failed to replace zone %s, old zone "
		       "not found\n", name);
		free(name);

		return KNOT_ENOZONE;
	}

	rcu_read_unlock();
	int ret = xfrin_switch_zone(z, zone, xfr->type);
	rcu_read_lock();

	return ret;
}

/*! \brief Finalize XFR/IN transfer. */
static int xfr_task_finalize(knot_ns_xfr_t *rq)
{
	int ret = KNOT_EINVAL;
	rcu_read_lock();

	if (rq->type == XFR_TYPE_AIN) {
		ret = zones_save_zone(rq);
		if (ret == KNOT_EOK) {
			ret = knot_ns_switch_zone(rq);
			if (ret != KNOT_EOK) {
				log_zone_error("%s %s\n", rq->msg, knot_strerror(ret));
				log_zone_error("%s Failed to switch in-memory "
				               "zone.\n", rq->msg);
			}
		} else {
			log_zone_error("%s %s\n",
			               rq->msg, knot_strerror(ret));
			log_zone_error("%s Failed to save zonefile.\n",
			               rq->msg);
		}
	} else if (rq->type == XFR_TYPE_IIN) {
		knot_changesets_t *chs = (knot_changesets_t *)rq->data;
		ret = zones_store_and_apply_chgsets(chs, rq->zone,
		                                    &rq->new_contents,
		                                    rq->msg,
		                                    XFR_TYPE_IIN);
		rq->data = NULL; /* Freed or applied in prev function. */
	}

	if (ret == KNOT_EOK) {
		struct timeval t_end;
		gettimeofday(&t_end, NULL);
		log_zone_info("%s Finished in %.02fs "
		              "(finalization %.02fs).\n",
		              rq->msg,
		              time_diff(&rq->t_start, &t_end) / 1000.0,
		              time_diff(&rq->t_end, &t_end) / 1000.0);
		rq->new_contents = NULL; /* Do not free. */
	}

	rcu_read_unlock();

	return ret;
}

/*! \brief Query response event handler function. */
static int xfr_task_resp(xfrhandler_t *xfr, knot_ns_xfr_t *rq, knot_pkt_t *pkt)
{
	knot_pkt_type_t pkt_type = knot_pkt_type(pkt);

	/* Ignore other packets. */
	switch(pkt_type) {
	case KNOT_RESPONSE_NORMAL:
	case KNOT_RESPONSE_NOTIFY:
	case KNOT_RESPONSE_UPDATE:
		break;
	default:
		return KNOT_EOK; /* Ignore */
	}

	int ret = knot_pkt_parse_payload(pkt, 0);
	if (ret != KNOT_EOK) {
		return KNOT_EOK; /* Ignore */
	}

	/* Check TSIG. */
	const knot_rrset_t * tsig_rr = pkt->tsig_rr;
	if (rq->tsig_key != NULL) {
		ret = knot_tsig_client_check(tsig_rr, pkt->wire, pkt->size,
		                             rq->digest, rq->digest_size,
		                             rq->tsig_key, 0);
		if (ret != KNOT_EOK) {
			log_zone_error("%s %s\n", rq->msg, knot_strerror(ret));
			return KNOT_ECONNREFUSED;
		}

	}

	/* Process response. */
	switch(pkt_type) {
	case KNOT_RESPONSE_NORMAL:
		ret = zones_process_response(xfr->server, rq->packet_nr, &rq->addr,
		                             pkt);
		break;
	case KNOT_RESPONSE_NOTIFY:
		ret = notify_process_response(pkt, rq->packet_nr);
		break;
	case KNOT_RESPONSE_UPDATE:
		ret = forward_packet_response(rq, pkt);
		if (ret == KNOT_EOK) {
			log_zone_info("%s Forwarded response.\n", rq->msg);
		}
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	if (ret == KNOT_EUPTODATE) {  /* Check up-to-date zone. */
		log_zone_info("%s %s (serial %u)\n", rq->msg,
		              knot_strerror(ret),
		              knot_zone_serial(rq->zone->contents));
		ret = KNOT_ECONNREFUSED;
	} else if (ret == KNOT_EOK) { /* Disconnect if everything went well. */
		ret = KNOT_ECONNREFUSED;
	}

	return ret;
}

/*! \brief This will fall back to AXFR on active connection.
 *  \note The active connection is expected to be force shut.
 */
static int xfr_start_axfr(xfrhandler_t *xfr, knot_ns_xfr_t *rq, const char *reason)
{
	log_zone_notice("%s %s\n", rq->msg, reason);

	/* Copy current xfer data. */
	knot_ns_xfr_t *axfr = xfr_task_create(rq->zone, XFR_TYPE_AIN, XFR_FLAG_TCP);
	if (axfr == NULL) {
		log_zone_warning("%s Couldn't fall back to AXFR.\n", rq->msg);
		return KNOT_ECONNREFUSED; /* Disconnect */
	}

	xfr_task_setaddr(axfr, &rq->addr, &rq->saddr);
	axfr->tsig_key = rq->tsig_key;

	/* Enqueue new request and close the original. */
	log_zone_notice("%s Retrying with AXFR.\n", rq->msg);
	xfr_enqueue(xfr, axfr);
	return KNOT_ECONNREFUSED;
}

/*! \brief This will fall back to AXFR on idle connection. */
static int xfr_fallback_axfr(knot_ns_xfr_t *rq)
{
	/* Clean up current transfer. */
	xfr_task_cleanup(rq);

	/* Designate as AXFR type and restart. */
	rq->type = XFR_TYPE_AIN;
	rq->msg[XFR_MSG_DLTTR] = 'A';

	log_zone_notice("%s Retrying with AXFR.\n", rq->msg);
	return xfr_task_start(rq);
}

static int xfr_parse_packet(knot_pkt_t *pkt)
{
	/* This is important, don't merge RRs together. The SOAs are ordered
	 * in a special way for a reason. */
	int ret = knot_pkt_parse(pkt, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// check if the response is OK
	if (knot_wire_get_rcode(pkt->wire) != KNOT_RCODE_NOERROR) {
		return KNOT_EXFRREFUSED;
	}

	// check if the TC bit is set (it must not be)
	if (knot_wire_get_tc(pkt->wire)) {
		return KNOT_EMALF;
	}

	return ret;
}

static int xfr_task_xfer(xfrhandler_t *xfr, knot_ns_xfr_t *rq, knot_pkt_t *pkt)
{
	/* Parse transfer packet. */
	int ret = xfr_parse_packet(pkt);
	if (ret != KNOT_EOK) {
		log_zone_error("%s %s\n", rq->msg, knot_strerror(ret));
		return ret;
	}

	/* Process incoming packet. */
	switch(rq->type) {
	case XFR_TYPE_AIN:
		ret = axfr_process_answer(pkt, rq);
		break;
	case XFR_TYPE_IIN:
		ret = ixfr_process_answer(pkt, rq);
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	/* AXFR-style IXFR. */
	if (ret == KNOT_ENOIXFR) {
		assert(rq->type == XFR_TYPE_IIN);
		log_zone_notice("%s Fallback to AXFR.\n", rq->msg);
		xfr_task_cleanup(rq);
		rq->type = XFR_TYPE_AIN;
		rq->msg[XFR_MSG_DLTTR] = 'A';
		ret = axfr_process_answer(pkt, rq);
	}

	/* IXFR refused, try again with AXFR. */
	const char *diff_nospace_msg = "Can't fit the differences in the journal.";
	const char *diff_invalid_msg = "IXFR packet processed, but invalid parameters.";
	if (rq->type == XFR_TYPE_IIN) {
		switch(ret) {
		case KNOT_ESPACE: /* Fallthrough */
			return xfr_start_axfr(xfr, rq, diff_nospace_msg);
		case KNOT_EXFRREFUSED:
			return xfr_fallback_axfr(rq);
		default:
			break;
		}
	}

	/* Handle errors. */
	if (ret == KNOT_ENOXFR) {
		log_zone_warning("%s Finished, %s\n", rq->msg, knot_strerror(ret));
	} else if (ret < 0) {
		log_zone_error("%s %s\n", rq->msg, knot_strerror(ret));
	}

	/* Only for successful xfers. */
	if (ret > 0) {
		ret = xfr_task_finalize(rq);
		zone_t *zone = rq->zone;

		/* EBUSY on incremental transfer has a special meaning and
		 * is caused by a journal not able to free up space for incoming
		 * transfer, thus forcing to start a new full zone transfer. */

		/* Some bad incremental transfer packets seem to get further
		 * than they should.  This has been seen when the master has
		 * logged the fact that it is falling back to AXFR.
		 * In this case, chs->count == 0, so we end up here with
		 * EINVAL.  To work around this problem, force a new full
		 * zone transfer in this case. */

		if (ret == KNOT_EBUSY && rq->type == XFR_TYPE_IIN) {
			return xfr_start_axfr(xfr, rq, diff_nospace_msg);
		} else if (ret == KNOT_EINVAL && rq->type == XFR_TYPE_IIN) {
			return xfr_start_axfr(xfr, rq, diff_invalid_msg);
		} else {

			/* Passed, schedule NOTIFYs. */
			zones_schedule_notify(zone, xfr->server);
		}

		/* Sync zonefile immediately if configured. */
		if (rq->type == XFR_TYPE_IIN && zone->conf->dbsync_timeout == 0) {
			dbg_zones("%s: syncing zone immediately\n", __func__);
			zones_schedule_zonefile_sync(zone, 0);
		}

		/* Update REFRESH/RETRY */
		zones_schedule_refresh(zone, REFRESH_DEFAULT);
		ret = KNOT_ECONNREFUSED; /* Disconnect */
	}

	return ret;
}

/*! \brief Incoming packet handling function. */
static int xfr_process_event(xfrhandler_t *xfr, knot_ns_xfr_t *rq)
{
	/* Check if zone is valid. */
	if (rq->zone->flags & ZONE_DISCARDED) {
		return KNOT_ECONNREFUSED;
	}

	/* Receive msg. */
	int n = rq->recv(rq->session, (struct sockaddr *)&rq->addr, rq->wire, rq->wire_maxlen);
	if (n < 0) { /* Disconnect */
		n = knot_map_errno(errno);
		log_zone_error("%s %s\n", rq->msg, knot_strerror(n));
		return n;
	} else if (n == 0) {
		return KNOT_ECONNREFUSED;
	} else {
		rq->wire_size = n;
	}

	/* Parse question. */
	knot_pkt_t *pkt = knot_pkt_new(rq->wire, rq->wire_size, NULL);
	if (pkt == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = knot_pkt_parse_question(pkt);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&pkt);
		return ret;
	}

	/* Process packet by request type. */
	switch(rq->type) {
	case XFR_TYPE_NOTIFY:
	case XFR_TYPE_SOA:
	case XFR_TYPE_FORWARD:
		ret = xfr_task_resp(xfr, rq, pkt);
		break;
	default:
		ret = xfr_task_xfer(xfr, rq, pkt);
		break;
	}

	knot_pkt_free(&pkt);
	return ret;
}

/*! \brief Sweep inactive connection. */
static enum fdset_sweep_state xfr_sweep(fdset_t *set, int i, void *data)
{
	assert(set && i < set->n && i >= 0);

	knot_ns_xfr_t *rq = set->ctx[i];
	xfrhandler_t *xfr = (xfrhandler_t *)data;

	/* Expire only UDP requests. */
	int ret = KNOT_ECONNREFUSED;
	switch(rq->type) {
	case XFR_TYPE_SOA:
	case XFR_TYPE_NOTIFY:
	case XFR_TYPE_FORWARD:
		ret = xfr_task_expire(set, i, rq);
		break;
	default:
		break;
	}

	/* Close if not valid anymore. */
	if (ret != KNOT_EOK) {
		if (xfr_task_is_transfer(rq))
			xfr_pending_decr(xfr);
		xfr_task_close(rq);
		close(set->pfd[i].fd);
		return FDSET_SWEEP;
	}

	return FDSET_KEEP;
}

int xfr_worker(dthread_t *thread)
{
	assert(thread != NULL && thread->data != NULL);
	xfrhandler_t *xfr = (xfrhandler_t *)thread->data;

	/* Buffer for answering. */
	size_t buflen = KNOT_WIRE_MAX_PKTSIZE;
	uint8_t* buf = malloc(buflen);
	if (buf == NULL) {
		dbg_xfr("xfr: failed to allocate buffer for XFR worker\n");
		return KNOT_ENOMEM;
	}

	/* Next sweep time. */
	timev_t next_sweep;
	time_now(&next_sweep);
	next_sweep.tv_sec += XFR_SWEEP_INTERVAL;

	/* Approximate thread capacity limits. */
	unsigned threads = xfr->unit->size;
	unsigned thread_capacity = XFR_MAX_TASKS / threads;

	/* Set of connections. */
	fdset_t set;
	int ret = fdset_init(&set, thread_capacity);
	if (ret != KNOT_EOK) {
		free(buf);
		return ret;
	}

	/* Accept requests. */
	for (;;) {

		/* Populate pool with new requests. */
		unsigned newconns = 0;
		for (;;) {
			/* Do not exceed thread capacity. */
			if (set.n >= thread_capacity || newconns > XFR_CHUNKLEN)
				break;

			/* Tak first request. */
			pthread_mutex_lock(&xfr->mx);
			if (EMPTY_LIST(xfr->queue)) {
				pthread_mutex_unlock(&xfr->mx);
				break;
			}

			/* Limit number of transfers. */
			knot_ns_xfr_t *rq = HEAD(xfr->queue);
			unsigned is_transfer = xfr_task_is_transfer(rq);
			if (is_transfer && !xfr_pending_incr(xfr)) {
				pthread_mutex_unlock(&xfr->mx);
				break;
			}

			rem_node(&rq->n);
			pthread_mutex_unlock(&xfr->mx);

			/* Start asynchronous connect. */
			xfr_async_setbuf(rq, buf, buflen);
			if (xfr_async_start(&set, rq) != KNOT_EOK) {
				if (is_transfer)
					xfr_pending_decr(xfr);
				xfr_task_close(rq);
				break;
			}

			++newconns;
		}

		/* Check pending threads. */
		if (dt_is_cancelled(thread) || set.n == 0) {
			break;
		}

		/* Poll fdset. */
		int nfds = poll(set.pfd, set.n, XFR_SWEEP_INTERVAL * 1000);
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* Iterate fdset. */
		unsigned i = 0;
		while (nfds > 0 && i < set.n && !dt_is_cancelled(thread)) {

			knot_ns_xfr_t *rq = (knot_ns_xfr_t *)set.ctx[i];
			if (set.pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				/* Error events. */
				--nfds;           /* Treat error event as activity. */
				ret = KNOT_ECONN; /* Force disconnect */
			} else if (set.pfd[i].revents & set.pfd[i].events) {
				/* One less active event. */
				--nfds;
				/* Process pending tasks. */
				if (rq->flags & XFR_FLAG_CONNECTING)
					ret = xfr_async_finish(&set, i);
				else
					ret = xfr_process_event(xfr, rq);
			} else {
				/* Inactive connection. */
				++i;
				continue;
			}

			/* Check task state. */
			if (ret != KNOT_EOK) {
				if (xfr_task_is_transfer(rq))
					xfr_pending_decr(xfr);
				xfr_task_close(rq);
				close(set.pfd[i].fd);
				fdset_remove(&set, i);
				continue; /* Stay on the same index. */
			} else {
				/* Connection is active, update watchdog. */
				if (rq->type == XFR_TYPE_NOTIFY) {
					fdset_set_watchdog(&set, i, NOTIFY_TIMEOUT);
				} else {
					fdset_set_watchdog(&set, i, conf()->max_conn_idle);
				}
			}

			/* Next active. */
			++i;
		}

		/* Sweep inactive. */
		timev_t now;
		if (time_now(&now) == 0) {
			if (now.tv_sec >= next_sweep.tv_sec) {
				fdset_sweep(&set, &xfr_sweep, xfr);
				memcpy(&next_sweep, &now, sizeof(next_sweep));
				next_sweep.tv_sec += XFR_SWEEP_INTERVAL;
			}
		}
	}

	/* Cancel existing connections. */
	for (unsigned i = 0; i < set.n; ++i) {
		knot_ns_xfr_t *rq = (knot_ns_xfr_t *)set.ctx[i];
		close(set.pfd[i].fd);
		if (xfr_task_is_transfer(rq))
			xfr_pending_decr(xfr);
		xfr_task_free(rq);
	}

	fdset_clear(&set);
	free(buf);
	return KNOT_EOK;
}

/*
 * Public APIs.
 */

xfrhandler_t *xfr_create(size_t thrcount, struct server_t *server)
{
	/* Create XFR handler data. */
	xfrhandler_t *xfr = malloc(sizeof(xfrhandler_t));
	if (xfr == NULL) {
		return NULL;
	}
	memset(xfr, 0, sizeof(xfrhandler_t));
	xfr->server = server;

	/* Create threading unit. */
	xfr->unit = dt_create(thrcount, xfr_worker, NULL, xfr);
	if (xfr->unit == NULL) {
		free(xfr);
		return NULL;
	}

	/* Create tasks structure and mutex. */
	pthread_mutex_init(&xfr->mx, 0);
	pthread_mutex_init(&xfr->pending_mx, 0);
	init_list(&xfr->queue);

	return xfr;
}

int xfr_free(xfrhandler_t *xfr)
{
	if (!xfr) {
		return KNOT_EINVAL;
	}

	/* Free RR mutex. */
	pthread_mutex_destroy(&xfr->pending_mx);
	pthread_mutex_destroy(&xfr->mx);

	/* Free pending queue. */
	knot_ns_xfr_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, xfr->queue) {
		xfr_task_free(n);
	}

	/* Delete unit. */
	dt_delete(&xfr->unit);
	free(xfr);

	return KNOT_EOK;
}

int xfr_stop(xfrhandler_t *xfr)
{
	if (!xfr) {
		return KNOT_EINVAL;
	}

	xfr_enqueue(xfr, NULL);
	return dt_stop(xfr->unit);
}

int xfr_join(xfrhandler_t *xfr) {
	return dt_join(xfr->unit);
}

int xfr_enqueue(xfrhandler_t *xfr, knot_ns_xfr_t *rq)
{
	if (!xfr) {
		return KNOT_EINVAL;
	}

	if (rq) {
		pthread_mutex_lock(&xfr->mx);
		add_tail(&xfr->queue, &rq->n);
		pthread_mutex_unlock(&xfr->mx);
	}

	/* Notify threads. */
	for (unsigned i = 0; i < xfr->unit->size; ++i) {
		dt_activate(xfr->unit->threads[i]);
	}

	return KNOT_EOK;
}

knot_ns_xfr_t *xfr_task_create(zone_t *zone, int type, int flags)
{
	if (zone == NULL) {
		return NULL; /* Invalid. */
	}

	knot_ns_xfr_t *rq = malloc(sizeof(knot_ns_xfr_t));
	if (rq == NULL) {
		return NULL;
	}
	memset(rq, 0, sizeof(knot_ns_xfr_t));

	/* Initialize. */
	rq->type = type;
	rq->flags = flags;
	rq->zone = zone;
	zone_retain(rq->zone);
	return rq;
}

int xfr_task_free(knot_ns_xfr_t *rq)
{
	if (!rq) {
		return KNOT_EINVAL;
	}

	/* Free TSIG buffers. */
	free(rq->digest);
	rq->digest = NULL;
	rq->digest_size = 0;
	free(rq->tsig_data);
	rq->tsig_data = NULL;
	rq->tsig_data_size = 0;

	/* Cleanup transfer-specifics. */
	xfr_task_cleanup(rq);

	/* No further access to zone. */
	zone_release(rq->zone);
	free(rq->msg);
	rq->msg = NULL;
	free(rq);

	/* Trim extra heap. */
	mem_trim();

	return KNOT_EOK;
}

int xfr_task_setaddr(knot_ns_xfr_t *rq,
                     const struct sockaddr_storage *to,
                     const struct sockaddr_storage *from)
{
	if (!rq) {
		return KNOT_EINVAL;
	}

	memcpy(&rq->addr, to, sizeof(struct sockaddr_storage));
	memcpy(&rq->saddr, from, sizeof(struct sockaddr_storage));

	return KNOT_EOK;
}

char *xfr_remote_str(const struct sockaddr_storage *addr, const char *key)
{
	if (!addr) {
		return NULL;
	}

	/* Prepare address strings. */
	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(addr, addr_str, sizeof(addr_str));

	/* Prepare key strings. */
	if (key) {
		return sprintf_alloc("'%s' key '%s'", addr_str, key);
	} else {
		return sprintf_alloc("'%s'", addr_str);
	}
}
