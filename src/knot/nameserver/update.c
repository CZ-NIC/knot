#include <config.h>

#include "knot/nameserver/update.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/name-server.h"
#include "libknot/util/debug.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/ddns.h"
#include "common/descriptor.h"
#include "knot/server/zones.h"

static int update_forward(struct query_data *qdata)
{
	/*! \todo This will be implemented when RESPONSE and REQUEST processors
	 *        are written. */
#if 0
	const zone_t* zone = qdata->zone;
	knot_pkt_t *query = qdata->pkt;
	const sockaddr_t *from = &qdata->param->query_source;

	rcu_read_lock();

	/* Check transport type. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	unsigned flags = XFR_FLAG_UDP;
	if (ttype == NS_TRANSPORT_TCP) {
		flags = XFR_FLAG_TCP;
	}

	/* Prepare task. */
	knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_FORWARD, flags);
	if (!rq) {
		rcu_read_unlock();
		return KNOT_ENOMEM;
	}
	xfr_task_setaddr(rq, &zd->xfr_in.master, &zd->xfr_in.via);

	/* Copy query originator data. */
	rq->fwd_src_fd = fd;
	memcpy(&rq->fwd_addr, from, sizeof(sockaddr_t));
	rq->packet_nr = knot_wire_get_id(query->wire);

	/* Duplicate query to keep it in memory during forwarding. */
	rq->query = knot_pkt_new(NULL, query->size, NULL);
	if (!rq->query) {
		xfr_task_free(rq);
		rcu_read_unlock();
		return KNOT_ENOMEM;
	}
	memcpy(rq->query->wire, query->wire, query->size);

	/* Retain pointer to zone and issue. */
	rcu_read_unlock();
	int ret = xfr_enqueue(zd->server->xfr, rq);
	if (ret != KNOT_EOK) {
		xfr_task_free(rq);
	}
#endif

	qdata->rcode = KNOT_RCODE_NOTIMPL;
	return NS_PROC_FAIL;
}

static int update_process(knot_pkt_t *resp, struct query_data *qdata)
{
	/*! \todo Reusing the API for compatibility reasons. */
	knot_rcode_t rcode = qdata->rcode;
	int ret = zones_process_update_auth((zone_t *)qdata->zone, qdata->query,
	                                    &rcode,
	                                    &qdata->param->query_source,
	                                    qdata->sign.tsig_key);
	qdata->rcode = rcode;
	return ret;
}

static int update_prereq_check(struct query_data *qdata)
{
	knot_pkt_t *query = qdata->query;
	const knot_zone_contents_t *contents = qdata->zone->contents;

	/*
	 * 2) DDNS Prerequisities Section processing (RFC2136, Section 3.2).
	 *
	 * \note Permissions section means probably policies and fine grained
	 *       access control, not transaction security.
	 */
	knot_rcode_t rcode = KNOT_RCODE_NOERROR;
	knot_ddns_prereq_t *prereqs = NULL;
	int ret = knot_ddns_process_prereqs(query, &prereqs, &rcode);
	if (ret == KNOT_EOK) {
		ret = knot_ddns_check_prereqs(contents, &prereqs, &rcode);
		knot_ddns_prereqs_free(&prereqs);
	}
	qdata->rcode = rcode;

	return ret;
}

int update_answer(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	/* RFC1996 require SOA question. */
	NS_NEED_QTYPE(qdata, KNOT_RRTYPE_SOA, KNOT_RCODE_FORMERR);

	/*! \note NOTIFY/RFC1996 isn't clear on error RCODEs.
	 *        Most servers use NOTAUTH from RFC2136. */
	NS_NEED_VALID_ZONE(qdata, KNOT_RCODE_NOTAUTH);

	zone_t *zone = (zone_t *)qdata->zone;

	/* Allow pass-through of an unknown TSIG in DDNS forwarding (must have zone). */
	if (zone->xfr_in.has_master) {
		return update_forward(qdata);
	}

	/* Need valid transaction security. */
	NS_NEED_AUTH(zone->update_in, qdata);

	/*
	 * Check if UPDATE not running already.
	 */
	if (pthread_mutex_trylock(&zone->ddns_lock) != 0) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		log_zone_error("Failed to process UPDATE for "
		               "zone %s: Another UPDATE in progress.\n",
		               zone->conf->name);
		return NS_PROC_FAIL;
	}

	/* Reserve space for TSIG. */
	knot_pkt_tsig_set(pkt, qdata->sign.tsig_key);

	/* Check prerequisites. */
	if (update_prereq_check(qdata) != KNOT_EOK) {
		pthread_mutex_unlock(&zone->ddns_lock);
		return NS_PROC_FAIL;
	}

	/* Process UPDATE. */
	if (update_process(pkt, qdata) != KNOT_EOK) {
		pthread_mutex_unlock(&zone->ddns_lock);
		return NS_PROC_FAIL;
	}

	pthread_mutex_unlock(&zone->ddns_lock);
	return NS_PROC_DONE;
}
