#include <config.h>

#include "libknot/nameserver/ixfr.h"
#include "libknot/nameserver/ns_proc_query.h"
#include "common/descriptor.h"

int ixfr_answer(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	qdata->rcode = KNOT_RCODE_NOTIMPL;
	return NS_PROC_FAIL;
}

int ixfr_answer_soa(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata)
{
	if (pkt == NULL || ns == NULL || qdata == NULL) {
		return NS_PROC_FAIL;
	}

	/* Check zone state. */
	const knot_zone_t *zone = pkt->zone;
	switch(knot_zone_state(zone)) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		return NS_PROC_FAIL;
	default:
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}

	/* Guaranteed to have zone contents. */
	const knot_node_t *apex = zone->contents->apex;
	const knot_rrset_t *soa_rr = knot_node_rrset(apex, KNOT_RRTYPE_SOA);
	int ret = knot_pkt_put(pkt, 0, soa_rr, 0);
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}

	return NS_PROC_FINISH;
}
