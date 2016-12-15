/*  Copyright (C) 2016 Fastly, Inc.

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

#include "knot/modules/whoami/whoami.h"

const yp_item_t scheme_mod_whoami[] = {
	{ C_ID,         YP_TSTR, YP_VNONE },
	{ C_COMMENT,    YP_TSTR, YP_VNONE },
	{ NULL }
};

static int whoami_query(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	knot_rrset_t *rrset = NULL;

	/* Sanity checks. */
	if (pkt == NULL ||
	    qdata == NULL ||
	    qdata->query == NULL ||
	    qdata->param == NULL || qdata->param->remote == NULL ||
	    qdata->zone == NULL || qdata->zone->name == NULL ||
	    qdata->zone->contents == NULL || qdata->zone->contents->apex == NULL)
	{
		return ERROR;
	}

	/* Retrieve the query tuple. */
	const knot_dname_t *qname = knot_pkt_qname(qdata->query);
	const uint16_t qtype = knot_pkt_qtype(qdata->query);
	const uint16_t qclass = knot_pkt_qclass(qdata->query);

	/* We only generate A and AAAA records, which are Internet class. */
	if (qclass != KNOT_CLASS_IN) {
		return state;
	}

	/* Only handle queries with qname set to the zone name. */
	if (!knot_dname_is_equal(qname, qdata->zone->name)) {
		return state;
	}

	/* Only handle A and AAAA queries. */
	if (qtype != KNOT_RRTYPE_A && qtype != KNOT_RRTYPE_AAAA) {
		return state;
	}

	/* Retrieve the IP address that sent the query. */
	const struct sockaddr_storage *query_source = qdata->param->remote;
	if (query_source == NULL) {
		return ERROR;
	}

	/* If the socket address family corresponds to the query type (i.e.,
	 * AF_INET <-> A and AF_INET6 <-> AAAA), put the socket address and
	 * length into 'rdata' and 'len_rdata'.
	 */
	const void *rdata = NULL;
	size_t len_rdata = 0;
	if (query_source->ss_family == AF_INET && qtype == KNOT_RRTYPE_A) {
		const struct sockaddr_in *sai = (struct sockaddr_in *)query_source;
		rdata = &sai->sin_addr.s_addr;
		len_rdata = sizeof(sai->sin_addr.s_addr);
	} else if (query_source->ss_family == AF_INET6 && qtype == KNOT_RRTYPE_AAAA) {
		const struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *)query_source;
		rdata = &sai6->sin6_addr;
		len_rdata = sizeof(sai6->sin6_addr);
	} else {
		/* Query type didn't match address family. */
		return state;
	}

	/* Sanity check, since knot_rrset_add_rdata() takes a uint16_t length
	 * parameter.
	 */
	if (len_rdata > UINT16_MAX) {
		return state;
	}

	/* Synthesize the response RRset. */

	/* Owner name, type, and class are taken from the question. */
	rrset = knot_rrset_new(qname, qtype, qclass, &pkt->mm);
	if (rrset == NULL) {
		return ERROR;
	}

	/* TTL is taken from the TTL of the SOA record. */
	uint32_t ttl = 0;
	const zone_node_t *apex = qdata->zone->contents->apex;
	for (uint16_t i = 0; apex != NULL && i < apex->rrset_count; i++) {
		const struct rr_data *rr_data = &apex->rrs[i];
		if (rr_data->type == KNOT_RRTYPE_SOA) {
			ttl = knot_rdataset_ttl(&rr_data->rrs);
			break;
		}
	}

	/* Record data is the query source address. */
	int ret = knot_rrset_add_rdata(rrset, rdata, len_rdata, ttl, &pkt->mm);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&rrset, &pkt->mm);
		return ERROR;
	}

	/* Add the new RRset to the response packet. */
	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, rrset, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&rrset, &pkt->mm);
		return ERROR;
	}

	/* Success. */
	return HIT;
}

int whoami_load(struct query_plan *plan, struct query_module *self,
                const knot_dname_t *zone)
{
	/* Sanity checks. */
	if (plan == NULL || self == NULL) {
		return KNOT_EINVAL;
	}

	/* Hook to the query plan. */
	query_plan_step(plan, QPLAN_ANSWER, whoami_query, NULL);

	return KNOT_EOK;
}

int whoami_unload(struct query_module *self)
{
	/* Sanity check. */
	if (self == NULL) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}
