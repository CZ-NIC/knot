/*  Copyright (C) 2017 Fastly, Inc.

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

#include <netinet/in.h>

#include "knot/include/module.h"

static knotd_in_state_t whoami_query(knotd_in_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata);

	const knot_dname_t *zone_name = knotd_qdata_zone_name(qdata);
	if (zone_name == NULL) {
		return KNOTD_IN_STATE_ERROR;
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
	if (!knot_dname_is_equal(qname, zone_name)) {
		return state;
	}

	/* Only handle A and AAAA queries. */
	if (qtype != KNOT_RRTYPE_A && qtype != KNOT_RRTYPE_AAAA) {
		return state;
	}

	/* Retrieve the IP address that sent the query. */
	const struct sockaddr_storage *query_source = qdata->params->remote;
	if (query_source == NULL) {
		return KNOTD_IN_STATE_ERROR;
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

	/* TTL is taken from the TTL of the SOA record. */
	knot_rrset_t soa = knotd_qdata_zone_apex_rrset(qdata, KNOT_RRTYPE_SOA);

	/* Owner name, type, and class are taken from the question. */
	knot_rrset_t *rrset = knot_rrset_new(qname, qtype, qclass, soa.ttl, &pkt->mm);
	if (rrset == NULL) {
		return KNOTD_IN_STATE_ERROR;
	}

	/* Record data is the query source address. */
	int ret = knot_rrset_add_rdata(rrset, rdata, len_rdata, &pkt->mm);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&rrset, &pkt->mm);
		return KNOTD_IN_STATE_ERROR;
	}

	/* Add the new RRset to the response packet. */
	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, rrset, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&rrset, &pkt->mm);
		return KNOTD_IN_STATE_ERROR;
	}

	/* Success. */
	return KNOTD_IN_STATE_HIT;
}

int whoami_load(knotd_mod_t *mod)
{
	/* Hook to the query plan. */
	knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, whoami_query);

	return KNOT_EOK;
}

KNOTD_MOD_API(whoami, KNOTD_MOD_FLAG_SCOPE_ZONE | KNOTD_MOD_FLAG_OPT_CONF,
              whoami_load, NULL, NULL, NULL);
