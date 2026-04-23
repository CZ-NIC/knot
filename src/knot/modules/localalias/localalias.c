/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief ALIAS record synthesis from locally-served targets.
 *
 * When a zone node carries one or more ALIAS records (type 65401), this
 * module synthesises answers at query time by looking up the target in the
 * server's zone database and copying its records into the response, with
 * the original query name as the owner.
 *
 * Hooked at KNOTD_STAGE_PREANSWER so that the standard put_answer path
 * never sees an ALIAS node for normal queries.  The client sees only
 * synthesised target records (or NODATA if the target is not served
 * locally).  Explicit TYPE65401, RRSIG, NSEC and ANY queries are passed
 * through to the standard resolver so it can return whatever is actually
 * on the node (including the raw ALIAS record).
 *
 * Non-ALIAS nodes are passed through untouched; the normal resolver
 * handles them.
 *
 * Behaviour summary:
 *   * ALIAS is additive: if the node also has direct rrsets of the
 *     queried type, both direct and target records are merged.
 *   * Multiple ALIAS rdata are followed in turn and merged.
 *   * TTL = min(alias_ttl, all contributing source TTLs).
 *   * Targets not served locally are silently ignored.
 *   * Synthesised records are not DNSSEC-signed.
 */

#include <assert.h>
#include <stdbool.h>

#include "knot/include/module.h"
#include "knot/nameserver/process_query.h"
#include "knot/server/server.h"
#include "knot/zone/contents.h"
#include "knot/zone/zonedb.h"
#include "contrib/macros.h"
#include "libknot/libknot.h"
#include "libknot/rrtype/rdname.h"

/*!
 * \brief Find a locally-served target node.
 */
static const zone_node_t *find_target_node(server_t *server,
                                           const knot_dname_t *target)
{
	zone_t *tz = knot_zonedb_find_suffix(server->zone_db, target);
	if (tz == NULL || tz->contents == NULL) {
		return NULL;
	}
	const zone_node_t *tn = NULL, *cl = NULL, *pv = NULL;
	if (zone_contents_find_dname(tz->contents, target, &tn, &cl, &pv, false)
	    != ZONE_NAME_FOUND || tn == NULL) {
		return NULL;
	}
	return tn;
}

static int merge_target(const zone_node_t *tn, uint16_t rtype,
                        knot_mm_t *mm, knot_rrset_t *synth)
{
	knot_rrset_t src = node_rrset(tn, rtype);
	if (knot_rrset_empty(&src)) {
		return KNOT_ENOENT;
	}
	synth->ttl = MIN(synth->ttl, src.ttl);
	if (knot_rdataset_merge(&synth->rrs, &src.rrs, mm) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}
	return KNOT_EOK;
}

/*!
 * \brief Resolve the query name in the zone, including wildcard expansion.
 *
 * Populates qdata->extra->{node,encloser,previous} as a side-effect, so
 * downstream stages (AUTHORITY, ADDITIONAL) see the correct node.
 *
 * \return The resolved node, or NULL if the name is not in the zone.
 */
static const zone_node_t *resolve_name(knotd_qdata_t *qdata)
{
	int ret = zone_contents_find_dname(
		qdata->extra->contents, qdata->name,
		&qdata->extra->node, &qdata->extra->encloser,
		&qdata->extra->previous,
		qdata->query->flags & KNOT_PF_NULLBYTE);

	if (ret == ZONE_NAME_FOUND) {
		return qdata->extra->node;
	}

	if (ret == ZONE_NAME_NOT_FOUND &&
	    qdata->extra->encloser != NULL &&
	    (qdata->extra->encloser->flags & NODE_FLAGS_WILDCARD_CHILD)) {
		const zone_node_t *wc = zone_contents_find_wildcard_child(
			qdata->extra->contents, qdata->extra->encloser);
		if (wc != NULL) {
			qdata->extra->node = wc;
			return wc;
		}
	}

	return NULL;
}

/*!
 * \brief PREANSWER hook: intercept ALIAS nodes before put_answer runs.
 *
 * If the query name resolves to a node with ALIAS records, we do full
 * synthesis here and return KNOTD_IN_STATE_HIT.  solve_answer() sees
 * HIT and skips, so the raw ALIAS record is never placed in the packet.
 *
 * For non-ALIAS nodes we return state unchanged (BEGIN) and the normal
 * resolver handles everything.
 */
static knotd_in_state_t solve_localalias(knotd_in_state_t state, knot_pkt_t *pkt,
                                         knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	if (state != KNOTD_IN_STATE_BEGIN) {
		return state;
	}
	if (qdata->extra == NULL || qdata->extra->contents == NULL) {
		return state;
	}

	uint16_t qtype = knot_pkt_qtype(pkt);

	/* ALIAS/RRSIG/NSEC/ANY queries are handled by the normal resolver:
	 * explicit TYPE65401 returns the raw ALIAS record for diagnostics,
	 * and for ANY the standard answering routines return whatever is on
	 * the node (including the raw ALIAS record). */
	if (qtype == KNOT_RRTYPE_ALIAS || qtype == KNOT_RRTYPE_RRSIG
	    || qtype == KNOT_RRTYPE_NSEC || qtype == KNOT_RRTYPE_ANY) {
		return state;
	}

	/* Resolve the query name (exact match or wildcard). */
	const zone_node_t *node = resolve_name(qdata);
	if (node == NULL) {
		return state; /* NXDOMAIN — let solve_answer handle it. */
	}

	knot_rrset_t alias_rr = node_rrset(node, KNOT_RRTYPE_ALIAS);
	if (knot_rrset_empty(&alias_rr)) {
		return state; /* No ALIAS on this node — normal resolver. */
	}

	/* ---- This is an ALIAS node.  We handle it entirely. ---- */

	server_t *server = (server_t *)qdata->params->server;

	knot_dname_t *owner = knot_dname_copy(qdata->name, &pkt->mm);
	if (owner == NULL) {
		return KNOTD_IN_STATE_ERROR;
	}
	knot_rrset_t synth;
	knot_rrset_init(&synth, owner, qtype, KNOT_CLASS_IN, alias_rr.ttl);

	/* Merge records from each target. */
	knot_rdata_t *rdata = alias_rr.rrs.rdata;
	for (uint16_t j = 0; j < alias_rr.rrs.count;
	     j++, rdata = knot_rdataset_next(rdata)) {
		const zone_node_t *tn = find_target_node(server,
		                                         knot_alias_name(rdata));
		if (tn == NULL) {
			continue;
		}
		int ret = merge_target(tn, qtype, &pkt->mm, &synth);
		if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
			return KNOTD_IN_STATE_ERROR;
		}
	}

	/* Also merge direct records of this type on the alias node
	 * (additive: ALIAS augments, not replaces). */
	int ret = merge_target(node, qtype, &pkt->mm, &synth);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		return KNOTD_IN_STATE_ERROR;
	}

	if (!knot_rrset_empty(&synth)) {
		ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &synth,
		                   KNOT_PF_FREE);
		switch (ret) {
		case KNOT_EOK:
			knot_wire_set_aa(pkt->wire);
			return KNOTD_IN_STATE_HIT;
		case KNOT_ESPACE:
			return KNOTD_IN_STATE_TRUNC;
		default:
			return KNOTD_IN_STATE_ERROR;
		}
	}

	/* ALIAS present but no records synthesised (e.g. target not local).
	 * Return NODATA — solve_answer sees this and does nothing useful
	 * (no matching rrtype to return). */
	qdata->rcode = KNOT_RCODE_NOERROR;
	return KNOTD_IN_STATE_NODATA;
}

int localalias_load(knotd_mod_t *mod)
{
	return knotd_mod_in_hook(mod, KNOTD_STAGE_PREANSWER, solve_localalias);
}

KNOTD_MOD_API(localalias, KNOTD_MOD_FLAG_SCOPE_ZONE | KNOTD_MOD_FLAG_OPT_CONF,
              localalias_load, NULL, NULL, NULL);
