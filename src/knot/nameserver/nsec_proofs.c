/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>

#include "libknot/libknot.h"
#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/internet.h"
#include "knot/dnssec/zone-nsec.h"

/*!
 * \brief Check if node is empty non-terminal.
 */
static bool empty_nonterminal(const zone_node_t *node)
{
	return node && node->rrset_count == 0;
}

/*!
 * \brief Check if wildcard expansion happened for given node and QNAME.
 */
static bool wildcard_expanded(const zone_node_t *node, const knot_dname_t *qname)
{
	return !knot_dname_is_wildcard(qname) && knot_dname_is_wildcard(node->owner);
}

/*!
 * \brief Check if opt-out can take an effect.
 */
static bool ds_optout(const zone_node_t *node)
{
	return node->nsec3_node == NULL && node->flags & NODE_FLAGS_DELEG;
}

/*!
 * \brief Check if node is part of the NSEC chain.
 *
 * NSEC is created for each node with authoritative data or delegation.
 *
 * \see https://tools.ietf.org/html/rfc4035#section-2.3
 */
static bool node_in_nsec(const zone_node_t *node)
{
	return (node->flags & NODE_FLAGS_NONAUTH) == 0 && !empty_nonterminal(node);
}

/*!
 * \brief Check if node is part of the NSEC3 chain.
 *
 * NSEC3 is created for each node with authoritative data, empty-non terminal,
 * and delegation (unless opt-out is in effect).
 *
 * \see https://tools.ietf.org/html/rfc5155#section-7.1
 */
static bool node_in_nsec3(const zone_node_t *node)
{
	return (node->flags & NODE_FLAGS_NONAUTH) == 0 && !ds_optout(node);
}

/*!
 * \brief Walk previous names until we reach a node in NSEC chain.
 *
 */
static const zone_node_t *nsec_previous(const zone_node_t *previous)
{
	assert(previous);

	while (!node_in_nsec(previous)) {
		previous = previous->prev;
		assert(previous);
	}

	return previous;
}

/*!
 * \brief Get closest provable encloser from closest matching parent node.
 */
static const zone_node_t *nsec3_encloser(const zone_node_t *closest)
{
	assert(closest);

	while (!node_in_nsec3(closest)) {
		closest = closest->parent;
		assert(closest);
	}

	return closest;
}

/*!
 * \brief Create a 'next closer name' to the given domain name.
 *
 * Next closer is the name one label longer than the closest provable encloser
 * of a name.
 *
 * \see https://tools.ietf.org/html/rfc5155#section-1.3
 *
 * \param closest_encloser  Closest provable encloser of \a name.
 * \param name              Domain name to create the 'next closer' name to.
 *
 * \return Next closer name, NULL on error.
 */
static const knot_dname_t *get_next_closer(const knot_dname_t *closest_encloser,
                                           const knot_dname_t *name)
{
	size_t ce_labels = knot_dname_labels(closest_encloser, NULL);
	size_t qname_labels = knot_dname_labels(name, NULL);

	// the common labels should match
	assert(knot_dname_matched_labels(closest_encloser, name) == ce_labels);

	// chop some labels from the qname
	for (int i = 0; i < (qname_labels - ce_labels - 1); ++i) {
		name = knot_wire_next_label(name, NULL);
	}

	return name;
}

/*!
 * \brief Put NSEC/NSEC3 record with corresponding RRSIG into the response.
 */
static int put_nxt_from_node(const zone_node_t *node,
                             uint16_t type,
                             knotd_qdata_t *qdata,
                             knot_pkt_t *resp)
{
	assert(type == KNOT_RRTYPE_NSEC || type == KNOT_RRTYPE_NSEC3);

	knot_rrset_t rrset = node_rrset(node, type);
	if (knot_rrset_empty(&rrset)) {
		return KNOT_EOK;
	}

	knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);

	return process_query_put_rr(resp, qdata, &rrset, &rrsigs,
	                            KNOT_COMPR_HINT_NONE, KNOT_PF_CHECKDUP);
}

/*!
 * \brief Put NSEC record with corresponding RRSIG into the response.
 */
static int put_nsec_from_node(const zone_node_t *node,
                              knotd_qdata_t *qdata,
                              knot_pkt_t *resp)
{
	return put_nxt_from_node(node, KNOT_RRTYPE_NSEC, qdata, resp);
}

/*!
 * \brief Put NSEC3 record with corresponding RRSIG into the response.
 */
static int put_nsec3_from_node(const zone_node_t *node,
                               knotd_qdata_t *qdata,
                               knot_pkt_t *resp)
{
	return put_nxt_from_node(node, KNOT_RRTYPE_NSEC3, qdata, resp);
}

/*!
 * \brief Find NSEC for given name and put it into the response.
 *
 * Note this function allows the name to match the QNAME. The NODATA proof
 * for empty non-terminal is equivalent to NXDOMAIN proof, except that the
 * names may exist. This is why.
 */
static int put_covering_nsec(const zone_contents_t *zone,
                             const knot_dname_t *name,
                             knotd_qdata_t *qdata,
                             knot_pkt_t *resp)
{
	const zone_node_t *match = NULL;
	const zone_node_t *closest = NULL;
	const zone_node_t *prev = NULL;

	const zone_node_t *proof = NULL;

	int ret = zone_contents_find_dname(zone, name, &match, &closest, &prev);
	if (ret == ZONE_NAME_FOUND) {
		proof = match;
	} else if (ret == ZONE_NAME_NOT_FOUND) {
		proof = nsec_previous(prev);
	} else {
		assert(ret < 0);
		return ret;
	}

	return put_nsec_from_node(proof, qdata, resp);
}

/*!
 * \brief Find NSEC3 covering the given name and put it into the response.
 */
static int put_covering_nsec3(const zone_contents_t *zone,
                              const knot_dname_t *name,
                              knotd_qdata_t *qdata,
                              knot_pkt_t *resp)
{
	const zone_node_t *prev = NULL;
	const zone_node_t *node = NULL;

	int match = zone_contents_find_nsec3_for_name(zone, name, &node, &prev);
	if (match < 0) {
		// ignore if missing
		return KNOT_EOK;
	}

	if (match == ZONE_NAME_FOUND || prev == NULL){
		return KNOT_ERROR;
	}

	return put_nsec3_from_node(prev, qdata, resp);
}

/*!
 * \brief Add NSEC3 covering the next closer name to closest encloser.
 *
 * \param cpe    Closest provable encloser of \a qname.
 * \param qname  Source QNAME.
 * \param zone   Source zone.
 * \param qdata  Query processing data.
 * \param resp   Response packet.
 *
 * \return KNOT_E*
 */
static int put_nsec3_next_closer(const zone_node_t *cpe,
                                 const knot_dname_t *qname,
                                 const zone_contents_t *zone,
                                 knotd_qdata_t *qdata,
                                 knot_pkt_t *resp)
{
	const knot_dname_t *next_closer = get_next_closer(cpe->owner, qname);

	return put_covering_nsec3(zone, next_closer, qdata, resp);
}

/*!
 * \brief Add NSEC3s for closest encloser proof.
 *
 * Adds up to two NSEC3 records. The first one proves that closest encloser
 * of the queried name exists, the second one proves that the name bellow the
 * encloser doesn't.
 *
 * \see https://tools.ietf.org/html/rfc5155#section-7.2.1
 *
 * \param qname  Source QNAME.
 * \param zone   Source zone.
 * \param cpe    Closest provable encloser of \a qname.
 * \param qdata  Query processing data.
 * \param resp   Response packet.
 *
 * \return KNOT_E*
 */
static int put_closest_encloser_proof(const knot_dname_t *qname,
                                      const zone_contents_t *zone,
                                      const zone_node_t *cpe,
                                      knotd_qdata_t *qdata,
                                      knot_pkt_t *resp)
{
	// An NSEC3 RR that matches the closest (provable) encloser.

	int ret = put_nsec3_from_node(cpe->nsec3_node, qdata, resp);
	if (ret !=  KNOT_EOK) {
		return ret;
	}

	// An NSEC3 RR that covers the "next closer" name to the closest encloser.

	return put_nsec3_next_closer(cpe, qname, zone, qdata, resp);
}

/*!
 * \brief Put NSEC for wildcard answer into the response.
 *
 * Add NSEC record proving that no better match on QNAME exists.
 *
 * \see https://tools.ietf.org/html/rfc4035#section-3.1.3.3
 *
 * \param previous  Previous name for QNAME.
 * \param qdata     Query processing data.
 * \param resp      Response packet.
 *
 * \return KNOT_E*
 */
static int put_nsec_wildcard(const zone_node_t *previous,
                             knotd_qdata_t *qdata,
                             knot_pkt_t *resp)
{
	return put_nsec_from_node(previous, qdata, resp);
}

/*!
 * \brief Put NSEC3s for wildcard answer into the response.
 *
 * Add NSEC3 record proving that no better match on QNAME exists.
 *
 * \see https://tools.ietf.org/html/rfc5155#section-7.2.6
 *
 * \param wildcard  Wildcard node that was used for expansion.
 * \param qname     Source QNAME.
 * \param zone      Source zone.
 * \param qdata     Query processing data.
 * \param resp      Response packet.
 */
static int put_nsec3_wildcard(const zone_node_t *wildcard,
                              const knot_dname_t *qname,
                              const zone_contents_t *zone,
                              knotd_qdata_t *qdata,
                              knot_pkt_t *resp)
{
	const zone_node_t *cpe = nsec3_encloser(wildcard->parent);

	return put_nsec3_next_closer(cpe, qname, zone, qdata, resp);
}

/*!
 * \brief Put NSECs or NSEC3s for wildcard expansion in the response.
 *
 * \return KNOT_E*
 */
static int put_wildcard_answer(const zone_node_t *wildcard,
                               const zone_node_t *previous,
                               const zone_contents_t *zone,
                               const knot_dname_t *qname,
                               knotd_qdata_t *qdata,
                               knot_pkt_t *resp)
{
	if (!wildcard_expanded(wildcard, qname)) {
		return KNOT_EOK;
	}

	int ret = 0;

	if (knot_is_nsec3_enabled(zone)) {
		ret = put_nsec3_wildcard(wildcard, qname, zone, qdata, resp);
	} else {
		previous = nsec_previous(previous);
		ret = put_nsec_wildcard(previous, qdata, resp);
	}

	return ret;
}

/*!
 * \brief Create a wildcard child of a name as a local variable.
 *
 * \param out     Name of the output wariable.
 * \param parent  Parent of the wildcard.
 */
#define CREATE_WILDCARD(out, parent) \
	int size = knot_dname_size(parent); \
	if (size < 0 || size > KNOT_DNAME_MAXLEN - 2) return KNOT_EINVAL; \
	uint8_t out[2 + size]; \
	memcpy(out, "\x01""*", 2); \
	memcpy(out + 2, parent, size);

/*!
 * \brief Put NSECs for NXDOMAIN error into the response.
 *
 * Adds up to two NSEC records. We have to prove that the queried name doesn't
 * exist and that no wildcard expansion is possible for that name.
 *
 * \see https://tools.ietf.org/html/rfc4035#section-3.1.3.2
 *
 * \param zone      Source zone.
 * \param previous  Previous node to QNAME.
 * \param closest   Closest matching parent of QNAME.
 * \param qdata     Query data.
 * \param resp      Response packet.
 *
 * \return KNOT_E*
 */
static int put_nsec_nxdomain(const zone_contents_t *zone,
                             const zone_node_t *previous,
                             const zone_node_t *closest,
                             knotd_qdata_t *qdata,
                             knot_pkt_t *resp)
{
	assert(previous);
	assert(closest);

	// An NSEC RR proving that there is no exact match for <SNAME, SCLASS>.

	previous = nsec_previous(previous);
	int ret = put_nsec_from_node(previous, qdata, resp);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// An NSEC RR proving that the zone contains no RRsets that would match
	// <SNAME, SCLASS> via wildcard name expansion.

	// NOTE: closest may be empty non-terminal and thus not authoritative.

	CREATE_WILDCARD(wildcard, closest->owner)

	return put_covering_nsec(zone, wildcard, qdata, resp);
}

/*!
 * \brief Put NSEC3s for NXDOMAIN error into the response.
 *
 * Adds up to three NSEC3 records. We have to prove that some parent name
 * exists (closest encloser proof) and that no wildcard expansion is possible
 * bellow that closest encloser.
 *
 * \see https://tools.ietf.org/html/rfc5155#section-7.2.2
 *
 * \param qname    Source QNAME.
 * \param zone     Source zone.
 * \param closest  Closest matching parent of \a qname.
 * \param qdata    Query processing data.
 * \param resp     Response packet.
 *
 * \retval KNOT_E*
 */
static int put_nsec3_nxdomain(const knot_dname_t *qname,
                              const zone_contents_t *zone,
                              const zone_node_t *closest,
                              knotd_qdata_t *qdata,
                              knot_pkt_t *resp)
{
	const zone_node_t *cpe = nsec3_encloser(closest);

	// Closest encloser proof.

	int ret = put_closest_encloser_proof(qname, zone, cpe, qdata, resp);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// NSEC3 covering the (nonexistent) wildcard at the closest encloser.

	if (cpe->nsec3_wildcard_prev == NULL) {
		return KNOT_ERROR;
	}

	return put_nsec3_from_node(cpe->nsec3_wildcard_prev, qdata, resp);
}

/*!
 * \brief Put NSECs or NSEC3s for the NXDOMAIN error into the response.
 *
 * \param zone      Zone used for answering.
 * \param previous  Previous node to \a qname.
 * \param closest   Closest matching parent name for \a qname.
 * \param qname     Source QNAME.
 * \param qdata     Query processing data.
 * \param resp      Response packet.
 *
 * \return KNOT_E*
 */
static int put_nxdomain(const zone_contents_t *zone,
                        const zone_node_t *previous,
                        const zone_node_t *closest,
                        const knot_dname_t *qname,
                        knotd_qdata_t *qdata,
                        knot_pkt_t *resp)
{
	if (knot_is_nsec3_enabled(zone)) {
		return put_nsec3_nxdomain(qname, zone, closest, qdata, resp);
	} else {
		return put_nsec_nxdomain(zone, previous, closest, qdata, resp);
	}
}

/*!
 * \brief Put NSEC for NODATA error into the response.
 *
 * Then NSEC matching the QNAME must be added into the response and the bitmap
 * will indicate that the QTYPE doesn't exist. As NSECs for empty non-terminals
 * don't exist, the proof for NODATA match on non-terminal is proved as for
 * NXDOMAIN.
 *
 * \see https://tools.ietf.org/html/rfc4035#section-3.1.3.1
 * \see https://tools.ietf.org/html/rfc4035#section-3.1.3.2 (empty non-terminal)
 *
 * \param zone      Source zone.
 * \param match     Node matching QNAME.
 * \param previous  Previous node to QNAME in the zone.
 * \param qdata     Query procssing data.
 * \param resp      Response packet.
 *
 * \return KNOT_E*
 */
static int put_nsec_nodata(const zone_contents_t *zone,
                           const zone_node_t *match,
                           const zone_node_t *closest,
                           const zone_node_t *previous,
                           knotd_qdata_t *qdata,
                           knot_pkt_t *resp)
{
	if (empty_nonterminal(match)) {
		return put_nsec_nxdomain(zone, previous, closest, qdata, resp);
	} else {
		return put_nsec_from_node(match, qdata, resp);
	}
}

/*!
 * \brief Put NSEC3 for NODATA error into the response.
 *
 * The NSEC3 matching the QNAME is added into the response and the bitmap
 * will indicate that the QTYPE doesn't exist. For QTYPE==DS, the server
 * may alternatively serve a closest encloser proof with opt-out. For wildcard
 * expansion, the closest encloser proof must included as well.
 *
 * \see https://tools.ietf.org/html/rfc5155#section-7.2.3
 * \see https://tools.ietf.org/html/rfc5155#section-7.2.4
 * \see https://tools.ietf.org/html/rfc5155#section-7.2.5
 */
static int put_nsec3_nodata(const knot_dname_t *qname,
                           const zone_contents_t *zone,
                           const zone_node_t *match,
                           const zone_node_t *closest,
                           knotd_qdata_t *qdata,
                           knot_pkt_t *resp)
{
	int ret = KNOT_EOK;

	// NSEC3 matching QNAME is always included.

	if (match->nsec3_node) {
		ret = put_nsec3_from_node(match->nsec3_node, qdata, resp);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Closest encloser proof for wildcard effect or NSEC3 opt-out.

	if (wildcard_expanded(match, qname) || ds_optout(match)) {
		const zone_node_t *cpe = nsec3_encloser(closest);
		ret = put_closest_encloser_proof(qname, zone, cpe, qdata, resp);
	}

	return ret;
}

/*!
 * \brief Put NSECs or NSEC3s for the NODATA error into the response.
 *
 * \param node   Source node.
 * \param qdata  Query processing data.
 * \param resp   Response packet.
 */
static int put_nodata(const zone_node_t *node,
                      const zone_node_t *closest,
                      const zone_node_t *previous,
                      const zone_contents_t *zone,
                      const knot_dname_t *qname,
                      knotd_qdata_t *qdata,
                      knot_pkt_t *resp)
{
	if (knot_is_nsec3_enabled(zone)) {
		return put_nsec3_nodata(qname, zone, node, closest, qdata, resp);
	} else {
		return put_nsec_nodata(zone, node, closest, previous, qdata, resp);
	}
}

int nsec_prove_wildcards(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (qdata->extra->zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	struct wildcard_hit *item = NULL;

	WALK_LIST(item, qdata->extra->wildcards) {
		if (item->node == NULL) {
			return KNOT_EINVAL;
		}
		ret = put_wildcard_answer(item->node, item->prev,
		                          qdata->extra->zone->contents,
		                          item->sname, qdata, pkt);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	return ret;
}

int nsec_prove_nodata(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (qdata->extra->zone->contents == NULL || qdata->extra->node == NULL) {
		return KNOT_EINVAL;
	}

	return put_nodata(qdata->extra->node, qdata->extra->encloser, qdata->extra->previous,
	                  qdata->extra->zone->contents, qdata->name, qdata, pkt);
}

int nsec_prove_nxdomain(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (qdata->extra->zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	return put_nxdomain(qdata->extra->zone->contents,
	                    qdata->extra->previous, qdata->extra->encloser,
	                    qdata->name, qdata, pkt);
}

int nsec_prove_dp_security(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (qdata->extra->node == NULL || qdata->extra->encloser == NULL ||
	    qdata->extra->zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	// Add DS into the response.

	knot_rrset_t rrset = node_rrset(qdata->extra->node, KNOT_RRTYPE_DS);
	if (!knot_rrset_empty(&rrset)) {
		knot_rrset_t rrsigs = node_rrset(qdata->extra->node, KNOT_RRTYPE_RRSIG);
		return process_query_put_rr(pkt, qdata, &rrset, &rrsigs,
		                            KNOT_COMPR_HINT_NONE, 0);
	}

	// Alternatively prove that DS doesn't exist.

	return put_nodata(qdata->extra->node, qdata->extra->encloser, qdata->extra->previous,
	                  qdata->extra->zone->contents, qdata->name, qdata, pkt);
}

int nsec_append_rrsigs(knot_pkt_t *pkt, knotd_qdata_t *qdata, bool optional)
{
	int ret = KNOT_EOK;
	uint32_t flags = optional ? KNOT_PF_NOTRUNC : KNOT_PF_NULL;
	flags |= KNOT_PF_FREE; // Free all RRSIGs, they are synthesized

	/* Append RRSIGs for section. */
	struct rrsig_info *info = NULL;
	WALK_LIST(info, qdata->extra->rrsigs) {
		knot_rrset_t *rrsig = &info->synth_rrsig;
		uint16_t compr_hint = info->rrinfo->compress_ptr[KNOT_COMPR_HINT_OWNER];
		ret = knot_pkt_put(pkt, compr_hint, rrsig, flags);
		if (ret != KNOT_EOK) {
			break;
		}
		/* RRSIG is owned by packet now. */
		knot_rdataset_init(&info->synth_rrsig.rrs);
	};

	/* Clear the list. */
	nsec_clear_rrsigs(qdata);

	return ret;
}

void nsec_clear_rrsigs(knotd_qdata_t *qdata)
{
	if (qdata == NULL) {
		return;
	}

	struct rrsig_info *info = NULL;
	WALK_LIST(info, qdata->extra->rrsigs) {
		knot_rrset_t *rrsig = &info->synth_rrsig;
		knot_rrset_clear(rrsig, qdata->mm);
	};

	ptrlist_free(&qdata->extra->rrsigs, qdata->mm);
	init_list(&qdata->extra->rrsigs);
}
