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

#include <assert.h>
#include <urcu.h>

#include "knot/server/journal.h"

#include "knot/updates/xfr-in.h"

#include "libknot/packet/wire.h"
#include "common/debug.h"
#include "libknot/packet/pkt.h"
#include "libknot/processing/process.h"
#include "libknot/dname.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "libknot/dnssec/random.h"
#include "libknot/common.h"
#include "knot/updates/changesets.h"
#include "libknot/rdata/tsig.h"
#include "libknot/tsig-op.h"
#include "knot/zone/semantic-check.h"
#include "common/lists.h"
#include "common/descriptor.h"
#include "libknot/util/utils.h"
#include "libknot/rdata/soa.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/ixfr.h"

#define KNOT_NS_TSIG_FREQ 100

/*!
 * \brief Post update cleanup: frees data that are in the tree that will not
 *        be used (old tree if success, new tree if failure).
 *          Freed data:
 *           - actual data inside knot_rrs_t. (the rest is part of the node)
 */
static void rrs_list_clear(list_t *l, mm_ctx_t *mm)
{
	ptrnode_t *n;
	node_t *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		mm_free(mm, (void *)n->d);
		mm_free(mm, n);
	};
}

static int knot_ns_tsig_required(int packet_nr)
{
	/*! \bug This can overflow to negative numbers. Proper solution is to
	 *       count exactly at one place for each incoming/outgoing packet
	 *       with packet_nr = (packet_nr + 1) % FREQ and require TSIG on 0.
	 */
	dbg_ns_verb("ns_tsig_required(%d): %d\n", packet_nr,
	            (packet_nr % KNOT_NS_TSIG_FREQ == 0));
	return (packet_nr % KNOT_NS_TSIG_FREQ == 0);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int xfrin_transfer_needed(const zone_contents_t *zone,
                          knot_pkt_t *soa_response)
{
	/*
	 * Retrieve the local Serial
	 */
	const knot_rdataset_t *soa_rrs =
		node_rdataset(zone->apex, KNOT_RRTYPE_SOA);
	if (soa_rrs == NULL) {
		char *name = knot_dname_to_str(zone->apex->owner);
		dbg_xfrin("SOA RRSet missing in the zone %s!\n", name);
		free(name);
		return KNOT_ERROR;
	}

	uint32_t local_serial = knot_soa_serial(soa_rrs);
	/*
	 * Retrieve the remote Serial
	 */
	// the SOA should be the first (and only) RRSet in the response
	const knot_pktsection_t *answer = knot_pkt_section(soa_response, KNOT_ANSWER);
	if (answer->count < 1) {
		return KNOT_EMALF;
	}
	knot_rrset_t soa_rr = answer->rr[0];
	if (soa_rr.type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	uint32_t remote_serial = knot_soa_serial(&soa_rr.rrs);
	return (knot_serial_compare(local_serial, remote_serial) < 0);
}

/*----------------------------------------------------------------------------*/

static int xfrin_check_tsig(knot_pkt_t *packet, knot_ns_xfr_t *xfr,
                            int tsig_req)
{
	assert(packet != NULL);
	assert(xfr != NULL);

	dbg_xfrin_verb("xfrin_check_tsig(): packet nr: %d, required: %d\n",
		       xfr->packet_nr, tsig_req);

	/*
	 * If we are expecting it (i.e. xfr->prev_digest_size > 0)
	 *   a) it should be there (first, last or each 100th packet) and it
	 *      is not
	 *        Then we should discard the changes and close the connection.
	 *   b) it should be there and it is or it may not be there (other
	 *      packets) and it is
	 *        We validate the TSIG and reset packet number counting and
	 *        data aggregation.
	 *
	 * If we are not expecting it (i.e. xfr->prev_digest_size <= 0) and
	 * it is there => it should probably be considered an error
	 */

	int ret = KNOT_EOK;
	if (xfr->tsig_key) {
		// just append the wireformat to the TSIG data
		uint8_t *wire_buf = xfr->tsig_data + xfr->tsig_data_size;
		memcpy(wire_buf, packet->wire, packet->size);
		xfr->tsig_data_size += packet->size;
	}

	if (xfr->tsig_key) {
		if (tsig_req && packet->tsig_rr == NULL) {
			// TSIG missing!!
			return KNOT_ENOTSIG;
		} else if (packet->tsig_rr != NULL) {
			// TSIG there, either required or not, process
			if (xfr->packet_nr == 0) {
				ret = knot_tsig_client_check(packet->tsig_rr,
					xfr->tsig_data, xfr->tsig_data_size,
					xfr->digest, xfr->digest_size,
					xfr->tsig_key,
					xfr->tsig_prev_time_signed);
			} else {
				ret = knot_tsig_client_check_next(packet->tsig_rr,
					xfr->tsig_data, xfr->tsig_data_size,
					xfr->digest, xfr->digest_size,
					xfr->tsig_key,
					xfr->tsig_prev_time_signed);
			}

			if (ret != KNOT_EOK) {
				/* No need to check TSIG error
				 * here, propagate and check elsewhere.*/
				return ret;
			}

			// and reset the data storage
			//xfr->packet_nr = 1;
			xfr->tsig_data_size = 0;

			// Extract the digest from the TSIG RDATA and store it.
			if (xfr->digest_max_size < tsig_rdata_mac_length(packet->tsig_rr)) {
				return KNOT_ESPACE;
			}
			memcpy(xfr->digest, tsig_rdata_mac(packet->tsig_rr),
			       tsig_rdata_mac_length(packet->tsig_rr));
			xfr->digest_size = tsig_rdata_mac_length(packet->tsig_rr);

			// Extract the time signed from the TSIG and store it
			// We may rewrite the tsig_req_time_signed field
			xfr->tsig_prev_time_signed =
					tsig_rdata_time_signed(packet->tsig_rr);

		}
	} else if (packet->tsig_rr != NULL) {
		// TSIG where it should not be
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static void xfrin_take_rr(const knot_pktsection_t *answer, const knot_rrset_t **rr, uint16_t *cur)
{
	if (*cur < answer->count) {
		*rr = &answer->rr[*cur];
		*cur += 1;
	} else {
		*rr = NULL;
	}
}

/*----------------------------------------------------------------------------*/

int xfrin_process_axfr_packet(knot_pkt_t *pkt, struct xfr_proc *proc)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	uint16_t rr_id = 0;
	const knot_rrset_t *rr = NULL;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);

	xfrin_take_rr(answer, &rr, &rr_id);
	++proc->npkts;

	// Init zone creator
	zcreator_t zc = {.z = proc->zone,
	                 .master = false, .ret = KNOT_EOK };

	while (rr) {
		if (rr->type == KNOT_RRTYPE_SOA &&
		    node_rrtype_exists(zc.z->apex, KNOT_RRTYPE_SOA)) {
			// Last SOA, last message, check TSIG.
//			int ret = xfrin_check_tsig(pkt, xfr, 1);
#warning TODO: TSIG API
			if (ret != KNOT_EOK) {
				return ret;
			}
			return 1; // Signal that transfer finished.
		} else {
			int ret = zcreator_step(&zc, rr);
			if (ret != KNOT_EOK) {
				// 'rr' is either inserted, or free'd
				return ret;
			}
			xfrin_take_rr(answer, &rr, &rr_id);
		}
	}

	// Check possible TSIG at the end of DNS message.
//	return xfrin_check_tsig(pkt, xfr, knot_ns_tsig_required(xfr->packet_nr));
#warning TODO: TSIG API
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int solve_start(const knot_rrset_t *rr, knot_changesets_t *changesets, mm_ctx_t *mm)
{
	assert(changesets->first_soa == NULL);
	if (rr->type != KNOT_RRTYPE_SOA) {
		return NS_PROC_FAIL;
	}

	// Store the first SOA for later use.
	changesets->first_soa = knot_rrset_copy(rr, mm);
	if (changesets->first_soa == NULL) {
		return NS_PROC_FAIL;
	}

	return NS_PROC_MORE;
}

static int solve_soa_from(const knot_rrset_t *rr, knot_changesets_t *changesets,
                          int *state, mm_ctx_t *mm)
{
	if (rr->type != KNOT_RRTYPE_SOA) {
		return NS_PROC_FAIL;
	}

	if (knot_rrset_equal(rr, changesets->first_soa, KNOT_RRSET_COMPARE_WHOLE)) {
		// Last SOA encountered, transfer done.
		*state = IXFR_DONE;
		return NS_PROC_DONE;
	}

	// Create new changeset.
	knot_changeset_t *change = knot_changesets_create_changeset(changesets);
	if (change == NULL) {
		return NS_PROC_FAIL;
	}

	// Store SOA into changeset.
	change->soa_from = knot_rrset_copy(rr, mm);
	if (change->soa_from == NULL) {
		return NS_PROC_FAIL;
	}
	change->serial_from = knot_soa_serial(&rr->rrs);

	return NS_PROC_MORE;
}

static int solve_soa_to(const knot_rrset_t *rr, knot_changeset_t *change, mm_ctx_t *mm)
{
	if (rr->type != KNOT_RRTYPE_SOA) {
		return NS_PROC_FAIL;
	}

	change->soa_to= knot_rrset_copy(rr, mm);
	if (change->soa_to == NULL) {
		return NS_PROC_FAIL;
	}
	change->serial_to = knot_soa_serial(&rr->rrs);

	return NS_PROC_MORE;
}

static int add_part(const knot_rrset_t *rr, knot_changeset_t *change, int part, mm_ctx_t *mm)
{
	knot_rrset_t *copy = knot_rrset_copy(rr, mm);
	if (copy) {
		int ret = knot_changeset_add_rrset(change, copy, part);
		if (ret != KNOT_EOK) {
			return NS_PROC_FAIL;
		} else {
			return NS_PROC_MORE;
		}
	} else {
		return NS_PROC_FAIL;
	}
}

static int solve_del(const knot_rrset_t *rr, knot_changeset_t *change, mm_ctx_t *mm)
{
	return add_part(rr, change, KNOT_CHANGESET_REMOVE, mm);
}

static int solve_add(const knot_rrset_t *rr, knot_changeset_t *change, mm_ctx_t *mm)
{
	return add_part(rr, change, KNOT_CHANGESET_ADD, mm);
}

static int ixfrin_step(const knot_rrset_t *rr, knot_changesets_t *changesets,
                       int *state, bool *next, mm_ctx_t *mm)
{
	switch (*state) {
		case IXFR_START:
			*state = IXFR_SOA_FROM;
			*next = true;
			return solve_start(rr, changesets, mm);
		case IXFR_SOA_FROM:
			*state = IXFR_DEL;
			*next = true;
			return solve_soa_from(rr, changesets, state, mm);
		case IXFR_DEL:
			if (rr->type == KNOT_RRTYPE_SOA) {
				*state = IXFR_SOA_TO;
				*next = false;
				return NS_PROC_MORE;
			}
			*next = true;
			return solve_del(rr, knot_changesets_get_last(changesets), mm);
		case IXFR_SOA_TO:
			*state = IXFR_ADD;
			*next = true;
			return solve_soa_to(rr, knot_changesets_get_last(changesets), mm);
		case IXFR_ADD:
			if (rr->type == KNOT_RRTYPE_SOA) {
				*state = IXFR_SOA_FROM;
				*next = false;
				return NS_PROC_MORE;
			}
			*next = true;
			return solve_add(rr, knot_changesets_get_last(changesets), mm);
		default:
			assert(0);
	}
}

static bool journal_limit_exceeded(struct ixfrin_proc *proc)
{
	return proc->changesets->count > JOURNAL_NCOUNT;
}

static bool out_of_zone(const knot_rrset_t *rr, struct ixfrin_proc *proc)
{
	return !knot_dname_is_sub(rr->owner, proc->zone->name) &&
	       !knot_dname_is_equal(rr->owner, proc->zone->name);
}

int xfrin_process_ixfr_packet(knot_pkt_t *pkt, struct ixfrin_proc *proc)
{
	uint16_t rr_id = 0;
	const knot_rrset_t *rr = NULL;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	xfrin_take_rr(answer, &rr, &rr_id);
	knot_changesets_t *changesets = proc->changesets;
	int ret = NS_PROC_NOOP;
	while (rr) {
		if (journal_limit_exceeded(proc)) {
			assert(proc->state != IXFR_DONE);
			return NS_PROC_DONE;
		}

		if (out_of_zone(rr, proc)) {
			continue;
		}

		// Process RR.
		bool next = false;
		ret = ixfrin_step(rr, changesets, &proc->state, &next, proc->mm);
		if (ret == NS_PROC_FAIL || ret == NS_PROC_DONE) {
			// Quit on errors and if we're done.
			return ret;
		}

		if (next) {
			xfrin_take_rr(answer, &rr, &rr_id);
		}
	}

#warning TODO TSIG
	assert(ret == NS_PROC_MORE);
	return ret;
}

/*----------------------------------------------------------------------------*/
/* Applying changesets to zone                                                */
/*----------------------------------------------------------------------------*/

void xfrin_cleanup_successful_update(knot_changesets_t *chgs)
{
	if (chgs == NULL) {
		return;
	}

	knot_changeset_t *change = NULL;
	WALK_LIST(change, chgs->sets) {
		// Delete old RR data
		rrs_list_clear(&change->old_data, NULL);
		init_list(&change->old_data);
		// Keep new RR data
		ptrlist_free(&change->new_data, NULL);
		init_list(&change->new_data);
	};
}

/*----------------------------------------------------------------------------*/

static int free_additional(zone_node_t **node, void *data)
{
	UNUSED(data);
	if ((*node)->flags & NODE_FLAGS_NONAUTH) {
		// non-auth nodes have no additionals.
		return KNOT_EOK;
	}

	for (uint16_t i = 0; i < (*node)->rrset_count; ++i) {
		struct rr_data *data = &(*node)->rrs[i];
		if (data->additional) {
			free(data->additional);
			data->additional = NULL;
		}
	}

	return KNOT_EOK;
}

void xfrin_zone_contents_free(zone_contents_t **contents)
{
	// free the zone tree, but only the structure
	// (nodes are already destroyed)
	dbg_zone("Destroying zone tree.\n");
	// free additional arrays
	knot_zone_tree_apply((*contents)->nodes, free_additional, NULL);
	knot_zone_tree_deep_free(&(*contents)->nodes);
	dbg_zone("Destroying NSEC3 zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nsec3_nodes);

	knot_nsec3param_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

static void xfrin_cleanup_failed_update(zone_contents_t **new_contents)
{
	if (new_contents == NULL) {
		return;
	}

	if (*new_contents != NULL) {
		// destroy the shallow copy of zone
		xfrin_zone_contents_free(new_contents);
	}

}

/*----------------------------------------------------------------------------*/

void xfrin_rollback_update(knot_changesets_t *chgs,
                           zone_contents_t **new_contents)
{
	if (chgs != NULL) {
		knot_changeset_t *change = NULL;
		WALK_LIST(change, chgs->sets) {
			// Delete new RR data
			rrs_list_clear(&change->new_data, NULL);
			init_list(&change->new_data);
			// Keep old RR data
			ptrlist_free(&change->old_data, NULL);
			init_list(&change->old_data);
		};
	}
	xfrin_cleanup_failed_update(new_contents);
}

/*----------------------------------------------------------------------------*/

static int xfrin_replace_rrs_with_copy(zone_node_t *node,
                                       uint16_t type)
{
	// Find data to copy.
	struct rr_data *data = NULL;
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		if (node->rrs[i].type == type) {
			data = &node->rrs[i];
			break;
		}
	}
	assert(data);

	// Create new data.
	knot_rdataset_t *rrs = &data->rrs;
	void *copy = malloc(knot_rdataset_size(rrs));
	if (copy == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(copy, rrs->data, knot_rdataset_size(rrs));

	// Store new data into node RRS.
	rrs->data = copy;

	return KNOT_EOK;
}

static void clear_new_rrs(zone_node_t *node, uint16_t type)
{
	knot_rdataset_t *new_rrs = node_rdataset(node, type);
	if (new_rrs) {
		knot_rdataset_clear(new_rrs, NULL);
	}
}

static bool can_remove(const zone_node_t *node, const knot_rrset_t *rr)
{
	if (node == NULL) {
		// Node does not exist, cannot remove anything.
		return false;
	}
	const knot_rdataset_t *node_rrs = node_rdataset(node, rr->type);
	if (node_rrs == NULL) {
		// Node does not have this type at all.
		return false;
	}

	const bool compare_ttls = false;
	for (uint16_t i = 0; i < rr->rrs.rr_count; ++i) {
		knot_rdata_t *rr_cmp = knot_rdataset_at(&rr->rrs, i);
		if (knot_rdataset_member(node_rrs, rr_cmp, compare_ttls)) {
			// At least one RR matches.
			return true;
		}
	}

	// Node does have the type, but no RRs match.
	return false;
}

static int add_old_data(knot_changeset_t *chset, knot_rdata_t *old_data)
{
	if (ptrlist_add(&chset->old_data, old_data, NULL) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int add_new_data(knot_changeset_t *chset, knot_rdata_t *new_data)
{
	if (ptrlist_add(&chset->new_data, new_data, NULL) == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int remove_rr(zone_node_t *node, const knot_rrset_t *rr,
                     knot_changeset_t *chset)
{
	knot_rrset_t removed_rrset = node_rrset(node, rr->type);
	knot_rdata_t *old_data = removed_rrset.rrs.data;
	int ret = xfrin_replace_rrs_with_copy(node, rr->type);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Store old data for cleanup.
	ret = add_old_data(chset, old_data);
	if (ret != KNOT_EOK) {
		clear_new_rrs(node, rr->type);
		return ret;
	}

	knot_rdataset_t *changed_rrs = node_rdataset(node, rr->type);
	// Subtract changeset RRS from node RRS.
	ret = knot_rdataset_subtract(changed_rrs, &rr->rrs, NULL);
	if (ret != KNOT_EOK) {
		clear_new_rrs(node, rr->type);
		return ret;
	}

	if (changed_rrs->rr_count > 0) {
		// Subtraction left some data in RRSet, store it for rollback.
		ret = add_new_data(chset, changed_rrs->data);
		if (ret != KNOT_EOK) {
			knot_rdataset_clear(changed_rrs, NULL);
			return ret;
		}
	} else {
		// RRSet is empty now, remove it from node, all data freed.
		node_remove_rdataset(node, rr->type);
	}

	return KNOT_EOK;
}

static int xfrin_apply_remove(zone_contents_t *contents, knot_changeset_t *chset)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chset->remove) {
		const knot_rrset_t *rr = rr_node->rr;

		// Find node for this owner
		zone_node_t *node = zone_contents_find_node_for_rr(contents,
		                                                   rr);
		if (!can_remove(node, rr)) {
			// Nothing to remove from, skip.
			continue;
		}

		int ret = remove_rr(node, rr, chset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int add_rr(zone_node_t *node, const knot_rrset_t *rr,
                  knot_changeset_t *chset, bool master)
{
	knot_rrset_t changed_rrset = node_rrset(node, rr->type);
	if (!knot_rrset_empty(&changed_rrset)) {
		// Modifying existing RRSet.
		knot_rdata_t *old_data = changed_rrset.rrs.data;
		int ret = xfrin_replace_rrs_with_copy(node, rr->type);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Store old RRS for cleanup.
		ret = add_old_data(chset, old_data);
		if (ret != KNOT_EOK) {
			clear_new_rrs(node, rr->type);
			return ret;
		}
	}

	// Insert new RR to RRSet, data will be copied.
	int ret = node_add_rrset(node, rr);
	if (ret == KNOT_EOK || ret == KNOT_ETTL) {
		// RR added, store for possible rollback.
		knot_rdataset_t *rrs = node_rdataset(node, rr->type);
		int data_ret = add_new_data(chset, rrs->data);
		if (data_ret != KNOT_EOK) {
			knot_rdataset_clear(rrs, NULL);
			return data_ret;
		}

		if (ret == KNOT_ETTL) {
			// Handle possible TTL errors.
			log_ttl_error(node, rr);
			if (!master) {
				// TTL errors fatal only for master.
				return KNOT_EOK;
			}
		}
	}

	return ret;
}

static int xfrin_apply_add(zone_contents_t *contents,
                           knot_changeset_t *chset, bool master)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chset->add) {
		knot_rrset_t *rr = rr_node->rr;

		// Get or create node with this owner
		zone_node_t *node = zone_contents_get_node_for_rr(contents, rr);
		if (node == NULL) {
			return KNOT_ENOMEM;
		}

		int ret = add_rr(node, rr, chset, master);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_replace_soa(zone_contents_t *contents,
                                   knot_changeset_t *chset)
{
	assert(chset->soa_from);
	int ret = remove_rr(contents->apex, chset->soa_from, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(!node_rrtype_exists(contents->apex, KNOT_RRTYPE_SOA));

	return add_rr(contents->apex, chset->soa_to, chset, false);
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_changeset(zone_contents_t *contents,
                                 knot_changeset_t *chset, bool master)
{
	/*
	 * Applies one changeset to the zone. Checks if the changeset may be
	 * applied (i.e. the origin SOA (soa_from) has the same serial as
	 * SOA in the zone apex.
	 */

	dbg_xfrin("APPLYING CHANGESET: from serial %u to serial %u\n",
		  chset->serial_from, chset->serial_to);

	// check if serial matches
	const knot_rdataset_t *soa = node_rdataset(contents->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL || knot_soa_serial(soa) != chset->serial_from) {
		dbg_xfrin("SOA serials do not match!!\n");
		return KNOT_EINVAL;
	}

	int ret = xfrin_apply_remove(contents, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = xfrin_apply_add(contents, chset, master);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return xfrin_apply_replace_soa(contents, chset);
}

/*----------------------------------------------------------------------------*/

/*! \brief Wrapper for BIRD lists. Storing: Node. */
typedef struct knot_node_ln {
	node_t n; /*!< List node. */
	zone_node_t *node; /*!< Actual usable data. */
} knot_node_ln_t;

static int add_node_to_list(zone_node_t *node, list_t *l)
{
	assert(node && l);
	knot_node_ln_t *data = malloc(sizeof(knot_node_ln_t));
	if (data == NULL) {
		return KNOT_ENOMEM;
	}
	data->node = node;
	add_head(l, (node_t *)data);
	return KNOT_EOK;
}

static int xfrin_mark_empty(zone_node_t **node_p, void *data)
{
	assert(node_p && *node_p);
	zone_node_t *node = *node_p;
	list_t *l = (list_t *)data;
	assert(data);
	if (node->rrset_count == 0 && node->children == 0 &&
	    !(node->flags & NODE_FLAGS_EMPTY)) {
		/*!
		 * Mark this node and all parent nodes that have 0 RRSets and
		 * no children for removal.
		 */
		int ret = add_node_to_list(node, l);
		if (ret != KNOT_EOK) {
			return ret;
		}
		node->flags |= NODE_FLAGS_EMPTY;
		if (node->parent) {
			if ((node->parent->flags & NODE_FLAGS_WILDCARD_CHILD)
			    && knot_dname_is_wildcard(node->owner)) {
				node->parent->flags &= ~NODE_FLAGS_WILDCARD_CHILD;
			}
			node->parent->children--;
			// Recurse using the parent node
			return xfrin_mark_empty(&node->parent, data);
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_remove_empty_nodes(zone_contents_t *z)
{
	dbg_xfrin("Removing empty nodes from zone.\n");

	list_t l;
	init_list(&l);
	// walk through the zone and select nodes to be removed
	int ret = knot_zone_tree_apply(z->nodes,
	                               xfrin_mark_empty, &l);
	if (ret != KNOT_EOK) {
		return ret;
	}

	node_t *n = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, l) {
		knot_node_ln_t *list_node = (knot_node_ln_t *)n;
		ret = zone_contents_remove_node(z, list_node->node->owner);
		if (ret != KNOT_EOK) {
			return ret;
		}
		node_free(&list_node->node);
		free(n);
	}

	init_list(&l);
	// Do the same with NSEC3 nodes.
	ret = knot_zone_tree_apply(z->nsec3_nodes,
	                           xfrin_mark_empty, &l);
	if (ret != KNOT_EOK) {
		return ret;
	}

	WALK_LIST_DELSAFE(n, nxt, l) {
		knot_node_ln_t *list_node = (knot_node_ln_t *)n;
		ret = zone_contents_remove_nsec3_node(z, list_node->node->owner);
		if (ret != KNOT_EOK) {
			return ret;
		}
		node_free(&list_node->node);
		free(n);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_prepare_zone_copy(zone_contents_t *old_contents, zone_contents_t **new_contents)
{
	if (old_contents == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	dbg_xfrin("Preparing zone copy...\n");

	/*
	 * Ensure that the zone generation is set to 0.
	 */
	if (!zone_contents_gen_is_old(old_contents)) {
		// this would mean that a previous update was not completed
		// abort
		dbg_zone("Trying to apply changesets to zone that is "
				  "being updated. Aborting.\n");
		return KNOT_EAGAIN;
	}

	/*
	 * Create a shallow copy of the zone, so that the structures may be
	 * updated.
	 *
	 * This will create new zone contents structures (normal nodes' tree,
	 * NSEC3 tree), and copy all nodes.
	 * The data in the nodes (RRSets) remain the same though.
	 */
	zone_contents_t *contents_copy = NULL;

	dbg_xfrin("Copying zone contents.\n");
	int ret = zone_contents_shallow_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to create shallow copy of zone: %s\n",
			  knot_strerror(ret));
		return ret;
	}

	assert(contents_copy->apex != NULL);

	*new_contents = contents_copy;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_finalize_updated_zone(zone_contents_t *contents_copy,
                                bool set_nsec3_names)
{
	if (contents_copy == NULL) {
		return KNOT_EINVAL;
	}

	/*
	 * Finalize the new zone contents:
	 * - delete empty nodes
	 * - parse NSEC3PARAM
	 * - do adjusting of nodes and RDATA
	 * - ???
	 * - PROFIT
	 */

	/*
	 * Select and remove empty nodes from zone trees. Do not free them right
	 * away as they may be referenced by some domain names.
	 */
	int ret = xfrin_remove_empty_nodes(contents_copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to remove empty nodes: %s\n",
			  knot_strerror(ret));
		return ret;
	}

	dbg_xfrin("Adjusting zone contents.\n");
	if (set_nsec3_names) {
		ret = zone_contents_adjust_full(contents_copy, NULL, NULL);
	} else {
		ret = zone_contents_adjust_pointers(contents_copy);
	}
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to finalize zone contents: %s\n",
			  knot_strerror(ret));
		return ret;
	}

	assert(contents_copy->apex != NULL);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_apply_changesets_directly(zone_contents_t *contents,
                                    knot_changesets_t *chsets)
{
	if (contents == NULL || chsets == NULL) {
		return KNOT_EINVAL;
	}

	knot_changeset_t *set = NULL;
	WALK_LIST(set, chsets->sets) {
		const bool master = true; // Only DNSSEC changesets are applied directly.
		int ret = xfrin_apply_changeset(contents, set, master);
		if (ret != KNOT_EOK) {
			xfrin_cleanup_successful_update(chsets);
			return ret;
		}
	}

	int ret = xfrin_finalize_updated_zone(contents, true);

	/*
	 * HACK: Cleanup for successful update is used for both success and fail
	 * when modifying the zone directly, will fix in new zone API.
	 */
	xfrin_cleanup_successful_update(chsets);
	return ret;
}

/*----------------------------------------------------------------------------*/

int xfrin_apply_changesets(zone_t *zone,
                           knot_changesets_t *chsets,
                           zone_contents_t **new_contents)
{
	if (zone == NULL || chsets == NULL || EMPTY_LIST(chsets->sets)
	    || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	zone_contents_t *old_contents = zone->contents;
	if (!old_contents) {
		dbg_xfrin("Cannot apply changesets to empty zone.\n");
		return KNOT_EINVAL;
	}

	dbg_xfrin("Applying changesets to zone...\n");

	dbg_xfrin_verb("Creating shallow copy of the zone...\n");
	zone_contents_t *contents_copy = NULL;
	int ret = xfrin_prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to prepare zone copy: %s\n",
			  knot_strerror(ret));
		return ret;
	}

	/*
	 * Apply the changesets.
	 */
	dbg_xfrin("Applying changesets.\n");
	dbg_xfrin_verb("Old contents apex: %p, new apex: %p\n",
		       old_contents->apex, contents_copy->apex);
	knot_changeset_t *set = NULL;
	const bool master = (zone_master(zone) == NULL);
	WALK_LIST(set, chsets->sets) {
		ret = xfrin_apply_changeset(contents_copy, set, master);
		if (ret != KNOT_EOK) {
			xfrin_rollback_update(chsets, &contents_copy);
			dbg_xfrin("Failed to apply changesets to zone: "
				  "%s\n", knot_strerror(ret));
			return ret;
		}
	}

	assert(contents_copy->apex != NULL);

	/*!
	 * \todo Test failure of IXFR.
	 */

	dbg_xfrin_verb("Finalizing updated zone...\n");
	ret = xfrin_finalize_updated_zone(contents_copy, true);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to finalize updated zone: %s\n",
			  knot_strerror(ret));
		xfrin_rollback_update(chsets, &contents_copy);
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

zone_contents_t *xfrin_switch_zone(zone_t *zone, zone_contents_t *new_contents)
{
	if (zone == NULL || new_contents == NULL) {
		return NULL;
	}

	dbg_xfrin("Switching zone contents.\n");
	dbg_xfrin_verb("Old contents: %p, apex: %p, new apex: %p\n",
		       zone->contents, (zone->contents)
		       ? zone->contents->apex : NULL, new_contents->apex);

	zone_contents_t *old =
		zone_switch_contents(zone, new_contents);

	dbg_xfrin_verb("Old contents: %p, apex: %p, new apex: %p\n",
		       old, (old) ? old->apex : NULL, new_contents->apex);

	// set generation to old, so that the flags may be used in next transfer
	// and we do not search for new nodes anymore
	zone_contents_set_gen_old(new_contents);

	// wait for readers to finish
	dbg_xfrin_verb("Waiting for readers to finish...\n");
	synchronize_rcu();

	return old;
}
