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
#include "libknot/dname.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone-create.h"
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

int xfrin_transfer_needed(const knot_zone_contents_t *zone,
                          knot_pkt_t *soa_response)
{
	/*
	 * Retrieve the local Serial
	 */
	const knot_rdataset_t *soa_rrs =
		knot_node_rdataset(zone->apex, KNOT_RRTYPE_SOA);
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

int xfrin_create_soa_query(const zone_t *zone, knot_pkt_t *pkt)
{
	return knot_pkt_put_question(pkt, zone->name, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
}

/*----------------------------------------------------------------------------*/

int xfrin_create_axfr_query(const zone_t *zone, knot_pkt_t *pkt)
{
	return knot_pkt_put_question(pkt, zone->name, KNOT_CLASS_IN, KNOT_RRTYPE_AXFR);
}

/*----------------------------------------------------------------------------*/

int xfrin_create_ixfr_query(const zone_t *zone, knot_pkt_t *pkt)
{
	if (zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	int ret = knot_pkt_put_question(pkt, zone->name, KNOT_CLASS_IN, KNOT_RRTYPE_IXFR);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Add SOA RR to authority section for IXFR. */
	knot_node_t *apex = zone->contents->apex;
	knot_rrset_t soa = knot_node_rrset(apex, KNOT_RRTYPE_SOA);
	knot_pkt_begin(pkt, KNOT_AUTHORITY);
	ret = knot_pkt_put(pkt, COMPR_HINT_QNAME, &soa, 0);
	return ret;
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

int xfrin_process_axfr_packet(knot_pkt_t *pkt, knot_ns_xfr_t *xfr, knot_zone_contents_t **zone)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	uint16_t rr_id = 0;
	const knot_rrset_t *rr = NULL;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);

	xfrin_take_rr(answer, &rr, &rr_id);
	if (*zone == NULL) {
		if (rr == NULL) {
			// Empty transfer.
			return KNOT_EMALF;
		}
		// Transfer start, init zone
		if (rr->type != KNOT_RRTYPE_SOA) {
			return KNOT_EMALF;
		}
		*zone = knot_zone_contents_new(rr->owner);
		if (*zone == NULL) {
			return KNOT_ENOMEM;
		}
		xfr->packet_nr = 0;
	} else {
		++xfr->packet_nr;
	}

	// Init zone creator
	zcreator_t zc = {.z = *zone,
	                 .master = false, .ret = KNOT_EOK };

	while (rr) {
		if (rr->type == KNOT_RRTYPE_SOA &&
		    knot_node_rrtype_exists(zc.z->apex, KNOT_RRTYPE_SOA)) {
			// Last SOA, last message, check TSIG.
			int ret = xfrin_check_tsig(pkt, xfr, 1);
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
	return xfrin_check_tsig(pkt, xfr, knot_ns_tsig_required(xfr->packet_nr));
}

/*----------------------------------------------------------------------------*/

int xfrin_process_ixfr_packet(knot_pkt_t *pkt, knot_ns_xfr_t *xfr)
{
	knot_changesets_t **chs = (knot_changesets_t **)(&xfr->data);
	if (pkt == NULL || chs == NULL) {
		dbg_xfrin("Wrong parameters supported.\n");
		return KNOT_EINVAL;
	}

	uint16_t rr_id = 0;
	const knot_rrset_t *rr = NULL;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	xfrin_take_rr(answer, &rr, &rr_id);
	if (rr == NULL) {
		return KNOT_EXFRREFUSED; /* Empty, try again with AXFR */
	}

	// state of the transfer
	// -1 .. a SOA is expected to create a new changeset
	int state = 0;
	int ret = KNOT_EOK;
	if (*chs == NULL) {
		dbg_xfrin_verb("Changesets empty, creating new.\n");
		ret = knot_changesets_init(chs);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// the first RR must be a SOA
		if (rr->type != KNOT_RRTYPE_SOA) {
			dbg_xfrin("First RR is not a SOA RR!\n");
			ret = KNOT_EMALF;
			goto cleanup;
		}

		// just store the first SOA for later use
		(*chs)->first_soa = knot_rrset_copy(rr, NULL);
		if ((*chs)->first_soa == NULL) {
			ret = KNOT_ENOMEM;
			goto cleanup;
		}
		state = -1;

		dbg_xfrin_verb("First SOA of IXFR saved, state set to -1.\n");

		// take next RR
		xfrin_take_rr(answer, &rr, &rr_id);

		/*
		 * If there is no other records in the response than the SOA, it
		 * means one of these three cases:
		 *
		 * 1) The server does not have newer zone than ours.
		 *    This is indicated by serial equal to the one of our zone.
		 * 2) The server wants to send the transfer but is unable to fit
		 *    it in the packet. This is indicated by serial different
		 *    (newer) from the one of our zone, but applies only for
		 *    IXFR/UDP.
		 * 3) The master is weird and sends only SOA in the first packet
		 *    of a fallback to AXFR answer (PowerDNS does this).
		 *
		 * The serials must be compared in other parts of the server, so
		 * just indicate that the answer contains only one SOA.
		 */
		if (rr == NULL) {
			dbg_xfrin("Response containing only SOA,\n");
			return XFRIN_RES_SOA_ONLY;
		} else if (rr->type != KNOT_RRTYPE_SOA) {
			dbg_xfrin("Fallback to AXFR.\n");
			return XFRIN_RES_FALLBACK;
		}
	} else {
		if ((*chs)->first_soa == NULL) {
			dbg_xfrin("Changesets don't contain SOA first!\n");
			ret = KNOT_EINVAL;
			goto cleanup;
		}
		dbg_xfrin_detail("Changesets present.\n");
	}

	/*
	 * Process the next RR. Different requirements are in place in
	 * different cases:
	 *
	 * 1) Last changeset has both soa_from and soa_to.
	 *    a) The next RR is a SOA.
	 *      i) The next RR is equal to the first_soa saved in changesets.
	 *         This denotes the end of the transfer. It may be dropped and
	 *         the end should be signalised by returning positive value.
	 *
	 *      ii) The next RR is some other SOA.
	 *          This means a start of new changeset - create it and add it
	 *          to the list.
	 *
	 *    b) The next RR is not a SOA.
	 *       Put the RR into the ADD part of the last changeset as this is
	 *       not finished yet. Continue while SOA is not encountered. Then
	 *       jump to 1-a.
	 *
	 * 2) Last changeset has only the soa_from and does not have soa_to.
	 *    a) The next RR is a SOA.
	 *       This means start of the ADD section. Put the SOA to the
	 *       changeset. Continue adding RRs to the ADD section while SOA
	 *       is not encountered. This is identical to 1-b.
	 *
	 *    b) The next RR is not a SOA.
	 *       This means the REMOVE part is not finished yet. Add the RR to
	 *       the REMOVE part. Continue adding next RRs until a SOA is
	 *       encountered. Then jump to 2-a.
	 */

	// first, find out in what state we are
	/*! \todo It would be more elegant to store the state in the
	 *        changesets structure, or in some place persistent between
	 *        calls to this function.
	 */
	knot_changeset_t *chset = knot_changesets_get_last(*chs);
	if (state != -1) {
		dbg_xfrin_detail("State is not -1, deciding...\n");
		// there should be at least one started changeset right now
		if (EMPTY_LIST((*chs)->sets)) {
			ret = KNOT_EMALF;
			goto cleanup;
		}

		// a changeset should be created only when there is a SOA
		assert(chset->soa_from != NULL);

		if (chset->soa_to == NULL) {
			state = KNOT_CHANGESET_REMOVE;
		} else {
			state = KNOT_CHANGESET_ADD;
		}
	}

	dbg_xfrin_detail("State before the loop: %d\n", state);

	/*! \todo This may be implemented with much less IFs! */

	while (rr != NULL) {
		if (!knot_dname_is_sub(rr->owner, xfr->zone->name) &&
		    !knot_dname_is_equal(rr->owner, xfr->zone->name)) {
			// out-of-zone domain
			// take next RR
			xfrin_take_rr(answer, &rr, &rr_id);
			continue;
		}

		switch (state) {
		case -1:
			// a SOA is expected
			// this may be either a start of a changeset or the
			// last SOA (in case the transfer was empty, but that
			// is quite weird in fact
			if (rr->type != KNOT_RRTYPE_SOA) {
				dbg_xfrin("First RR is not a SOA RR!\n");
				dbg_xfrin_verb("RR type: %u\n",
					       rr->type);
				ret = KNOT_EMALF;
				goto cleanup;
			}

			if (knot_soa_serial(&rr->rrs)
			    == knot_soa_serial(&(*chs)->first_soa->rrs)) {

				/*! \note [TSIG] Check TSIG, we're at the end of
				 *               transfer.
				 */
				ret = xfrin_check_tsig(pkt, xfr, 1);

				// last SOA, discard and end
				/*! \note [TSIG] If TSIG validates, consider
				 *        transfer complete. */
				if (ret == KNOT_EOK) {
					ret = XFRIN_RES_COMPLETE;
				}

				return ret;
			} else {
				// normal SOA, start new changeset
				/* Check changesets for maximum count (so they fit into journal). */
				if ((*chs)->count + 1 > JOURNAL_NCOUNT)
					ret = KNOT_ESPACE;

				if (ret != KNOT_EOK) {
					goto cleanup;
				}

				chset = knot_changesets_create_changeset(*chs);
				if (chset == NULL) {
					goto cleanup;
				}
				knot_rrset_t *soa = knot_rrset_copy(rr, NULL);
				if (soa == NULL) {
					ret = KNOT_ENOMEM;
					goto cleanup;
				}

				knot_changeset_add_soa(chset, soa, KNOT_CHANGESET_REMOVE);

				// change state to REMOVE
				state = KNOT_CHANGESET_REMOVE;
			}
			break;
		case KNOT_CHANGESET_REMOVE:
			// if the next RR is SOA, store it and change state to
			// ADD
			if (rr->type == KNOT_RRTYPE_SOA) {
				// we should not be here if soa_from is not set
				assert(chset->soa_from != NULL);
				knot_rrset_t *soa = knot_rrset_copy(rr, NULL);
				if (soa == NULL) {
					ret = KNOT_ENOMEM;
					goto cleanup;
				}
				knot_changeset_add_soa(chset, soa, KNOT_CHANGESET_ADD);

				state = KNOT_CHANGESET_ADD;
			} else {
				// just add the RR to the REMOVE part and
				// continue
				knot_rrset_t *cpy = knot_rrset_copy(rr, NULL);
				if (cpy == NULL) {
					ret = KNOT_ENOMEM;
					goto cleanup;
				}
				ret = knot_changeset_add_rrset(chset, cpy,
				                               KNOT_CHANGESET_REMOVE);
				if (ret != KNOT_EOK) {
					goto cleanup;
				}
			}
			break;
		case KNOT_CHANGESET_ADD:
			// if the next RR is SOA change to state -1 and do not
			// parse next RR
			if (rr->type == KNOT_RRTYPE_SOA) {
				log_zone_info("%s Serial %u -> %u.\n",
					      xfr->msg,
					      knot_soa_serial(&chset->soa_from->rrs),
					      knot_soa_serial(&chset->soa_to->rrs));
				state = -1;
				continue;
			} else {
				// just add the RR to the ADD part and continue
				knot_rrset_t *cpy = knot_rrset_copy(rr, NULL);
				if (cpy == NULL) {
					ret = KNOT_ENOMEM;
					goto cleanup;
				}
				ret = knot_changeset_add_rrset(chset, cpy,
				                               KNOT_CHANGESET_ADD);
				if (ret != KNOT_EOK) {
					goto cleanup;
				}
			}
			break;
		}

		// take next RR
		xfrin_take_rr(answer, &rr, &rr_id);
	}

	/*! \note Check TSIG, we're at the end of packet. It may not be
	 *        required.
	 */
	ret = xfrin_check_tsig(pkt, xfr,
			       knot_ns_tsig_required(xfr->packet_nr));
	dbg_xfrin_verb("xfrin_check_tsig() returned %d\n", ret);
	++xfr->packet_nr;

	/*! \note [TSIG] Cleanup and propagate error if TSIG validation fails.*/
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	// here no RRs remain in the packet but the transfer is not finished
	// yet, return EOK
	return KNOT_EOK;

cleanup:
	/* We should go here only if some error occured. */
	assert(ret < 0);

	dbg_xfrin_detail("Cleanup after processing IXFR/IN packet.\n");
	knot_changesets_free(chs);
	xfr->data = 0;
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

static int free_additional(knot_node_t **node, void *data)
{
	UNUSED(data);
	if ((*node)->flags & KNOT_NODE_FLAGS_NONAUTH) {
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

static void xfrin_zone_contents_free(knot_zone_contents_t **contents)
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

static void xfrin_cleanup_failed_update(knot_zone_contents_t **new_contents)
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
                           knot_zone_contents_t **new_contents)
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

static int xfrin_replace_rrs_with_copy(knot_node_t *node,
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

static void clear_new_rrs(knot_node_t *node, uint16_t type)
{
	knot_rdataset_t *new_rrs = knot_node_rdataset(node, type);
	if (new_rrs) {
		knot_rdataset_clear(new_rrs, NULL);
	}
}

static bool can_remove(const knot_node_t *node, const knot_rrset_t *rr)
{
	if (node == NULL) {
		// Node does not exist, cannot remove anything.
		return false;
	}
	const knot_rdataset_t *node_rrs = knot_node_rdataset(node, rr->type);
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

static int remove_rr(knot_node_t *node, const knot_rrset_t *rr,
                     knot_changeset_t *chset)
{
	knot_rrset_t removed_rrset = knot_node_rrset(node, rr->type);
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

	knot_rdataset_t *changed_rrs = knot_node_rdataset(node, rr->type);
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
		knot_node_remove_rrset(node, rr->type);
	}

	return KNOT_EOK;
}

static int xfrin_apply_remove(knot_zone_contents_t *contents,
                              knot_changeset_t *chset)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chset->remove) {
		const knot_rrset_t *rr = rr_node->rr;

		// Find node for this owner
		knot_node_t *node = zone_contents_find_node_for_rr(contents,
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

static int add_rr(knot_node_t *node, const knot_rrset_t *rr,
                  knot_changeset_t *chset)
{
	knot_rrset_t changed_rrset = knot_node_rrset(node, rr->type);
	if (!knot_rrset_empty(&changed_rrset)) {
		// Modifying existing RRSet.
		knot_rdata_t *old_data = changed_rrset.rrs.data;
		int ret = xfrin_replace_rrs_with_copy(node, rr->type);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Store old RRS and additional for cleanup.
		ret = add_old_data(chset, old_data);
		if (ret != KNOT_EOK) {
			clear_new_rrs(node, rr->type);
			return ret;
		}

		// Extract copy, merge into it
		knot_rdataset_t *changed_rrs = knot_node_rdataset(node, rr->type);
		ret = knot_rdataset_merge(changed_rrs, &rr->rrs, NULL);
		if (ret != KNOT_EOK) {
			clear_new_rrs(node, rr->type);
			return ret;
		}
	} else {
		// Inserting new RRSet, data will be copied.
		bool ttl_err = false;
		int ret = knot_node_add_rrset(node, rr, &ttl_err);
		if (ret != KNOT_EOK) {
			return ret;
		}

		if (ttl_err) {
			char type_str[16] = { '\0' };
			knot_rrtype_to_string(rr->type, type_str, sizeof(type_str));
			char *name = knot_dname_to_str(rr->owner);
			char *zname = knot_dname_to_str(chset->soa_from->owner);
			log_zone_warning("Changes application to zone %s: TTL mismatch"
			                 " in %s, type %s\n", zname, name, type_str);
			free(name);
			free(zname);
		}
	}

	// Get changed RRS and store for possible rollback.
	knot_rdataset_t *rrs = knot_node_rdataset(node, rr->type);
	int ret = add_new_data(chset, rrs->data);
	if (ret != KNOT_EOK) {
		knot_rdataset_clear(rrs, NULL);
		return ret;
	}

	return KNOT_EOK;
}

static int xfrin_apply_add(knot_zone_contents_t *contents,
                           knot_changeset_t *chset)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chset->add) {
		knot_rrset_t *rr = rr_node->rr;

		// Get or create node with this owner
		knot_node_t *node = zone_contents_get_node_for_rr(contents, rr);
		if (node == NULL) {
			return KNOT_ENOMEM;
		}

		int ret = add_rr(node, rr, chset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_replace_soa(knot_zone_contents_t *contents,
                                   knot_changeset_t *chset)
{
	assert(chset->soa_from);
	int ret = remove_rr(contents->apex, chset->soa_from, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	assert(!knot_node_rrtype_exists(contents->apex, KNOT_RRTYPE_SOA));

	return add_rr(contents->apex, chset->soa_to, chset);
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_changeset(list_t *old_rrs, list_t *new_rrs,
                                 knot_zone_contents_t *contents,
                                 knot_changeset_t *chset)
{
	/*
	 * Applies one changeset to the zone. Checks if the changeset may be
	 * applied (i.e. the origin SOA (soa_from) has the same serial as
	 * SOA in the zone apex.
	 */

	dbg_xfrin("APPLYING CHANGESET: from serial %u to serial %u\n",
		  chset->serial_from, chset->serial_to);

	// check if serial matches
	const knot_rdataset_t *soa = knot_node_rdataset(contents->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL || knot_soa_serial(soa)
			   != chset->serial_from) {
		dbg_xfrin("SOA serials do not match!!\n");
		return KNOT_EINVAL;
	}

	int ret = xfrin_apply_remove(contents, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = xfrin_apply_add(contents, chset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return xfrin_apply_replace_soa(contents, chset);
}

/*----------------------------------------------------------------------------*/

/*! \brief Wrapper for BIRD lists. Storing: Node. */
typedef struct knot_node_ln {
	node_t n; /*!< List node. */
	knot_node_t *node; /*!< Actual usable data. */
} knot_node_ln_t;

static int add_node_to_list(knot_node_t *node, list_t *l)
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

static int xfrin_mark_empty(knot_node_t **node_p, void *data)
{
	assert(node_p && *node_p);
	knot_node_t *node = *node_p;
	list_t *l = (list_t *)data;
	assert(data);
	if (node->rrset_count == 0 && node->children == 0 &&
	    !(node->flags & KNOT_NODE_FLAGS_EMPTY)) {
		/*!
		 * Mark this node and all parent nodes that have 0 RRSets and
		 * no children for removal.
		 */
		int ret = add_node_to_list(node, l);
		if (ret != KNOT_EOK) {
			return ret;
		}
		node->flags |= KNOT_NODE_FLAGS_EMPTY;
		if (node->parent) {
			if ((node->parent->flags & KNOT_NODE_FLAGS_WILDCARD_CHILD)
			    && knot_dname_is_wildcard(node->owner)) {
				node->parent->flags &= ~KNOT_NODE_FLAGS_WILDCARD_CHILD;
			}
			node->parent->children--;
			// Recurse using the parent node
			return xfrin_mark_empty(&node->parent, data);
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_remove_empty_nodes(knot_zone_contents_t *z)
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
		ret = knot_zone_contents_remove_node(z, list_node->node->owner);
		if (ret != KNOT_EOK) {
			return ret;
		}
		knot_node_free(&list_node->node);
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
		ret = knot_zone_contents_remove_nsec3_node(z, list_node->node->owner);
		if (ret != KNOT_EOK) {
			return ret;
		}
		knot_node_free(&list_node->node);
		free(n);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_prepare_zone_copy(knot_zone_contents_t *old_contents,
                            knot_zone_contents_t **new_contents)
{
	if (old_contents == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	dbg_xfrin("Preparing zone copy...\n");

	/*
	 * Ensure that the zone generation is set to 0.
	 */
	if (!knot_zone_contents_gen_is_old(old_contents)) {
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
	knot_zone_contents_t *contents_copy = NULL;

	dbg_xfrin("Copying zone contents.\n");
	int ret = knot_zone_contents_shallow_copy(old_contents, &contents_copy);
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

int xfrin_finalize_updated_zone(knot_zone_contents_t *contents_copy,
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
		ret = knot_zone_contents_adjust_full(contents_copy,
		                                     NULL, NULL);
	} else {
		ret = knot_zone_contents_adjust_pointers(contents_copy);
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

int xfrin_apply_changesets_directly(knot_zone_contents_t *contents,
                                    knot_changesets_t *chsets)
{
	if (contents == NULL || chsets == NULL) {
		return KNOT_EINVAL;
	}

	knot_changeset_t *set = NULL;
	WALK_LIST(set, chsets->sets) {
		int ret = xfrin_apply_changeset(&set->old_data,
		                                &set->new_data,
		                                contents, set);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

/* Post-DDNS application, no need to shallow copy. */
int xfrin_apply_changesets_dnssec_ddns(zone_t *zone,
                                       knot_zone_contents_t *z_new,
                                       knot_changesets_t *sec_chsets,
                                       knot_changesets_t *chsets)
{
	if (zone == NULL || z_new == NULL ||
	    sec_chsets == NULL || chsets == NULL) {
		return KNOT_EINVAL;
	}

	/* Set generation to old. Zone should be long locked at this point. */
	knot_zone_contents_set_gen_old(z_new);

	/* Apply changes. */
	int ret = xfrin_apply_changesets_directly(z_new, sec_chsets);
	if (ret != KNOT_EOK) {
		xfrin_rollback_update(sec_chsets, &z_new);
		dbg_xfrin("Failed to apply changesets to zone: "
		          "%s\n", knot_strerror(ret));
		return ret;
	}

	const bool handle_nsec3 = true;
	ret = xfrin_finalize_updated_zone(z_new, handle_nsec3);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to finalize updated zone: %s\n",
		          knot_strerror(ret));
		xfrin_rollback_update(sec_chsets, &z_new);
		return ret;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

int xfrin_apply_changesets(zone_t *zone,
                           knot_changesets_t *chsets,
                           knot_zone_contents_t **new_contents)
{
	if (zone == NULL || chsets == NULL || EMPTY_LIST(chsets->sets)
	    || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_contents_t *old_contents = zone->contents;
	if (!old_contents) {
		dbg_xfrin("Cannot apply changesets to empty zone.\n");
		return KNOT_EINVAL;
	}

	dbg_xfrin("Applying changesets to zone...\n");

	dbg_xfrin_verb("Creating shallow copy of the zone...\n");
	knot_zone_contents_t *contents_copy = NULL;
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
	WALK_LIST(set, chsets->sets) {
		ret = xfrin_apply_changeset(&set->old_data,
		                            &set->new_data,
		                            contents_copy, set);
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

int xfrin_switch_zone(zone_t *zone,
                      knot_zone_contents_t *new_contents,
                      int transfer_type)
{
	if (zone == NULL || new_contents == NULL) {
		return KNOT_EINVAL;
	}

	dbg_xfrin("Switching zone contents.\n");
	dbg_xfrin_verb("Old contents: %p, apex: %p, new apex: %p\n",
		       zone->contents, (zone->contents)
		       ? zone->contents->apex : NULL, new_contents->apex);

	knot_zone_contents_t *old =
		zone_switch_contents(zone, new_contents);

	dbg_xfrin_verb("Old contents: %p, apex: %p, new apex: %p\n",
		       old, (old) ? old->apex : NULL, new_contents->apex);

	// set generation to old, so that the flags may be used in next transfer
	// and we do not search for new nodes anymore
	knot_zone_contents_set_gen_old(new_contents);

	// wait for readers to finish
	dbg_xfrin_verb("Waiting for readers to finish...\n");
	synchronize_rcu();

	// destroy the old zone
	dbg_xfrin_verb("Freeing old zone: %p\n", old);

	if (transfer_type == XFR_TYPE_AIN) {
		knot_zone_contents_deep_free(&old);
	} else {
		assert(old != NULL);
		xfrin_zone_contents_free(&old);
	}

	return KNOT_EOK;
}
