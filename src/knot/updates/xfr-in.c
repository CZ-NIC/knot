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
#include "libknot/tsig.h"
#include "libknot/tsig-op.h"
#include "knot/zone/semantic-check.h"
#include "common/lists.h"
#include "common/descriptor.h"
#include "libknot/rdata.h"
#include "libknot/util/utils.h"

#define KNOT_NS_TSIG_FREQ 100

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
	const knot_rrset_t *soa_rrset =
		knot_node_rrset(knot_zone_contents_apex(zone),
				KNOT_RRTYPE_SOA);
	if (soa_rrset == NULL) {
		char *name = knot_dname_to_str(knot_node_owner(
				knot_zone_contents_apex(zone)));
		dbg_xfrin("SOA RRSet missing in the zone %s!\n", name);
		free(name);
		return KNOT_ERROR;
	}

	int64_t local_serial = knot_rdata_soa_serial(soa_rrset);
	if (local_serial < 0) {
dbg_xfrin_exec(
		char *name = knot_dname_to_str(knot_rrset_owner(soa_rrset));
		dbg_xfrin("Malformed data in SOA of zone %s\n", name);
		free(name);
);
		return KNOT_EMALF;  // maybe some other error
	}

	/*
	 * Retrieve the remote Serial
	 */
	// the SOA should be the first (and only) RRSet in the response

	const knot_pktsection_t *answer = knot_pkt_section(soa_response, KNOT_ANSWER);
	if (answer->count < 1 || knot_rrset_type(answer->rr[0]) != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	int64_t remote_serial = knot_rdata_soa_serial(answer->rr[0]);
	if (remote_serial < 0) {
		return KNOT_EMALF;	// maybe some other error
	}

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
	const knot_rrset_t *soa = knot_node_rrset(apex, KNOT_RRTYPE_SOA);
	knot_pkt_begin(pkt, KNOT_AUTHORITY);
	return knot_pkt_put(pkt, COMPR_HINT_QNAME, soa, 0);
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

static int xfrin_take_rr(const knot_pktsection_t *answer, knot_rrset_t **rr, uint16_t *cur)
{
	int ret = KNOT_EOK;
	if (*cur < answer->count) {
		ret = knot_rrset_copy(answer->rr[*cur], rr, NULL);
		*cur += 1;
	} else {
		*rr = NULL;
		ret = KNOT_EOK;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

int xfrin_process_axfr_packet(knot_pkt_t *pkt, knot_ns_xfr_t *xfr, knot_zone_contents_t **zone)
{
	if (pkt == NULL) {
		return KNOT_EINVAL;
	}

	uint16_t rr_id = 0;
	knot_rrset_t *rr = NULL;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);

	int ret = xfrin_take_rr(answer, &rr, &rr_id);
	if (*zone == NULL) {
		// Transfer start, init zone
		if (rr->type != KNOT_RRTYPE_SOA) {
			knot_rrset_free(&rr, NULL);
			return KNOT_EMALF;
		}
		*zone = knot_zone_contents_new(rr->owner);
		if (*zone == NULL) {
			knot_rrset_free(&rr, NULL);
			return KNOT_ENOMEM;
		}
		xfr->packet_nr = 0;
	} else {
		++xfr->packet_nr;
	}

	// Init zone creator
	zcreator_t zc = {.z = *zone,
	                 .master = false, .ret = KNOT_EOK };


	while (ret == KNOT_EOK && rr) {
		if (rr->type == KNOT_RRTYPE_SOA &&
		    knot_node_rrset(zc.z->apex, KNOT_RRTYPE_SOA)) {
			// Last SOA, last message, check TSIG.
			ret = xfrin_check_tsig(pkt, xfr, 1);
			knot_rrset_free(&rr, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
			return 1; // Signal that transfer finished.
		} else {
			ret = zcreator_step(&zc, rr);
			if (ret != KNOT_EOK) {
				knot_rrset_free(&rr, NULL);
				return ret;
			}
			ret = xfrin_take_rr(answer, &rr, &rr_id);
		}
	}

	assert(rr == NULL);
	// Check possible TSIG at the end of DNS message.
	ret = xfrin_check_tsig(pkt, xfr,
	                       knot_ns_tsig_required(xfr->packet_nr));
	return ret; // ret == KNOT_EOK means processing continues.
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
	knot_rrset_t *rr = NULL;
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	int ret = xfrin_take_rr(answer, &rr, &rr_id);
	if (ret != KNOT_EOK) {
		return KNOT_EXFRREFUSED; /* Empty, try again with AXFR */
	}

	// state of the transfer
	// -1 .. a SOA is expected to create a new changeset
	int state = 0;

	/*! \todo Replace with RRSet duplicate checking. */
//	xfrin_insert_rrset_dnames_to_table(rr, xfr->lookup_tree);

	if (*chs == NULL) {
		dbg_xfrin_verb("Changesets empty, creating new.\n");

		ret = knot_changesets_init(chs);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&rr, NULL);
			return ret;
		}

		// the first RR must be a SOA
		if (knot_rrset_type(rr) != KNOT_RRTYPE_SOA) {
			dbg_xfrin("First RR is not a SOA RR!\n");
			knot_rrset_free(&rr, NULL);
			ret = KNOT_EMALF;
			goto cleanup;
		}

		// just store the first SOA for later use
		(*chs)->first_soa = rr;
		state = -1;

		dbg_xfrin_verb("First SOA of IXFR saved, state set to -1.\n");

		// take next RR
		ret = xfrin_take_rr(answer, &rr, &rr_id);

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
		} else if (knot_rrset_type(rr) != KNOT_RRTYPE_SOA) {
			knot_rrset_free(&rr, NULL);
			dbg_xfrin("Fallback to AXFR.\n");
			ret = XFRIN_RES_FALLBACK;
			return ret;
		}
	} else {
		if ((*chs)->first_soa == NULL) {
			dbg_xfrin("Changesets don't contain SOA first!\n");
			knot_rrset_free(&rr, NULL);
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
			knot_rrset_free(&rr, NULL);
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

	while (ret == KNOT_EOK && rr != NULL) {
dbg_xfrin_exec_verb(
		dbg_xfrin_detail("Next loop, state: %d\n", state);
		char *name = knot_dname_to_str(knot_rrset_owner(rr));
		dbg_xfrin_detail("Actual RR: %s, type %u.\n", name,
				 knot_rrset_type(rr));
		free(name);
);
		if (!knot_dname_is_sub(rr->owner, xfr->zone->name) &&
		    !knot_dname_is_equal(rr->owner, xfr->zone->name)) {
			// out-of-zone domain
			knot_rrset_free(&rr, NULL);
			// take next RR
			ret = xfrin_take_rr(answer, &rr, &rr_id);
			continue;
		}

		switch (state) {
		case -1:
			// a SOA is expected
			// this may be either a start of a changeset or the
			// last SOA (in case the transfer was empty, but that
			// is quite weird in fact
			if (knot_rrset_type(rr) != KNOT_RRTYPE_SOA) {
				dbg_xfrin("First RR is not a SOA RR!\n");
				dbg_xfrin_verb("RR type: %u\n",
					       knot_rrset_type(rr));
				knot_rrset_free(&rr, NULL);
				ret = KNOT_EMALF;
				goto cleanup;
			}

			if (knot_rdata_soa_serial(rr)
			    == knot_rdata_soa_serial((*chs)->first_soa)) {

				/*! \note [TSIG] Check TSIG, we're at the end of
				 *               transfer.
				 */
				ret = xfrin_check_tsig(pkt, xfr, 1);

				// last SOA, discard and end
				knot_rrset_free(&rr, NULL);

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
					knot_rrset_free(&rr, NULL);
					goto cleanup;
				}

				chset = knot_changesets_create_changeset(*chs);
				if (chset == NULL) {
					knot_rrset_free(&rr, NULL);
					goto cleanup;
				}
				knot_changeset_add_soa(chset, rr, KNOT_CHANGESET_REMOVE);

				// change state to REMOVE
				state = KNOT_CHANGESET_REMOVE;
			}
			break;
		case KNOT_CHANGESET_REMOVE:
			// if the next RR is SOA, store it and change state to
			// ADD
			if (knot_rrset_type(rr) == KNOT_RRTYPE_SOA) {
				// we should not be here if soa_from is not set
				assert(chset->soa_from != NULL);

				knot_changeset_add_soa(chset, rr, KNOT_CHANGESET_ADD);

				state = KNOT_CHANGESET_ADD;
			} else {
				// just add the RR to the REMOVE part and
				// continue
				ret = knot_changeset_add_rr(chset, rr,
				                            KNOT_CHANGESET_REMOVE);
				if (ret != KNOT_EOK) {
					knot_rrset_free(&rr, NULL);
					goto cleanup;
				}
			}
			break;
		case KNOT_CHANGESET_ADD:
			// if the next RR is SOA change to state -1 and do not
			// parse next RR
			if (knot_rrset_type(rr) == KNOT_RRTYPE_SOA) {
				log_zone_info("%s Serial %u -> %u.\n",
					      xfr->msg,
					      knot_rdata_soa_serial(chset->soa_from),
					      knot_rdata_soa_serial(chset->soa_to));
				state = -1;
				continue;
			} else {

				// just add the RR to the ADD part and continue
				ret = knot_changeset_add_rr(chset, rr,
				                            KNOT_CHANGESET_ADD);
				if (ret != KNOT_EOK) {
					knot_rrset_free(&rr, NULL);
					goto cleanup;
				}
			}
			break;
		}

		// take next RR
		ret = xfrin_take_rr(answer, &rr, &rr_id);
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

void xfrin_zone_contents_free(knot_zone_contents_t **contents)
{
	/*! \todo This should be all in some API!! */

	// free the zone tree with nodes
	dbg_zone("Destroying zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nodes);
	dbg_zone("Destroying NSEC3 zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nsec3_nodes);

	knot_nsec3_params_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

int xfrin_copy_old_rrset(knot_rrset_t *old, knot_rrset_t **copy,
                         knot_changes_t *changes, int save_new)
{
	dbg_xfrin_detail("Copying old RRSet: %p\n", old);
	// create new RRSet by copying the old one
	int ret = knot_rrset_copy(old, copy, NULL);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to create RRSet copy.\n");
		return KNOT_ENOMEM;
	}

	// add the RRSet to the list of new RRSets
	if (save_new) {
		ret = knot_changes_add_rrset(changes, *copy, KNOT_CHANGES_NEW);
		if (ret != KNOT_EOK) {
			knot_rrset_free(copy, NULL);
			return ret;
		}
	}

	ret = knot_changes_add_rrset(changes, old, KNOT_CHANGES_OLD);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_copy_rrset(knot_node_t *node, uint16_t type,
                     knot_rrset_t **rrset, knot_changes_t *changes,
                     int save_new)
{
dbg_xfrin_exec_detail(
	char *name = knot_dname_to_str(knot_node_owner(node));
	dbg_xfrin_detail("Removing RRSet of type %u from node %s (%p)\n",
			 type, name, node);
	free(name);
);
	knot_rrset_t *old = knot_node_remove_rrset(node, type);

	dbg_xfrin_detail("Removed RRSet: %p\n", old);
	dbg_xfrin_detail("Other RRSet of the same type in the node: %p\n",
			 knot_node_rrset(node, type));

	if (old == NULL) {
		dbg_xfrin_verb("RRSet not found for RR to be removed.\n");
		return 1;
	}

	int ret = xfrin_copy_old_rrset(old, rrset, changes, save_new);
	if (ret != KNOT_EOK) {
		return ret;
	}

	dbg_xfrin_detail("Copied old rrset %p to new %p.\n", old, *rrset);

	// replace the RRSet in the node copy by the new one
	ret = knot_node_add_rrset_replace(node, *rrset);
	if (ret != KNOT_EOK) {
		knot_rrset_free(rrset, NULL);
		dbg_xfrin("Failed to add RRSet copy to node\n");
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_remove_normal(knot_changes_t *changes,
                                     const knot_rrset_t *remove,
                                     knot_node_t *node,
                                     knot_rrset_t **rrset)
{
	assert(changes != NULL);
	assert(remove != NULL);
	assert(node != NULL);
	assert(rrset != NULL);

	int ret;

	// now we have the copy of the node, so lets get the right RRSet
	// check if we do not already have it
	if (*rrset
	    && knot_dname_cmp(knot_rrset_owner(*rrset),
				  knot_node_owner(node)) == 0
	    && knot_rrset_type(*rrset) == knot_rrset_type(remove)) {
		/*! \todo Does some other case even occur? */
		dbg_xfrin_verb("Using RRSet from previous loop.\n");
	} else {
		/*!
		 * \todo This may happen also with already
		 *       copied RRSet. In that case it would be
		 *       an unnecesary overhead but will
		 *       probably not cause problems. TEST!!
		 */
		ret = xfrin_copy_rrset(node,
			knot_rrset_type(remove), rrset, changes, 1);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (*rrset == NULL) {
		dbg_xfrin_verb("RRSet not found for RR to be removed.\n");
		return 1;
	}

dbg_xfrin_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(*rrset));
	dbg_xfrin_detail("Updating RRSet with owner %s, type %u\n", name,
			 knot_rrset_type(*rrset));
	free(name);
);

	// remove the specified RRs from the RRSet (de facto difference of sets)
	knot_rrset_t *rr_remove = NULL;
	ret = knot_rrset_remove_rr_using_rrset(*rrset, remove, &rr_remove, NULL);
	if (ret != KNOT_EOK) {
		dbg_xfrin("xfr: remove_normal: Could not remove RR (%s).\n",
			  knot_strerror(ret));
		return ret;
	}
	/*!< \todo either one of these checks should be enough. */
	if (knot_rrset_rr_count(rr_remove) == 0) {
		/* No RDATA, no need to deep free. */
		knot_rrset_free(&rr_remove, NULL);
		dbg_xfrin_verb("Failed to remove RDATA from RRSet\n");
		// In this case, the RDATA was not found in the RRSet
		return 1;
	}

	if (knot_rrset_rr_count(rr_remove) > 0) {
		ret = knot_changes_add_rrset(changes, rr_remove, KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&rr_remove, NULL);
			return ret;
		}
	} else {
		/* Discard empty RRSet. */
		knot_rrset_free(&rr_remove, NULL);
	}

	// if the RRSet is empty, remove from node and add to old RRSets
	if (knot_rrset_rr_count(*rrset) == 0) {
		knot_rrset_t *tmp = knot_node_remove_rrset(node,
						     knot_rrset_type(*rrset));
		dbg_xfrin_detail("Removed whole RRSet (%p). Node rr count=%d\n",
				 tmp, knot_node_rrset_count(node));

		// add the removed RRSet to list of old RRSets

		assert(tmp == *rrset);
		ret = knot_changes_add_rrset(changes, *rrset, KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to add empty RRSet to the "
				  "list of old RRSets.");
			// delete the RRSet right away
			knot_rrset_free(rrset, NULL);
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static knot_node_t *xfrin_add_new_node(knot_zone_contents_t *contents,
                                       knot_rrset_t *rrset, int is_nsec3)
{
	knot_node_t *node = knot_node_new(knot_rrset_get_owner(rrset),
					  NULL, 0);
	if (node == NULL) {
		dbg_xfrin("Failed to create a new node.\n");
		return NULL;
	}

	int ret = 0;

	// insert the node into zone structures and create parents if
	// necessary
	if (is_nsec3) {
		ret = knot_zone_contents_add_nsec3_node(contents, node, 1, 0);
	} else {
		ret = knot_zone_contents_add_node(contents, node, 1, 0);
	}
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to add new node to zone contents.\n");
		knot_node_free(&node);
		return NULL;
	}

	return node;
}

/*----------------------------------------------------------------------------*/

int xfrin_replace_rrset_in_node(knot_node_t *node,
                                       knot_rrset_t *rrset_new,
                                       knot_changes_t *changes,
                                       knot_zone_contents_t *contents)
{
	if (node == NULL || rrset_new == NULL || changes == NULL
	    || contents == NULL) {
		return KNOT_EINVAL;
	}

	uint16_t type = knot_rrset_type(rrset_new);
	// remove RRSet of the proper type from the node
	dbg_xfrin_verb("Removing RRSet of type: %u.\n", type);
	knot_rrset_t *rrset_old = knot_node_remove_rrset(node, type);
	assert(rrset_old != NULL);

	// save also the RDATA, because RDATA are not deleted with the RRSet
	// save the new RRSet to the new RRSet, so that it is deleted if the
	// apply fails
	int ret = knot_changes_add_rrset(changes, rrset_old, KNOT_CHANGES_OLD);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// insert the new RRSet to the node
	dbg_xfrin_verb("Adding new RRSet.\n");
	ret = knot_zone_contents_add_rrset(contents, rrset_new, &node,
	                                   KNOT_RRSET_DUPL_SKIP);

	if (ret < 0) {
		dbg_xfrin("Failed to add RRSet to node.\n");
		return KNOT_ERROR;
	}
	assert(ret == 0);

	ret = knot_changes_add_rrset(changes, rrset_new, KNOT_CHANGES_NEW);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_add_normal(knot_changes_t *changes,
                                  knot_rrset_t *add,
                                  knot_node_t *node,
                                  knot_rrset_t **rrset,
                                  knot_zone_contents_t *contents)
{
	assert(changes != NULL);
	assert(add != NULL);
	assert(node != NULL);
	assert(rrset != NULL);
	assert(contents != NULL);

	int ret;

	int copied = 0;
	/*! \note Reusing RRSet from previous function caused it not to be
	 *        removed from the node.
	 *        Maybe modification of the code would allow reusing the RRSet
	 *        as in apply_add_rrsigs() - the RRSet should not be copied
	 *        in such case.
	 */
	if (*rrset
	    && knot_dname_cmp(knot_rrset_owner(*rrset),
				  knot_node_owner(node)) == 0
	    && knot_rrset_type(*rrset) == knot_rrset_type(add)) {
		dbg_xfrin_verb("Using RRSet from previous iteration.\n");
	} else {
		dbg_xfrin_detail("Removing rrset!\n");
		*rrset = knot_node_remove_rrset(node, knot_rrset_type(add));

		knot_rrset_t *old = *rrset;

		if (*rrset != NULL) {
			ret = xfrin_copy_old_rrset(old, rrset, changes, 1);
			if (ret != KNOT_EOK) {
				return ret;
			}
			copied = 1;
		}
	}

	if (*rrset == NULL) {
dbg_xfrin_exec_detail(
		char *name = knot_dname_to_str(add->owner);
		dbg_xfrin_detail("RRSet to be added not found in zone.\n");
		dbg_xfrin_detail("owner: %s type: %u\n", name, add->type);
		free(name);
);
		// add the RRSet from the changeset to the node
		/*!
		 * \note The new zone must be adjusted nevertheless, so it
		 *       doesn't matter whether there are some extra dnames to
		 *       be added to the table or not.
		 */
		ret = knot_zone_contents_add_rrset(contents, add, &node,
						   KNOT_RRSET_DUPL_SKIP);

		if (ret < 0) {
			dbg_xfrin("Failed to add RRSet to node.\n");
			return ret;
		}

		assert(ret == 0);

		return 1; // return 1 to indicate the add RRSet was used
	}

dbg_xfrin_exec_detail(
	char *name = knot_dname_to_str(knot_rrset_owner(*rrset));
	dbg_xfrin_detail("Found RRSet with owner %s, type %u\n", name,
			 knot_rrset_type(*rrset));
	free(name);
);

	// merge the changeset RRSet to the copy
	/* What if the update fails?
	 * The changesets will be destroyed - that will destroy 'add',
	 * and the copied RRSet will be destroyed because it is in the new
	 * rrsets list.
	 *
	 * If the update is successfull, the old RRSet will be destroyed,
	 * but the one from the changeset will be not!!
	 *
	 * TODO: add the 'add' rrset to list of old RRSets?
	 */

	 /* Check if the added RR has the same TTL as the first RR from the
	  * zone's RRSet. If not, log a warning.
	  * We assume that the added RRSet has only one RR, but that should be
	  * the case here.
	  */
	if (knot_rrset_type(add) != KNOT_RRTYPE_RRSIG
	    && !knot_rrset_ttl_equal(add, *rrset)) {
		char type_str[16] = { '\0' };
		knot_rrtype_to_string(knot_rrset_type(add), type_str,
		                      sizeof(type_str));
		char *name = knot_dname_to_str(knot_rrset_owner(add));
		char *zname = knot_dname_to_str(knot_node_owner(contents->apex));
		log_zone_warning("Changes application to zone %s: TTL mismatch"
		                 " in %s, type %s\n", zname, name, type_str);
		free(name);
		free(zname);
	}

	int merged, deleted_rrs;
	ret = knot_rrset_merge_sort(*rrset, add, &merged, &deleted_rrs,
	                            NULL);
	if (ret < 0) {
		dbg_xfrin("Failed to merge changeset RRSet.\n");
		return ret;
	}
	if (copied) {
		ret = knot_node_add_rrset_no_merge(node, *rrset);

		if (ret < 0) {
			dbg_xfrin("Failed to add merged RRSet to the node.\n");
			return ret;
		}
	}

	// return 2 so that the add RRSet is removed from
	// the changeset (and thus not deleted)
	// and put to list of new RRSets (is this ok?)
	// and deleted
	return 2;
}

/*----------------------------------------------------------------------------*/

void xfrin_cleanup_successful_update(knot_changes_t *changes)
{
	if (changes == NULL) {
		return;
	}
	// Free old RRSets
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, changes->old_rrsets) {
		knot_rrset_t *rrset = rr_node->rr;
		knot_rrset_free(&rrset, NULL);
	}
}

/*----------------------------------------------------------------------------*/
/* New changeset applying                                                     */
/*----------------------------------------------------------------------------*/

static int xfrin_switch_nodes_in_node(knot_node_t **node, void *data)
{
	UNUSED(data);

	assert(node && *node);
	assert(knot_node_new_node(*node) == NULL);

	knot_node_update_refs(*node);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_switch_nodes(knot_zone_contents_t *contents_copy)
{
	assert(contents_copy != NULL);

	// Traverse the trees and for each node check every reference
	// stored in that node. The node itself should be new.
	int ret = knot_zone_tree_apply(contents_copy->nodes,
	                               xfrin_switch_nodes_in_node, NULL);
	if (ret == KNOT_EOK) {
		ret = knot_zone_tree_apply(contents_copy->nsec3_nodes,
		                           xfrin_switch_nodes_in_node, NULL);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static void xfrin_zone_contents_free2(knot_zone_contents_t **contents)
{
	/*! \todo This should be all in some API!! */

	// free the zone tree, but only the structure
	// (nodes are already destroyed)
	dbg_zone("Destroying zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nodes);
	dbg_zone("Destroying NSEC3 zone tree.\n");
	knot_zone_tree_deep_free(&(*contents)->nsec3_nodes);

	knot_nsec3_params_free(&(*contents)->nsec3_params);

	free(*contents);
	*contents = NULL;
}

/*----------------------------------------------------------------------------*/

static int xfrin_cleanup_old_nodes(knot_node_t **node, void *data)
{
	UNUSED(data);
	assert(node && *node);

	knot_node_set_new_node(*node, NULL);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static void xfrin_cleanup_failed_update(knot_zone_contents_t *old_contents,
                                        knot_zone_contents_t **new_contents)
{
	if (old_contents == NULL && new_contents == NULL) {
		return;
	}

	if (*new_contents != NULL) {
		// destroy the shallow copy of zone
		xfrin_zone_contents_free2(new_contents);
	}

	if (old_contents != NULL) {
		// cleanup old zone tree - reset pointers to new node to NULL
		knot_zone_tree_apply(old_contents->nodes, xfrin_cleanup_old_nodes,
				     NULL);

		knot_zone_tree_apply(old_contents->nsec3_nodes, xfrin_cleanup_old_nodes,
				     NULL);
	}
}

/*----------------------------------------------------------------------------*/

void xfrin_rollback_update(knot_zone_contents_t *old_contents,
                           knot_zone_contents_t **new_contents,
                           knot_changes_t *changes)
{
	if (changes == NULL) {
		return;
	}

	dbg_xfrin("Rolling back changeset application.\n");
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, changes->new_rrsets) {
		knot_rrset_t *rrset = rr_node->rr;
		knot_rrset_free(&rrset, NULL);
	}

	xfrin_cleanup_failed_update(old_contents, new_contents);
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_remove(knot_zone_contents_t *contents,
                              knot_changeset_t *chset,
                              knot_changes_t *changes)
{
	/*
	 * Iterate over removed RRSets, and remove them from the new nodes
	 * in 'contents'. By default, the RRSet should be copied so that
	 * RDATA may be removed from it.
	 */
	int ret = 0;
	knot_node_t *last_node = NULL;
	knot_rrset_t *rrset = NULL;
	int is_nsec3 = 0;

	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, chset->remove) {
		knot_rrset_t *rr = rr_node->rr;
		assert(rr); // No malformed changesets should get here
dbg_xfrin_exec_verb(
		char *name = knot_dname_to_str(
			knot_rrset_owner(rr));
		dbg_xfrin_verb("Removing RRSet: %s, type %u\n", name,
			       knot_rrset_type(rr));
		free(name);
);

		is_nsec3 = 0;

		// check if the RRSet belongs to the NSEC3 tree
		if ((knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3)
		    || (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG
			&& knot_rdata_rrsig_type_covered(rr, 0)
			    == KNOT_RRTYPE_NSEC3))
		{
			dbg_xfrin_verb("Removed RRSet belongs to NSEC3 tree.\n");
			is_nsec3 = 1;
		}

		// check if the old node is not the one we should use
		dbg_xfrin_verb("Node:%p Owner: %p Node owner: %p\n",
			       last_node, knot_rrset_owner(rr),
			       knot_node_owner(last_node));
		if (!last_node || knot_rrset_owner(rr)
			     != knot_node_owner(last_node)) {
			if (is_nsec3) {
				last_node = knot_zone_contents_get_nsec3_node(
					    contents,
					    knot_rrset_owner(rr));
			} else {
				last_node = knot_zone_contents_get_node(contents,
					    knot_rrset_owner(rr));
			}
			if (last_node == NULL) {
				dbg_xfrin_verb("Node not found for RR to be "
					       "removed!\n");
				continue;
			}
		}

		assert(last_node != NULL);

		// The CLASS should not be ANY, we do not accept such chgsets
		dbg_xfrin_verb("RRSet class to be removed=%u\n",
			       knot_rrset_class(rr));
		// this should work also for UPDATE
		ret = xfrin_apply_remove_normal(changes, rr, last_node,
		                                &rrset);

		dbg_xfrin_detail("xfrin_apply_remove() ret = %d\n", ret);

		if (ret > 0) {
			continue;
		} else if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_add(knot_zone_contents_t *contents,
                           knot_changeset_t *chset,
                           knot_changes_t *changes)
{
	int ret = KNOT_EOK;
	knot_node_t *last_node = NULL;
	knot_rrset_t *rrset = NULL;
	int is_nsec3 = 0;

	knot_rr_ln_t *rr_node = NULL;
	node_t *tmp_node;
	WALK_LIST_DELSAFE(rr_node, tmp_node, chset->add) {
		knot_rrset_t *rr = rr_node->rr;
		assert(rr); // No malformed changesets should get here
dbg_xfrin_exec_verb(
		char *name = knot_dname_to_str(
			knot_rrset_owner(rr));
		dbg_xfrin_verb("Adding RRSet: %s, type: %u\n", name,
			       knot_rrset_type(rr));
		free(name);
);
		is_nsec3 = 0;

		// check if the RRSet belongs to the NSEC3 tree
		if ((knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3)
		    || (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG
			&& knot_rdata_rrsig_type_covered(rr, 0)
			    == KNOT_RRTYPE_NSEC3))
		{
			dbg_xfrin_detail("This is NSEC3-related RRSet.\n");
			is_nsec3 = 1;
		}

		// check if the old node is not the one we should use
		if (!last_node || knot_rrset_owner(rr)
			     != knot_node_owner(last_node)) {
			dbg_xfrin_detail("Searching for node...\n");
			if (is_nsec3) {
				last_node = knot_zone_contents_get_nsec3_node(
				            contents,
				            knot_rrset_owner(rr));
			} else {
				last_node = knot_zone_contents_get_node(contents,
				            knot_rrset_owner(rr));
			}
			if (last_node == NULL) {
				// create new node, connect it properly to the
				// zone nodes
				dbg_xfrin_detail("Node not found. Creating new."
						 "\n");
				last_node = xfrin_add_new_node(contents,
							  rr,
							  is_nsec3);
				if (last_node == NULL) {
					dbg_xfrin("Failed to create new node "
						  "in zone.\n");
					return KNOT_ERROR;
				}
			}
		}

		ret = xfrin_apply_add_normal(changes, rr, last_node,
		                             &rrset, contents);
		assert(ret <= 3);

		// Not correct anymore, add_normal() returns KNOT_EOK if the
		// changeset RR should be removed
		//assert(ret != KNOT_EOK);

		dbg_xfrin_detail("xfrin_apply_..() returned %d, rrset: %p\n",
				 ret, rrset);

		if (ret > 0) {
			if (ret == 1) {
				// the ADD RRSet was used, i.e. it should be
				// removed from the changeset and saved in the
				// list of new RRSets
				ret = knot_changes_add_rrset(changes, rr,
				                             KNOT_CHANGES_NEW);
				if (ret != KNOT_EOK) {
					dbg_xfrin("Failed to add old RRSet to "
						  "list.\n");
					return ret;
				}

				rem_node((node_t *)rr_node);
			} else if (ret == 2) {
				// the copy of the RRSet was used, but it was
				// already stored in the new RRSets list
				// just delete the add RRSet, but without RDATA
				// DNAMES as these were merged to the copied RRSet
				knot_rrset_free(&rr, NULL);
				rem_node((node_t *)rr_node);
			} else if (ret == 3) {
				// the RRSet was used and both RRSet and RDATA
				// were properly stored. Just clear the place
				// in the changeset
				rem_node((node_t *)rr_node);
			} else {
				assert(0);
			}

		} else if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_replace_soa(knot_zone_contents_t *contents,
                                   knot_changes_t *changes,
                                   knot_changeset_t *chset)
{
	dbg_xfrin("Replacing SOA record.\n");
	knot_node_t *node = knot_zone_contents_get_apex(contents);
	assert(node != NULL);

	assert(node != NULL);

	int ret = xfrin_replace_rrset_in_node(node, chset->soa_to, changes,
					      contents);
	if (ret == KNOT_EOK) {
		// remove the SOA from the changeset, so it will not be deleted
		// after successful apply
		chset->soa_to = NULL;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static int xfrin_apply_changeset(knot_zone_contents_t *contents,
                                 knot_changes_t *changes,
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
	const knot_rrset_t *soa = knot_node_rrset(contents->apex,
	                                          KNOT_RRTYPE_SOA);
	if (soa == NULL || knot_rdata_soa_serial(soa)
			   != chset->serial_from) {
		dbg_xfrin("SOA serials do not match!!\n");
		return KNOT_ERROR;
	}

	int ret = xfrin_apply_remove(contents, chset, changes);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = xfrin_apply_add(contents, chset, changes);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return xfrin_apply_replace_soa(contents, changes, chset);
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
	    !knot_node_is_empty(node)) {
		/*!
		 * Mark this node and all parent nodes that have 0 RRSets and
		 * no children for removal.
		 */
		int ret = add_node_to_list(node, l);
		if (ret != KNOT_EOK) {
			return ret;
		}
		knot_node_set_empty(node);
		if (node->parent) {
			if (node->parent->wildcard_child == node) {
				node->parent->wildcard_child = NULL;
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
	 * NSEC3 tree, hash table, domain name table), and copy all nodes.
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

	assert(knot_zone_contents_apex(contents_copy) != NULL);

	/*
	 * Fix references to new nodes. Some references in new nodes may point
	 * to old nodes. Hash table contains only old nodes.
	 */
	dbg_xfrin("Switching ptrs pointing to old nodes to the new nodes.\n");
	ret = xfrin_switch_nodes(contents_copy);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to switch pointers in nodes.\n");
		knot_zone_contents_free(&contents_copy);
		return ret;
	}
	assert(knot_zone_contents_apex(contents_copy) != NULL);

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

	assert(knot_zone_contents_apex(contents_copy) != NULL);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int xfrin_apply_changesets_directly(knot_zone_contents_t *contents,
                                    knot_changes_t *changes,
                                    knot_changesets_t *chsets)
{
	if (contents == NULL || changes == NULL || chsets == NULL) {
		return KNOT_EINVAL;
	}

	knot_changeset_t *set = NULL;
	WALK_LIST(set, chsets->sets) {
		int ret = xfrin_apply_changeset(contents, changes, set);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

/* Post-DDNS application, no need to shallow copy. */
int xfrin_apply_changesets_dnssec_ddns(knot_zone_contents_t *z_old,
                                       knot_zone_contents_t *z_new,
                                       knot_changesets_t *sec_chsets,
                                       knot_changesets_t *chsets)
{
	if (z_old == NULL || z_new == NULL ||
	    sec_chsets == NULL || chsets == NULL) {
		return KNOT_EINVAL;
	}

	/* Set generation to old. Zone should be long locked at this point. */
	knot_zone_contents_set_gen_old(z_new);

	/* Apply changes. */
	int ret = xfrin_apply_changesets_directly(z_new, chsets->changes,
	                                          sec_chsets);
	if (ret != KNOT_EOK) {
		xfrin_rollback_update(z_old, &z_new, chsets->changes);
		dbg_xfrin("Failed to apply changesets to zone: "
		          "%s\n", knot_strerror(ret));
		return ret;
	}

	const bool handle_nsec3 = true;
	ret = xfrin_finalize_updated_zone(z_new, handle_nsec3);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to finalize updated zone: %s\n",
		          knot_strerror(ret));
		xfrin_rollback_update(z_old, &z_new, chsets->changes);
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
		ret = xfrin_apply_changeset(contents_copy, chsets->changes, set);
		if (ret != KNOT_EOK) {
			xfrin_rollback_update(old_contents,
					       &contents_copy, chsets->changes);
			dbg_xfrin("Failed to apply changesets to zone: "
				  "%s\n", knot_strerror(ret));
			return ret;
		}
	}
	assert(knot_zone_contents_apex(contents_copy) != NULL);

	/*!
	 * \todo Test failure of IXFR.
	 */

	dbg_xfrin_verb("Finalizing updated zone...\n");
	ret = xfrin_finalize_updated_zone(contents_copy, true);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to finalize updated zone: %s\n",
			  knot_strerror(ret));
		xfrin_rollback_update(old_contents, &contents_copy, chsets->changes);
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
