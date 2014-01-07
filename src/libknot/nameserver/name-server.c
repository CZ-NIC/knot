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

#include <config.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <urcu.h>

#include "libknot/nameserver/name-server.h"
#include "libknot/updates/xfr-in.h"

#include "libknot/libknot.h"
#include "common/errcode.h"
#include "libknot/common.h"
#include "common/lists.h"
#include "libknot/util/debug.h"
#include "libknot/packet/pkt.h"
#include "libknot/consts.h"
#include "common/descriptor.h"
#include "libknot/updates/changesets.h"
#include "libknot/updates/ddns.h"
#include "libknot/tsig-op.h"
#include "libknot/rdata.h"
#include "libknot/dnssec/random.h"
#include "libknot/dnssec/zone-nsec.h"

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/

int knot_ns_tsig_required(int packet_nr)
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

static int32_t ns_serial_difference(uint32_t s1, uint32_t s2)
{
	return (((int64_t)s1 - s2) % ((int64_t)1 << 32));
}

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

knot_nameserver_t *knot_ns_create()
{
	knot_nameserver_t *ns = malloc(sizeof(knot_nameserver_t));
	if (ns == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	ns->data = 0;

	// Create zone database structure
	dbg_ns("Creating Zone Database structure...\n");
	ns->zone_db = knot_zonedb_new(0);
	if (ns->zone_db == NULL) {
		ERR_ALLOC_FAILED;
		free(ns);
		return NULL;
	}

	/* Prepare empty response with SERVFAIL error. */
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_HEADER_SIZE, NULL);
	if (pkt == NULL) {
		ERR_ALLOC_FAILED;
		free(ns);
		return NULL;
	}

	/* QR bit set. */
	knot_wire_set_qr(pkt->wire);
	knot_wire_set_rcode(pkt->wire, KNOT_RCODE_SERVFAIL);

	/* Store packet. */
	ns->err_response = pkt;

	ns->opt_rr = NULL;
	ns->identity = NULL;
	ns->version = NULL;
	return ns;
}

/*----------------------------------------------------------------------------*/

int knot_ns_parse_packet(knot_pkt_t *packet, knot_packet_type_t *type)
{
	dbg_ns("%s(%p, %p)\n", __func__, packet, type);
	if (packet == NULL || type == NULL) {
		return KNOT_EINVAL;
	}

	// 1) create empty response
	int ret = KNOT_ERROR;
	*type = KNOT_QUERY_INVALID;
	if ((ret = knot_pkt_parse_question(packet)) != KNOT_EOK) {
		dbg_ns("%s: couldn't parse question = %d\n", __func__, ret);
		return KNOT_RCODE_FORMERR;
	}

	// 2) determine the query type
	*type = knot_pkt_type(packet);
	if (*type & KNOT_QUERY_INVALID) {
		return KNOT_RCODE_NOTIMPL;
	}

	return KNOT_RCODE_NOERROR;
}

/*----------------------------------------------------------------------------*/

int ns_serial_compare(uint32_t s1, uint32_t s2)
{
	int32_t diff = ns_serial_difference(s1, s2);
	return (s1 == s2) /* s1 equal to s2 */
	        ? 0
	        :((diff >= 1 && diff < ((uint32_t)1 << 31))
	           ? 1	/* s1 larger than s2 */
	           : -1); /* s1 less than s2 */
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_axfrin(knot_nameserver_t *nameserver, knot_ns_xfr_t *xfr)
{
	/*
	 * Here we assume that 'xfr' contains TSIG information
	 * and the digest of the query sent to the master or the previous
	 * digest.
	 */

	dbg_ns("ns_process_axfrin: incoming packet, wire size: %zu\n",
	       xfr->wire_size);
	int ret = xfrin_process_axfr_packet(xfr);

	if (ret > 0) { // transfer finished
		dbg_ns("ns_process_axfrin: AXFR finished, zone created.\n");

		gettimeofday(&xfr->t_end, NULL);

		/*
		 * Adjust zone so that node count is set properly and nodes are
		 * marked authoritative / delegation point.
		 */
		xfrin_constructed_zone_t *constr_zone =
				(xfrin_constructed_zone_t *)xfr->data;
		knot_zone_contents_t *zone = constr_zone->contents;
		assert(zone != NULL);
		log_zone_info("%s Serial %u -> %u\n", xfr->msg,
		              knot_zone_serial(knot_zone_contents(xfr->zone)),
		              knot_zone_serial(zone));

		dbg_ns_verb("ns_process_axfrin: adjusting zone.\n");
		int rc = knot_zone_contents_adjust(zone, NULL, NULL, 0);
		if (rc != KNOT_EOK) {
			return rc;
		}

		// save the zone contents to the xfr->data
		xfr->new_contents = zone;
		xfr->flags |= XFR_FLAG_AXFR_FINISHED;

		assert(zone->nsec3_nodes != NULL);

		// free the structure used for processing XFR
		assert(constr_zone->rrsigs == NULL);
		free(constr_zone);

		// check zone integrity
dbg_ns_exec_verb(
		int errs = knot_zone_contents_integrity_check(zone);
		dbg_ns_verb("Zone integrity check: %d errors.\n", errs);
);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_switch_zone(knot_nameserver_t *nameserver,
                          knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || nameserver == NULL || xfr->new_contents == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_contents_t *zone = (knot_zone_contents_t *)xfr->new_contents;

	dbg_ns("Replacing zone by new one: %p\n", zone);
	if (zone == NULL) {
		dbg_ns("No new zone!\n");
		return KNOT_ENOZONE;
	}

	/* Zone must not be looked-up from server, as it may be a different zone if
	 * a reload occurs when transfer is pending. */
	knot_zone_t *z = xfr->zone;
	if (z == NULL) {
		char *name = knot_dname_to_str(knot_node_owner(
				knot_zone_contents_apex(zone)));
		dbg_ns("Failed to replace zone %s, old zone "
		       "not found\n", name);
		free(name);

		return KNOT_ENOZONE;
	} else {
		zone->zone = z;
	}

	rcu_read_unlock();
	int ret = xfrin_switch_zone(z, zone, xfr->type);
	rcu_read_lock();

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_ixfrin(knot_nameserver_t *nameserver,
                             knot_ns_xfr_t *xfr)
{
	dbg_ns("ns_process_ixfrin: incoming packet\n");

	/*
	 * [TSIG] Here we assume that 'xfr' contains TSIG information
	 * and the digest of the query sent to the master or the previous
	 * digest.
	 */
	int ret = xfrin_process_ixfr_packet(xfr);

	if (ret == XFRIN_RES_FALLBACK) {
		dbg_ns("ns_process_ixfrin: Fallback to AXFR.\n");
		ret = KNOT_ENOIXFR;
	}

	if (ret < 0) {
		knot_pkt_free(&xfr->query);
		return ret;
	} else if (ret > 0) {
		dbg_ns("ns_process_ixfrin: IXFR finished\n");
		gettimeofday(&xfr->t_end, NULL);

		knot_changesets_t *chgsets = (knot_changesets_t *)xfr->data;
		if (chgsets == NULL || chgsets->first_soa == NULL) {
			// nothing to be done??
			dbg_ns("No changesets created for incoming IXFR!\n");
			return ret;
		}

		// find zone associated with the changesets
		/* Must not search for the zone in zonedb as it may fetch a
		 * different zone than the one the transfer started on. */
		knot_zone_t *zone = xfr->zone;
		if (zone == NULL) {
			dbg_ns("No zone found for incoming IXFR!\n");
			knot_changesets_free(
				(knot_changesets_t **)(&xfr->data));
			return KNOT_ENOZONE;
		}

		switch (ret) {
		case XFRIN_RES_COMPLETE:
			break;
		case XFRIN_RES_SOA_ONLY: {
			// compare the SERIAL from the changeset with the zone's
			// serial
			const knot_node_t *apex = knot_zone_contents_apex(
					knot_zone_contents(zone));
			if (apex == NULL) {
				return KNOT_ERROR;
			}

			const knot_rrset_t *zone_soa = knot_node_rrset(
					apex, KNOT_RRTYPE_SOA);
			if (zone_soa == NULL) {
				return KNOT_ERROR;
			}

			if (ns_serial_compare(
			      knot_rdata_soa_serial(chgsets->first_soa),
			      knot_rdata_soa_serial(zone_soa))
			    > 0) {
				if ((xfr->flags & XFR_FLAG_UDP) != 0) {
					// IXFR over UDP
					dbg_ns("Update did not fit.\n");
					return KNOT_EIXFRSPACE;
				} else {
					// fallback to AXFR
					dbg_ns("ns_process_ixfrin: "
					       "Fallback to AXFR.\n");
					knot_changesets_free(
					      (knot_changesets_t **)&xfr->data);
					knot_pkt_free(&xfr->query);
					return KNOT_ENOIXFR;
				}

			} else {
				// free changesets
				dbg_ns("No update needed.\n");
				knot_changesets_free(
					(knot_changesets_t **)(&xfr->data));
				return KNOT_ENOXFR;
			}
		} break;
		}
	}

	/*! \todo In case of error, shouldn't the zone be destroyed here? */

	return ret;
}

/*----------------------------------------------------------------------------*/
/*
 * This function should:
 * 1) Create zone shallow copy and the changes structure.
 * 2) Call knot_ddns_process_update().
 *    - If something went bad, call xfrin_rollback_update() and return an error.
 *    - If everything went OK, continue.
 * 3) Finalize the updated zone.
 *
 * NOTE: Mostly copied from xfrin_apply_changesets(). Should be refactored in
 *       order to get rid of duplicate code.
 */
int knot_ns_process_update(const knot_pkt_t *query,
                           knot_zone_contents_t *old_contents,
                           knot_zone_contents_t **new_contents,
                           knot_changesets_t *chgs, knot_rcode_t *rcode,
                           uint32_t new_serial)
{
	if (query == NULL || old_contents == NULL || chgs == NULL ||
	    EMPTY_LIST(chgs->sets) || new_contents == NULL || rcode == NULL) {
		return KNOT_EINVAL;
	}

	dbg_ns("Applying UPDATE to zone...\n");

	// 1) Create zone shallow copy.
	dbg_ns_verb("Creating shallow copy of the zone...\n");
	knot_zone_contents_t *contents_copy = NULL;
	int ret = xfrin_prepare_zone_copy(old_contents, &contents_copy);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to prepare zone copy: %s\n",
		          knot_strerror(ret));
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	// 2) Apply the UPDATE and create changesets.
	dbg_ns_verb("Applying the UPDATE and creating changeset...\n");
	ret = knot_ddns_process_update(contents_copy, query,
	                               knot_changesets_get_last(chgs),
	                               chgs->changes, rcode, new_serial);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to apply UPDATE to the zone copy or no update"
		       " made: %s\n", (ret < 0) ? knot_strerror(ret)
		                                : "No change made.");
		xfrin_rollback_update(old_contents, &contents_copy,
		                      chgs->changes);
		return ret;
	}

	// 3) Finalize zone
	dbg_ns_verb("Finalizing updated zone...\n");
	ret = xfrin_finalize_updated_zone(contents_copy, chgs->changes);
	if (ret != KNOT_EOK) {
		dbg_ns("Failed to finalize updated zone: %s\n",
		       knot_strerror(ret));
		xfrin_rollback_update(old_contents, &contents_copy,
		                      chgs->changes);
		*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
		                             : KNOT_RCODE_SERVFAIL;
		return ret;
	}

	*new_contents = contents_copy;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ns_create_forward_query(const knot_pkt_t *query,
                                 uint8_t *query_wire, size_t *size)
{
	/* Forward UPDATE query:
	 * assign a new packet id
	 */
	int ret = KNOT_EOK;
	if (query->size > *size) {
		return KNOT_ESPACE;
	}

	memcpy(query_wire, query->wire, query->size);
	*size = query->size;
	knot_wire_set_id(query_wire, knot_random_uint16_t());

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_ns_process_forward_response(const knot_pkt_t *response,
                                     uint16_t original_id,
                                     uint8_t *response_wire, size_t *size)
{
	// copy the wireformat of the response and set the original ID
	if (response->size > *size) {
		return KNOT_ESPACE;
	}

	memcpy(response_wire, response->wire, response->size);
	*size = response->size;

	knot_wire_set_id(response_wire, original_id);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void *knot_ns_data(knot_nameserver_t *nameserver)
{
	return nameserver->data;
}

/*----------------------------------------------------------------------------*/

void *knot_ns_get_data(knot_nameserver_t *nameserver)
{
	return nameserver->data;
}

/*----------------------------------------------------------------------------*/

void knot_ns_set_data(knot_nameserver_t *nameserver, void *data)
{
	nameserver->data = data;
}

/*----------------------------------------------------------------------------*/

void knot_ns_destroy(knot_nameserver_t **nameserver)
{
	synchronize_rcu();

	if ((*nameserver)->opt_rr != NULL) {
		knot_edns_free(&(*nameserver)->opt_rr);
	}

	// destroy the zone db
	knot_zonedb_deep_free(&(*nameserver)->zone_db);

	/* Free error response. */
	knot_pkt_free(&(*nameserver)->err_response);

	free(*nameserver);
	*nameserver = NULL;
}

/* State -> string translation table. */
#define NS_STATE_STR(x) _state_table[x]
static const char* _state_table[] = {
        [NS_PROC_NOOP] = "NOOP",
        [NS_PROC_MORE] = "MORE",
        [NS_PROC_FULL] = "FULL",
        [NS_PROC_DONE] = "DONE",
        [NS_PROC_FAIL] = "FAIL"
};

int ns_proc_begin(ns_proc_context_t *ctx, void *module_param, const ns_proc_module_t *module)
{
	/* Only in inoperable state. */
	if (ctx->state != NS_PROC_NOOP) {
		return NS_PROC_NOOP;
	}

#ifdef KNOT_NS_DEBUG
	/* Check module API. */
	assert(module->begin);
	assert(module->in);
	assert(module->out);
	assert(module->err);
	assert(module->reset);
	assert(module->finish);
#endif /* KNOT_NS_DEBUG */

	ctx->module = module;
	ctx->state = module->begin(ctx, module_param);

	dbg_ns("%s -> %s\n", __func__, NS_STATE_STR(ctx->state));
	return ctx->state;
}

int ns_proc_reset(ns_proc_context_t *ctx)
{
	ctx->state = ctx->module->reset(ctx);
	dbg_ns("%s -> %s\n", __func__, NS_STATE_STR(ctx->state));
	return ctx->state;
}

int ns_proc_finish(ns_proc_context_t *ctx)
{
	/* Only in operable state. */
	if (ctx->state == NS_PROC_NOOP) {
		return NS_PROC_NOOP;
	}

	ctx->state = ctx->module->finish(ctx);
	dbg_ns("%s -> %s\n", __func__, NS_STATE_STR(ctx->state));
	return ctx->state;
}

int ns_proc_in(const uint8_t *wire, uint16_t wire_len, ns_proc_context_t *ctx)
{
	/* Only if expecting data. */
	if (ctx->state != NS_PROC_MORE) {
		return NS_PROC_NOOP;
	}

	knot_pkt_t *pkt = knot_pkt_new((uint8_t *)wire, wire_len, &ctx->mm);
	knot_pkt_parse(pkt, 0);

	ctx->state = ctx->module->in(pkt, ctx);
	dbg_ns("%s -> %s\n", __func__, NS_STATE_STR(ctx->state));
	return ctx->state;
}

int ns_proc_out(uint8_t *wire, uint16_t *wire_len, ns_proc_context_t *ctx)
{
	knot_pkt_t *pkt = knot_pkt_new(wire, *wire_len, &ctx->mm);

	switch(ctx->state) {
	case NS_PROC_FULL: ctx->state = ctx->module->out(pkt, ctx); break;
	case NS_PROC_FAIL: ctx->state = ctx->module->err(pkt, ctx); break;
	default:
		assert(0); /* Improper use. */
		knot_pkt_free(&pkt);
		return NS_PROC_NOOP;
	}

	/* Accept only finished result. */
	if (ctx->state != NS_PROC_FAIL) {
		*wire_len = pkt->size;
	} else {
		*wire_len = 0;
	}
	
	knot_pkt_free(&pkt);

	dbg_ns("%s -> %s\n", __func__, NS_STATE_STR(ctx->state));
	return ctx->state;
}

/* #10 >>> Next-gen API. */
