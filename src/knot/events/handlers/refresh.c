/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdint.h>
#include <urcu.h>

#include "contrib/trim.h"
#include "dnssec/random.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/events/replan.h"
#include "knot/query/layer.h"
#include "knot/query/query.h"
#include "knot/updates/apply.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

/// TODO. Memory context.
/// TODO. Adjusting.

#include "contrib/mempattern.h" // mm_free()
#include "knot/nameserver/ixfr.h" // struct ixfr_proc
#include "knot/zone/zonefile.h" // err_handler_logger_t
#include "knot/zone/serial.h" // serial_compare (move to libknot)

/*!
 * \brief Refresh event processing.
 *
 * The following diagram represents refresh event processing.
 *
 * \verbatim
 *                               O
 *                               |
 *                         +-----v-----+
 *                         |   BEGIN   |
 *                         +---+---+---+
 *               has SOA       |   |           no SOA
 *         +-------------------+   +------------------------------+
 *         |                                                      |
 *  +------v------+  outdated  +--------------+   error   +-------v------+
 *  |  SOA query  +------------>  IXFR query  +----------->  AXFR query  |
 *  +-----+---+---+            +------+-------+           +----+----+----+
 *  error |   | current               | success        success |    | error
 *        |   +-----+ +---------------+                        |    |
 *        |         | | +--------------------------------------+    |
 *        |         | | |              +----------+  +--------------+
 *        |         | | |              |          |  |
 *        |      +--v-v-v--+           |       +--v--v--+
 *        |      |  DONE   |           |       |  FAIL  |
 *        |      +---------+           |       +--------+
 *        +----------------------------+
 *
 * \endverbatim
 */

#define REFRESH_LOG(priority, zone, remote, msg...) \
	ns_log(priority, zone, LOG_OPERATION_REFRESH, LOG_DIRECTION_OUT, remote, msg)

#define _XFRIN_LOG(priority, operation, zone, remote, msg...) \
	ns_log(priority, zone, operation, LOG_DIRECTION_IN, remote, msg)

#define AXFRIN_LOG(priority, zone, remote, msg...) \
	_XFRIN_LOG(priority, LOG_OPERATION_AXFR, zone, remote, msg)

#define IXFRIN_LOG(priority, zone, remote, msg...) \
	_XFRIN_LOG(priority, LOG_OPERATION_IXFR, zone, remote, msg)

#define BOOTSTRAP_MAXTIME (24*60*60)
#define BOOTSTRAP_JITTER (30)

enum state {
	REFRESH_STATE_INVALID = 0,
	STATE_SOA_QUERY,
	STATE_TRANSFER,
};

struct transfer_result {
	zone_contents_t *zone;  //!< AXFR, new zone
	list_t changesets;      //!< IXFR, zone updates
};

struct refresh_data {
	enum state state;                 //!< Event processing state.
	struct transfer_result result;    //!< Result of the refresh event.
	bool is_ixfr;                     //!< Transfer is IXFR not AXFR.

	const knot_dname_t *zone;         //!< Zone name.
	const struct sockaddr *remote;    //!< Remote endpoint.
	struct query_edns_data edns;      //!< EDNS data to be used in queries.
	const knot_rrset_t *soa;          //!< Local SOA (NULL for AXFR).

	struct xfr_stats stats;           //!< Transfer statistics.

	struct {
		struct ixfr_proc *proc;   //!< IXFR processing context.
		knot_rrset_t *final_soa;  //!< SOA denoting end of transfer.
	} ixfr;

	knot_mm_t *mm; // TODO: check where this should be used
};

static const char *rcode_name(uint16_t rcode)
{
	const knot_lookup_t *lut = knot_lookup_by_id(knot_rcode_names, rcode);
	return lut ? lut->name : "unknown RCODE";
}

static bool serial_is_current(uint32_t local_serial, uint32_t remote_serial)
{
	return serial_compare(local_serial, remote_serial) >= 0;
}

static void transfer_result_init(struct transfer_result *result)
{
	result->zone = NULL;
	init_list(&result->changesets);
}

static void transfer_result_cleanup(struct transfer_result *result)
{
	zone_contents_deep_free(&result->zone);
	changesets_free(&result->changesets);
	memset(result, 0, sizeof(*result));
}

static bool transfer_result_has_data(const struct transfer_result *result)
{
	return result->zone || !EMPTY_LIST(result->changesets);
}

time_t bootstrap_next(const zone_timers_t *timers)
{
	// previous interval
	time_t interval = timers->next_refresh - timers->last_refresh;
	if (interval < 0) {
		interval = 0;
	}

	// exponentional backoff
	interval *= 2;
	if (interval > BOOTSTRAP_MAXTIME) {
		interval = BOOTSTRAP_MAXTIME;
	}

	// prevent burst refresh
	interval += dnssec_random_uint16_t() % BOOTSTRAP_JITTER;

	return interval;
}

static int axfr_consume_packet(knot_pkt_t *pkt, zone_contents_t *zone)
{
	assert(pkt);
	assert(zone);

	zcreator_t zc = { .z = zone, .master = false, .ret = KNOT_EOK };

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_rrset_t *answer_rr = knot_pkt_rr(answer, 0);
	for (uint16_t i = 0; i < answer->count; ++i) {
		if (answer_rr[i].type == KNOT_RRTYPE_SOA &&
		    node_rrtype_exists(zc.z->apex, KNOT_RRTYPE_SOA)) {
			return KNOT_STATE_DONE;
		}

		int ret = zcreator_step(&zc, &answer_rr[i]);
		if (ret != KNOT_EOK) {
			return KNOT_STATE_FAIL;
		}
	}

	return KNOT_STATE_CONSUME;
}

static int axfr_consume(knot_pkt_t *pkt, struct refresh_data *data)
{
	assert(pkt);
	assert(data);

	// Check RCODE
	uint16_t rcode = knot_pkt_get_ext_rcode(pkt);
	if (rcode != KNOT_RCODE_NOERROR) {
		AXFRIN_LOG(LOG_WARNING, data->zone, data->remote,
		           "server responded with %s", rcode_name(rcode));
		return KNOT_STATE_FAIL;
	}

	// Initialize with first packet
	if (data->result.zone == NULL) {
		data->result.zone = zone_contents_new(data->zone);
		if (!data->result.zone) {
			AXFRIN_LOG(LOG_WARNING, data->zone, data->remote,
			           "failed to initialize (%s)", knot_strerror(KNOT_ENOMEM));
			return KNOT_STATE_FAIL;
		}

		AXFRIN_LOG(LOG_INFO, data->zone, data->remote, "starting");
		xfr_stats_begin(&data->stats);
	}

	// Process answer packet
	xfr_stats_add(&data->stats, pkt->size);
	int next = axfr_consume_packet(pkt, data->result.zone);

	// Finalize
	if (next == KNOT_STATE_DONE) {
		int ret = zone_contents_adjust_full(data->result.zone);
		if (ret != KNOT_EOK) {
			return KNOT_STATE_FAIL;
		}

		xfr_stats_end(&data->stats);
	}

	return next;
}

/*! \brief Initialize IXFR-in processing context. */
static int ixfr_init(struct refresh_data *data)
{
	struct ixfr_proc *proc = mm_alloc(data->mm, sizeof(*proc));
	if (proc == NULL) {
		return KNOT_ENOMEM;
	}
	memset(proc, 0, sizeof(struct ixfr_proc));
	proc->state = IXFR_START;
	proc->mm = data->mm;

	data->ixfr.proc = proc;
	data->ixfr.final_soa = NULL;

	return KNOT_EOK;
}

/*! \brief Clean up data allocated by IXFR-in processing. */
static void ixfr_cleanup(struct refresh_data *data)
{
	knot_rrset_free(&data->ixfr.final_soa, data->mm);
	mm_free(data->mm, data->ixfr.proc);
	data->ixfr.proc = NULL;
}

/*! \brief Stores starting SOA into changesets structure. */
static int ixfr_solve_start(const knot_rrset_t *rr, struct refresh_data *data)
{
	assert(data->ixfr.final_soa == NULL);
	if (rr->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	// Store terminal SOA
	data->ixfr.final_soa = knot_rrset_copy(rr, data->mm);
	if (data->ixfr.final_soa == NULL) {
		return KNOT_ENOMEM;
	}

	// Initialize list for changes
	init_list(&data->result.changesets);

	return KNOT_EOK;
}

/*! \brief Decides what to do with a starting SOA (deletions). */
static int ixfr_solve_soa_del(const knot_rrset_t *rr, struct refresh_data *data)
{
	if (rr->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	// Create new changeset.
	changeset_t *change = changeset_new(data->zone);
	if (change == NULL) {
		return KNOT_ENOMEM;
	}

	// Store SOA into changeset.
	change->soa_from = knot_rrset_copy(rr, NULL);
	if (change->soa_from == NULL) {
		changeset_clear(change);
		return KNOT_ENOMEM;
	}

	// Add changeset.
	add_tail(&data->result.changesets, &change->n);

	return KNOT_EOK;
}

/*! \brief Stores ending SOA into changeset. */
static int ixfr_solve_soa_add(const knot_rrset_t *rr, changeset_t *change, knot_mm_t *mm)
{
	if (rr->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	change->soa_to = knot_rrset_copy(rr, NULL);
	if (change->soa_to == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Adds single RR into remove section of changeset. */
static int ixfr_solve_del(const knot_rrset_t *rr, changeset_t *change, knot_mm_t *mm)
{
	return changeset_add_removal(change, rr, 0);
}

/*! \brief Adds single RR into add section of changeset. */
static int ixfr_solve_add(const knot_rrset_t *rr, changeset_t *change, knot_mm_t *mm)
{
	return changeset_add_addition(change, rr, 0);
}

/*! \brief Decides what the next IXFR-in state should be. */
static int ixfr_next_state(struct refresh_data *data, const knot_rrset_t *rr)
{
	const bool soa = (rr->type == KNOT_RRTYPE_SOA);
	enum ixfr_state state = data->ixfr.proc->state;

	if ((state == IXFR_SOA_ADD || state == IXFR_ADD) &&
	    knot_rrset_equal(rr, data->ixfr.final_soa, KNOT_RRSET_COMPARE_WHOLE)) {
		return IXFR_DONE;
	}

	switch (state) {
	case IXFR_START:
		// Final SOA already stored or transfer start.
		return data->ixfr.final_soa ? IXFR_SOA_DEL : IXFR_START;
	case IXFR_SOA_DEL:
		// Empty delete section or start of delete section.
		return soa ? IXFR_SOA_ADD : IXFR_DEL;
	case IXFR_SOA_ADD:
		// Empty add section or start of add section.
		return soa ? IXFR_SOA_DEL : IXFR_ADD;
	case IXFR_DEL:
		// End of delete section or continue.
		return soa ? IXFR_SOA_ADD : IXFR_DEL;
	case IXFR_ADD:
		// End of add section or continue.
		return soa ? IXFR_SOA_DEL : IXFR_ADD;
	default:
		assert(0);
		return IXFR_INVALID;
	}
}

/*!
 * \brief Processes single RR according to current IXFR-in state. The states
 *        correspond with IXFR-in message structure, in the order they are
 *        mentioned in the code.
 *
 * \param rr    RR to process.
 * \param proc  Processing context.
 *
 * \return KNOT_E*
 */
static int ixfr_step(const knot_rrset_t *rr, struct refresh_data *data)
{
	data->ixfr.proc->state = ixfr_next_state(data, rr);
	changeset_t *change = TAIL(data->result.changesets);

	switch (data->ixfr.proc->state) {
	case IXFR_START:
		return ixfr_solve_start(rr, data);
	case IXFR_SOA_DEL:
		return ixfr_solve_soa_del(rr, data);
	case IXFR_DEL:
		return ixfr_solve_del(rr, change, data->mm);
	case IXFR_SOA_ADD:
		return ixfr_solve_soa_add(rr, change, data->mm);
	case IXFR_ADD:
		return ixfr_solve_add(rr, change, data->mm);
	case IXFR_DONE:
		return KNOT_EOK;
	default:
		return KNOT_ERROR;
	}
}

/*!
 * \brief Processes IXFR reply packet and fills in the changesets structure.
 *
 * \param pkt    Packet containing the IXFR reply in wire format.
 * \param adata  Answer data, including processing context.
 *
 * \return KNOT_STATE_CONSUME, KNOT_STATE_DONE, KNOT_STATE_FAIL
 */
static int ixfr_consume_packet(knot_pkt_t *pkt, struct refresh_data *data)
{
	// Process RRs in the message.
	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	for (uint16_t i = 0; i < answer->count; ++i) {
		const knot_rrset_t *rr = knot_pkt_rr(answer, i);
		if (!knot_dname_in(data->zone, rr->owner)) {
			continue;
		}

		int ret = ixfr_step(rr, data);
		if (ret != KNOT_EOK) {
			IXFRIN_LOG(LOG_WARNING, data->zone, data->remote,
			           "failed (%s)", knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}

		if (data->ixfr.proc->state == IXFR_DONE) {
			return KNOT_STATE_DONE;
		}
	}

	return KNOT_STATE_CONSUME;
}

static bool ixfr_check_header(const knot_pktsection_t *answer)
{
	return answer->count >= 1 &&
	       knot_pkt_rr(answer, 0)->type == KNOT_RRTYPE_SOA;
}

static bool ixfr_is_axfr(const knot_pktsection_t *answer)
{
	return answer->count >= 2 &&
	       knot_pkt_rr(answer, 0)->type == KNOT_RRTYPE_SOA &&
	       knot_pkt_rr(answer, 1)->type != KNOT_RRTYPE_SOA;
}

static int ixfr_consume(knot_pkt_t *pkt, struct refresh_data *data)
{
	assert(pkt);
	assert(data);

	// Check RCODE
	uint8_t rcode = knot_wire_get_rcode(pkt->wire);
	if (rcode != KNOT_RCODE_NOERROR) {
		const knot_lookup_t *lut = knot_lookup_by_id(knot_rcode_names, rcode);
		if (lut != NULL) {
			IXFRIN_LOG(LOG_WARNING, data->zone, data->remote,
			           "server responded with %s", lut->name);
		}
		return KNOT_STATE_FAIL;
	}

	// Initialize with first packet
	if (data->ixfr.proc == NULL) {
		const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);

		if (!ixfr_check_header(answer)) {
			IXFRIN_LOG(LOG_WARNING, data->zone, data->remote, "malformed response");
			return KNOT_STATE_FAIL;
		}

		if (ixfr_is_axfr(answer)) {
			IXFRIN_LOG(LOG_NOTICE, data->zone, data->remote, "receiving AXFR-style IXFR");
			data->is_ixfr = false;
			return axfr_consume(pkt, data);
		}

		int ret = ixfr_init(data);
		if (ret != KNOT_EOK) {
			IXFRIN_LOG(LOG_WARNING, data->zone, data->remote,
			           "failed to initialize (%s)", knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}

		IXFRIN_LOG(LOG_INFO, data->zone, data->remote, "starting");
		xfr_stats_begin(&data->stats);
	}

	// Process answer packet
	xfr_stats_add(&data->stats, pkt->size);
	int next = ixfr_consume_packet(pkt, data);

	// Finalize
	if (next == KNOT_STATE_DONE) {
		xfr_stats_end(&data->stats);
	}

	return next;
}

static int soa_query_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	query_init_pkt(pkt);

	int r = knot_pkt_put_question(pkt, data->zone, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
	if (r != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	r = query_put_edns(pkt, &data->edns);
	if (r != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_CONSUME;
}

static int soa_query_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	uint16_t rcode = knot_pkt_get_ext_rcode(pkt);
	if (rcode != KNOT_RCODE_NOERROR) {
		REFRESH_LOG(LOG_WARNING, data->zone, data->remote,
		            "server responded with %s", rcode_name(rcode));
		return KNOT_STATE_FAIL;
	}

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_rrset_t *rr = answer->count == 1 ? knot_pkt_rr(answer, 0) : NULL;
	if (!rr || rr->type != KNOT_RRTYPE_SOA || rr->rrs.rr_count != 1) {
		REFRESH_LOG(LOG_WARNING, data->zone, data->remote, "malformed message");
		return KNOT_STATE_FAIL;
	}

	uint32_t local_serial = knot_soa_serial(&data->soa->rrs);
	uint32_t remote_serial = knot_soa_serial(&rr->rrs);
	bool current = serial_is_current(local_serial, remote_serial);

	REFRESH_LOG(LOG_INFO, data->zone, data->remote, "remote serial %u, %s",
	            remote_serial,
	            current ? "zone is up-to-date" : "zone is outdated");

	if (current) {
		return KNOT_STATE_DONE;
	} else {
		data->state = STATE_TRANSFER;
		return KNOT_STATE_RESET;
	}
}

static int transfer_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	bool ixfr = data->is_ixfr;

	query_init_pkt(pkt);
	knot_pkt_put_question(pkt, data->zone, KNOT_CLASS_IN,
			      ixfr ? KNOT_RRTYPE_IXFR : KNOT_RRTYPE_AXFR);

	if (ixfr) {
		assert(data->soa);
		knot_pkt_begin(pkt, KNOT_AUTHORITY);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, data->soa, 0);
	}

	query_put_edns(pkt, &data->edns);

	return KNOT_STATE_CONSUME;
}

static int transfer_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	int next = data->is_ixfr ? ixfr_consume(pkt, data) : axfr_consume(pkt, data);

	// IXFR to AXFR failover
	if (data->is_ixfr && next == KNOT_STATE_FAIL) {
		ixfr_cleanup(data);
		data->is_ixfr = false;
		return KNOT_STATE_RESET;
	}

	// Log result, no failover after the transfer is complete
	if (next == KNOT_STATE_DONE) {
		xfr_log_finished(data->zone,
		                 data->is_ixfr ? LOG_OPERATION_IXFR : LOG_OPERATION_AXFR,
		                 LOG_DIRECTION_IN, data->remote, &data->stats);
	}

	// Cleanup processing context
	if (next == KNOT_STATE_DONE || next == KNOT_STATE_FAIL) {
		ixfr_cleanup(data);
	}

	return next;
}

static int refresh_begin(knot_layer_t *layer, void *_data)
{
	layer->data = _data;
	struct refresh_data *data = _data;

	if (data->soa) {
		data->state = STATE_SOA_QUERY;
		data->is_ixfr = true;
	} else {
		data->state = STATE_TRANSFER;
		data->is_ixfr = false;
	}

	return KNOT_STATE_PRODUCE;
}

static int refresh_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	switch (data->state) {
	case STATE_SOA_QUERY: return soa_query_produce(layer, pkt);
	case STATE_TRANSFER:  return transfer_produce(layer, pkt);
	default:
		return KNOT_STATE_FAIL;
	}
}

static int refresh_consume(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	switch (data->state) {
	case STATE_SOA_QUERY: return soa_query_consume(layer, pkt);
	case STATE_TRANSFER:  return transfer_consume(layer, pkt);
	default:
		return KNOT_STATE_FAIL;
	}
}

static int refresh_reset(knot_layer_t *layer)
{
	return KNOT_STATE_PRODUCE;
}

static const knot_layer_api_t REFRESH_API = {
	.begin = refresh_begin,
	.produce = refresh_produce,
	.consume = refresh_consume,
	.reset = refresh_reset,
};

static int publish_zone(conf_t *conf, zone_t *zone, const struct sockaddr *remote,
                        struct transfer_result *result)
{
	int ret = KNOT_ERROR;
	bool axfr = result->zone != NULL;
	apply_ctx_t apply_ctx = { 0 };

	// Construct new zone

	zone_contents_t *new_zone = NULL;

	if (axfr) {
		new_zone = result->zone;
	} else {
		apply_init_ctx(&apply_ctx, NULL, 0);
		ret = apply_changesets(&apply_ctx, zone->contents,
		                       &result->changesets, &new_zone);
		if (ret != KNOT_EOK) {
			goto fail;
		}
	}

	assert(new_zone != NULL);

	// Run semantic checks

	err_handler_logger_t handler;
	handler._cb.cb = err_handler_logger;
	ret = zone_do_sem_checks(new_zone, false, &handler._cb);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	// Write journal for IXFR

	if (!axfr) {
		ret = zone_changes_store(conf, zone, &result->changesets);
		if (ret != KNOT_EOK) {
			goto fail;
		}
	}

	// Publish new zone

	zone_contents_t *old_zone = zone_switch_contents(zone, new_zone);

	if (old_zone) {
		REFRESH_LOG(LOG_INFO, zone->name, remote,
		            "zone updated, serial %u -> %u",
		            zone_contents_serial(old_zone),
		            zone_contents_serial(new_zone));
	} else {
		REFRESH_LOG(LOG_INFO, zone->name, remote,
		            "zone updated, serial none -> %u",
		            zone_contents_serial(new_zone));
	}

	// Clean up old resources

	assert(ret == KNOT_EOK);
	synchronize_rcu();

fail:
	if (axfr) {
		if (ret == KNOT_EOK) {
			zone_contents_deep_free(&old_zone);
			result->zone = NULL; // seized
		}
	} else {
		if (ret == KNOT_EOK) {
			update_free_zone(&old_zone);
			update_cleanup(&apply_ctx);
		} else {
			update_rollback(&apply_ctx);
			update_free_zone(&new_zone);
		}
	}

	return ret;
}

#include "knot/query/requestor.h"

static int try_refresh(conf_t *conf, zone_t *zone, const conf_remote_t *master, void *ctx)
{
	// XXX: COPY PASTED

	assert(zone);
	assert(master);

	knot_rrset_t soa = { 0 };
	if (zone->contents) {
		soa = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	}

	struct refresh_data data = {
		.remote = (struct sockaddr *)&master->addr,
		.zone = zone->name,
		.soa = zone->contents ? &soa : NULL,
	};

	transfer_result_init(&data.result);
	query_edns_data_init(&data.edns, conf, zone->name, master->addr.ss_family);

	// TODO: temporary until we can get event specific flags
	if (zone->flags & ZONE_FORCE_AXFR) {
		zone->flags &= ~ZONE_FORCE_AXFR;
		data.soa = NULL;
	}

	struct knot_requestor requestor;
	knot_requestor_init(&requestor, &REFRESH_API, &data, NULL);

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	const struct sockaddr *dst = (struct sockaddr *)&master->addr;
	const struct sockaddr *src = (struct sockaddr *)&master->via;
	struct knot_request *req = knot_request_make(NULL, dst, src, pkt, &master->key, 0);
	if (!req) {
		knot_request_free(req, NULL);
		knot_requestor_clear(&requestor);
		return KNOT_ENOMEM;
	}

	int timeout = conf->cache.srv_tcp_reply_timeout * 1000;

	int ret = knot_requestor_exec(&requestor, req, timeout);
	knot_request_free(req, NULL);
	knot_requestor_clear(&requestor);

	bool updated = transfer_result_has_data(&data.result);
	if (ret == KNOT_EOK && updated) {
		ret = publish_zone(conf, zone, data.remote, &data.result);
	}

	transfer_result_cleanup(&data.result);

	if (ret == KNOT_EOK && ctx) {
		*(bool *)ctx = updated;
	}

	return ret;
}

int event_refresh(conf_t *conf, zone_t *zone)
{
	assert(zone);

	// slave zones only
	if (!zone_is_slave(conf, zone)) {
		assert(0 && "unreachable");
		return KNOT_EOK;
	}

	bool updated = false;

	int ret = zone_master_try(conf, zone, try_refresh, &updated, "refresh");
	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "refresh, failed (%s)", knot_strerror(ret));
	}

	time_t now = time(NULL);
	const knot_rdataset_t *soa = zone_soa(zone);

	if (ret == KNOT_EOK) {
		zone->timers.soa_expire = knot_soa_expire(soa);
		zone->timers.last_refresh = now;
		zone->timers.next_refresh = now + knot_soa_refresh(soa);
	} else {
		time_t next = 0;
		if (soa) {
			next = knot_soa_retry(soa);
		} else {
			next = bootstrap_next(&zone->timers);
		}
		zone->timers.next_refresh = now + next;
	}

	/* Rechedule events. */
	zone_events_replan_after_timers(conf, zone);
	zone_events_schedule_at(zone, ZONE_EVENT_NOTIFY, now);

	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);
	if (sync_timeout == 0 && updated) {
		zone_events_schedule_at(zone, ZONE_EVENT_FLUSH, now);
	}

	// MEMORY TRIM?
	/* Trim extra heap. */
	//if (!is_bootstrap) {
	//	mem_trim();
	//}

	return KNOT_EOK;
}
