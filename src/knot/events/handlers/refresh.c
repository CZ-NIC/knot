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

#include "contrib/mempattern.h"
#include "contrib/trim.h"
#include "dnssec/random.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/events/replan.h"
#include "knot/nameserver/ixfr.h"
#include "knot/query/layer.h"
#include "knot/query/query.h"
#include "knot/query/requestor.h"
#include "knot/updates/apply.h"
#include "knot/zone/serial.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "libknot/errcode.h"

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

enum xfr_type {
	XFR_TYPE_ERROR = -1,
	XFR_TYPE_UNDETERMINED = 0,
	XFR_TYPE_UPTODATE,
	XFR_TYPE_AXFR,
	XFR_TYPE_IXFR,
};

struct refresh_data {
	// transfer configuration, initialize appropriately:

	zone_t *zone;                     //!< Zone to eventually updated.
	conf_t *conf;                     //!< Server configuration.
	const struct sockaddr *remote;    //!< Remote endpoint.
	const knot_rrset_t *soa;          //!< Local SOA (NULL for AXFR).
	const size_t max_zone_size;       //!< Maximal zone size.
	struct query_edns_data edns;      //!< EDNS data to be used in queries.

	// internal state, initialize with zeroes:

	enum state state;                 //!< Event processing state.
	enum xfr_type xfr_type;           //!< Transer type (mostly IXFR versus AXFR).
	knot_rrset_t *initial_soa_copy;   //!< Copy of the received initial SOA.
	struct xfr_stats stats;           //!< Transfer statistics.
	size_t change_size;               //!< Size of added and removed RRs.

	struct {
		zone_contents_t *zone;    //!< AXFR result, new zone.
	} axfr;

	struct {
		struct ixfr_proc *proc;   //!< IXFR processing context.
		knot_rrset_t *final_soa;  //!< SOA denoting end of transfer.
		list_t changesets;        //!< IXFR result, zone updates.
	} ixfr;

	bool updated;  // TODO: Can we fid a better way to check if zone was updated?
	knot_mm_t *mm; // TODO: This used to be used in IXFR. Remove or reuse.
};

static bool serial_is_current(uint32_t local_serial, uint32_t remote_serial)
{
	return (serial_compare(local_serial, remote_serial) & SERIAL_MASK_GEQ);
}

static time_t bootstrap_next(const zone_timers_t *timers)
{
	time_t expired_at = timers->last_refresh + timers->soa_expire;

	// previous interval
	time_t interval = timers->next_refresh - expired_at;
	if (interval < 0) {
		interval = 0;
	}

	// exponential backoff
	interval *= 2;
	if (interval > BOOTSTRAP_MAXTIME) {
		interval = BOOTSTRAP_MAXTIME;
	}

	// prevent burst refresh
	interval += dnssec_random_uint16_t() % BOOTSTRAP_JITTER;

	return interval;
}

static int xfr_validate(zone_contents_t *zone, struct refresh_data *data)
{
	err_handler_logger_t handler;
	handler._cb.cb = err_handler_logger;
	int ret = zone_do_sem_checks(zone, false, &handler._cb);
	if (ret != KNOT_EOK) {
		// error is logged by the error handler
		return ret;
	}

	if (zone->size > data->max_zone_size) {
		ns_log(LOG_WARNING, data->zone->name,
		       data->xfr_type == XFR_TYPE_IXFR ? LOG_OPERATION_IXFR : LOG_OPERATION_AXFR,
		       LOG_DIRECTION_IN, data->remote, "zone size exceeded");
		return KNOT_EZONESIZE;
	}

	return KNOT_EOK;
}

static void xfr_log_publish(const knot_dname_t *zone_name,
                            const struct sockaddr *remote,
                            const zone_contents_t *old_zone,
                            const zone_contents_t *new_zone)
{
	if (old_zone) {
		REFRESH_LOG(LOG_INFO, zone_name, remote,
		            "zone updated, serial %u -> %u",
		            zone_contents_serial(old_zone),
		            zone_contents_serial(new_zone));
	} else {
		REFRESH_LOG(LOG_INFO, zone_name, remote,
		            "zone updated, serial none -> %u",
		            zone_contents_serial(new_zone));
	}
}

static int axfr_init(struct refresh_data *data)
{
	zone_contents_t *new_zone = zone_contents_new(data->zone->name);
	if (new_zone == NULL) {
		return KNOT_ENOMEM;
	}

	data->axfr.zone = new_zone;
	return KNOT_EOK;
}

static void axfr_cleanup(struct refresh_data *data)
{
	zone_contents_deep_free(&data->axfr.zone);
}

/*! \brief Routine for calling call_rcu() easier way.
 *
 * TODO: move elsewhere, as it has no direct relation to AXFR
 */
typedef struct {
	struct rcu_head rcuhead;
	void (*ptr_free_fun)(void **);
	void *ptr;
} callrcu_wrapper_t;

static void callrcu_wrapper_cb(struct rcu_head *param)
{
	callrcu_wrapper_t *wrap = (callrcu_wrapper_t *)param;
	wrap->ptr_free_fun(&wrap->ptr);
	free(wrap);
}

/* note: does nothing if not-enough-memory */
static void callrcu_wrapper(void *ptr, void (*ptr_free_fun)(void **))
{
	callrcu_wrapper_t *wrap = calloc(1, sizeof(callrcu_wrapper_t));
	if (wrap != NULL) {
		wrap->ptr = ptr;
		wrap->ptr_free_fun = ptr_free_fun;
		call_rcu((struct rcu_head *)wrap, callrcu_wrapper_cb);
	}
}

static int axfr_finalize(struct refresh_data *data)
{
	zone_contents_t *new_zone = data->axfr.zone;

	int ret = zone_contents_adjust_full(new_zone);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = xfr_validate(new_zone, data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	conf_val_t val = conf_zone_get(data->conf, C_ZONE_IN_JOURNAL, data->zone->name);
	if (conf_bool(&val)) {
		ret = zone_in_journal_store(data->conf, data->zone, new_zone);
		if (ret != KNOT_EOK && ret != KNOT_ENOTSUP) {
			IXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
			           "failed to write zone contents to journal (%s)",
			           knot_strerror(ret));
		}
	}

	zone_contents_t *old_zone = zone_switch_contents(data->zone, new_zone);
	xfr_log_publish(data->zone->name, data->remote, old_zone, new_zone);
	data->axfr.zone = NULL; // seized
	callrcu_wrapper(old_zone, (void (*)(void **))zone_contents_deep_free);

	return KNOT_EOK;
}

static int axfr_consume_rr(const knot_rrset_t *rr, struct refresh_data *data)
{
	assert(rr);
	assert(data);
	assert(data->axfr.zone);

	// zc is stateless structure which can be initialized for each rr
	// the changes are stored only in data->axfr.zone (aka zc.z)
	zcreator_t zc = {
		.z = data->axfr.zone,
		.master = false,
		.ret = KNOT_EOK
	};

	if (rr->type == KNOT_RRTYPE_SOA &&
	    node_rrtype_exists(zc.z->apex, KNOT_RRTYPE_SOA)) {
		return KNOT_STATE_DONE;
	}

	int ret = zcreator_step(&zc, rr);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}

	data->change_size += knot_rrset_size(rr);
	if (data->change_size > data->max_zone_size) {
		AXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
		           "zone size exceeded");
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_CONSUME;
}

static int axfr_consume_packet(knot_pkt_t *pkt, struct refresh_data *data)
{
	assert(pkt);
	assert(data);

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	int ret = KNOT_STATE_CONSUME;
	for (uint16_t i = 0; i < answer->count && ret == KNOT_STATE_CONSUME; ++i) {
		ret = axfr_consume_rr(knot_pkt_rr(answer, i), data);
	}
	return ret;
}

static int axfr_consume(knot_pkt_t *pkt, struct refresh_data *data)
{
	assert(pkt);
	assert(data);

	// Check RCODE
	if (knot_pkt_ext_rcode(pkt) != KNOT_RCODE_NOERROR) {
		AXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
		           "server responded with error '%s'",
		           knot_pkt_ext_rcode_name(pkt));
		return KNOT_STATE_FAIL;
	}

	// Initialize with first packet
	if (data->axfr.zone == NULL) {
		int ret = axfr_init(data);
		if (ret != KNOT_EOK) {
			AXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
			           "failed to initialize (%s)",
			           knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}

		AXFRIN_LOG(LOG_INFO, data->zone->name, data->remote, "starting");
		xfr_stats_begin(&data->stats);
		data->change_size = 0;
	}

	int next;
	// Process saved SOA if fallback from IXFR
	if (data->initial_soa_copy != NULL) {
		next = axfr_consume_rr(data->initial_soa_copy, data);
		knot_rrset_free(&data->initial_soa_copy, data->mm);
		if (next != KNOT_STATE_CONSUME) {
			return next;
		}
	}

	// Process answer packet
	xfr_stats_add(&data->stats, pkt->size);
	next = axfr_consume_packet(pkt, data);

	// Finalize
	if (next == KNOT_STATE_DONE) {
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

	init_list(&data->ixfr.changesets);

	return KNOT_EOK;
}

/*! \brief Clean up data allocated by IXFR-in processing. */
static void ixfr_cleanup(struct refresh_data *data)
{
	if (data->ixfr.proc == NULL) {
		return;
	}

	knot_rrset_free(&data->ixfr.final_soa, data->mm);
	mm_free(data->mm, data->ixfr.proc);
	data->ixfr.proc = NULL;

	changesets_free(&data->ixfr.changesets);
}

static void ixfr_finalize_cleanup(void **ptr)
{
	apply_ctx_t *ctx = *ptr;
	update_free_zone(&ctx->contents);
	update_cleanup(ctx);
	free(ctx);
}

static int ixfr_finalize(struct refresh_data *data)
{
	zone_contents_t *new_zone = NULL;
	apply_ctx_t *ctx = calloc(1, sizeof(apply_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	apply_init_ctx(ctx, NULL, APPLY_STRICT);
	int ret = apply_changesets(ctx, data->zone->contents,
	                           &data->ixfr.changesets, &new_zone);
	if (ret != KNOT_EOK) {
		IXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
		           "failed to apply changes to zone (%s)",
		           knot_strerror(ret));
		free(ctx);
		return ret;
	}

	assert(new_zone != NULL);

	ret = xfr_validate(new_zone, data);
	if (ret != KNOT_EOK) {
		update_rollback(ctx);
		update_free_zone(&new_zone);
		free(ctx);
		return ret;
	}

	// TODO: Refactor zone_changes_store() not to take monster object with config.
	ret = zone_changes_store(data->conf, data->zone, &data->ixfr.changesets);
	if (ret != KNOT_EOK) {
		IXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
		           "failed to write changes to journal (%s)",
		           knot_strerror(ret));
		update_rollback(ctx);
		update_free_zone(&new_zone);
		free(ctx);
		return ret;
	}

	zone_contents_t *old_zone = zone_switch_contents(data->zone, new_zone);
	xfr_log_publish(data->zone->name, data->remote, old_zone, new_zone);

	ctx->contents = old_zone;
	callrcu_wrapper(ctx, ixfr_finalize_cleanup);

	return KNOT_EOK;
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
	init_list(&data->ixfr.changesets);

	return KNOT_EOK;
}

/*! \brief Decides what to do with a starting SOA (deletions). */
static int ixfr_solve_soa_del(const knot_rrset_t *rr, struct refresh_data *data)
{
	if (rr->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	// Create new changeset.
	changeset_t *change = changeset_new(data->zone->name);
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
	add_tail(&data->ixfr.changesets, &change->n);

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
	changeset_t *change = TAIL(data->ixfr.changesets);

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

static int ixfr_consume_rr(const knot_rrset_t *rr, struct refresh_data *data)
{
	if (!knot_dname_in(data->zone->name, rr->owner)) {
		return KNOT_STATE_CONSUME;
	}

	int ret = ixfr_step(rr, data);
	if (ret != KNOT_EOK) {
		IXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
		           "failed (%s)", knot_strerror(ret));
		return KNOT_STATE_FAIL;
	}

	data->change_size += knot_rrset_size(rr);
	if (data->change_size / 2 > data->max_zone_size) {
		IXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
		           "transfer size exceeded");
		return KNOT_STATE_FAIL;
	}

	if (data->ixfr.proc->state == IXFR_DONE) {
		return KNOT_STATE_DONE;
	}

	return KNOT_STATE_CONSUME;
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
	int ret = KNOT_STATE_CONSUME;
	for (uint16_t i = 0; i < answer->count && ret == KNOT_STATE_CONSUME; ++i) {
		ret = ixfr_consume_rr(knot_pkt_rr(answer, i), data);
	}
	return ret;
}

static enum xfr_type determine_xfr_type(const knot_pktsection_t *answer,
                                        uint32_t zone_serial, const knot_rrset_t *initial_soa)
{
	if (answer->count < 1) {
		return XFR_TYPE_ERROR;
	}

	const knot_rrset_t *rr_one = knot_pkt_rr(answer, 0);
	if (initial_soa != NULL) {
		if (rr_one->type == KNOT_RRTYPE_SOA) {
		        return knot_rrset_equal(initial_soa, rr_one, KNOT_RRSET_COMPARE_WHOLE) ?
		               XFR_TYPE_AXFR : XFR_TYPE_IXFR;
		}
		return XFR_TYPE_AXFR;
	}

	if (answer->count == 1) {
		if (rr_one->type == KNOT_RRTYPE_SOA) {
			return serial_is_current(zone_serial, knot_soa_serial(&rr_one->rrs)) ?
			       XFR_TYPE_UPTODATE : XFR_TYPE_UNDETERMINED;
		}
		return XFR_TYPE_ERROR;
	}

	const knot_rrset_t *rr_two = knot_pkt_rr(answer, 1);
	if (answer->count == 2 && rr_one->type == KNOT_RRTYPE_SOA &&
	    knot_rrset_equal(rr_one, rr_two, KNOT_RRSET_COMPARE_WHOLE)) {
		return XFR_TYPE_AXFR;
	}

	return (rr_one->type == KNOT_RRTYPE_SOA && rr_two->type != KNOT_RRTYPE_SOA) ?
	       XFR_TYPE_AXFR : XFR_TYPE_IXFR;
}

static int ixfr_consume(knot_pkt_t *pkt, struct refresh_data *data)
{
	assert(pkt);
	assert(data);

	// Check RCODE
	if (knot_pkt_ext_rcode(pkt) != KNOT_RCODE_NOERROR) {
		IXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
		           "server responded with error '%s'",
		           knot_pkt_ext_rcode_name(pkt));
		return KNOT_STATE_FAIL;
	}

	// Initialize with first packet
	if (data->ixfr.proc == NULL) {
		const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);

		data->xfr_type = determine_xfr_type(answer, knot_soa_serial(&data->soa->rrs),
		                                    data->initial_soa_copy);
		switch (data->xfr_type) {
		case XFR_TYPE_ERROR:
			IXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
			           "malformed response SOA");
			return KNOT_STATE_FAIL;
		case XFR_TYPE_UNDETERMINED:
			// Store the SOA and check with next packet
			data->initial_soa_copy = knot_rrset_copy(knot_pkt_rr(answer, 0), data->mm);
			if (data->initial_soa_copy == NULL) {
				return KNOT_STATE_FAIL;
			}
			xfr_stats_add(&data->stats, pkt->size);
			return KNOT_STATE_CONSUME;
		case XFR_TYPE_AXFR:
			IXFRIN_LOG(LOG_INFO, data->zone->name, data->remote,
			           "receiving AXFR-style IXFR");
			return axfr_consume(pkt, data);
		case XFR_TYPE_UPTODATE:
			IXFRIN_LOG(LOG_INFO, data->zone->name, data->remote,
			          "zone is up-to-date");
			xfr_stats_begin(&data->stats);
			xfr_stats_add(&data->stats, pkt->size);
			xfr_stats_end(&data->stats);
			return KNOT_STATE_DONE;
		case XFR_TYPE_IXFR:
			break;
		default:
			assert(0);
			return KNOT_STATE_FAIL;
		}

		int ret = ixfr_init(data);
		if (ret != KNOT_EOK) {
			IXFRIN_LOG(LOG_WARNING, data->zone->name, data->remote,
			           "failed to initialize (%s)", knot_strerror(ret));
			return KNOT_STATE_FAIL;
		}

		IXFRIN_LOG(LOG_INFO, data->zone->name, data->remote, "starting");
		xfr_stats_begin(&data->stats);
		data->change_size = 0;
	}

	int next;
	// Process saved SOA if existing
	if (data->initial_soa_copy != NULL) {
		next = ixfr_consume_rr(data->initial_soa_copy, data);
		knot_rrset_free(&data->initial_soa_copy, data->mm);
		if (next != KNOT_STATE_CONSUME) {
			return next;
		}
	}

	// Process answer packet
	xfr_stats_add(&data->stats, pkt->size);
	next = ixfr_consume_packet(pkt, data);

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

	int r = knot_pkt_put_question(pkt, data->zone->name, KNOT_CLASS_IN, KNOT_RRTYPE_SOA);
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

	if (knot_pkt_ext_rcode(pkt) != KNOT_RCODE_NOERROR) {
		REFRESH_LOG(LOG_WARNING, data->zone->name, data->remote,
		            "server responded with error '%s'",
		            knot_pkt_ext_rcode_name(pkt));
		return KNOT_STATE_FAIL;
	}

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_rrset_t *rr = answer->count == 1 ? knot_pkt_rr(answer, 0) : NULL;
	if (!rr || rr->type != KNOT_RRTYPE_SOA || rr->rrs.rr_count != 1) {
		REFRESH_LOG(LOG_WARNING, data->zone->name, data->remote,
		            "malformed message");
		return KNOT_STATE_FAIL;
	}

	uint32_t local_serial = knot_soa_serial(&data->soa->rrs);
	uint32_t remote_serial = knot_soa_serial(&rr->rrs);
	bool current = serial_is_current(local_serial, remote_serial);
	bool master_uptodate = serial_is_current(remote_serial, local_serial);

	REFRESH_LOG(LOG_INFO, data->zone->name, data->remote,
	            "remote serial %u, %s", remote_serial,
	            current ? (master_uptodate ? "zone is up-to-date" :
	            "master is outdated") : "zone is outdated");

	if (current) {
		return master_uptodate ? KNOT_STATE_DONE : KNOT_STATE_FAIL;
	} else {
		data->state = STATE_TRANSFER;
		return KNOT_STATE_RESET;
	}
}

static int transfer_produce(knot_layer_t *layer, knot_pkt_t *pkt)
{
	struct refresh_data *data = layer->data;

	bool ixfr = (data->xfr_type == XFR_TYPE_IXFR);

	query_init_pkt(pkt);
	knot_pkt_put_question(pkt, data->zone->name, KNOT_CLASS_IN,
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

	int next = (data->xfr_type == XFR_TYPE_AXFR) ? axfr_consume(pkt, data) :
	                                               ixfr_consume(pkt, data);

	// Transfer completed
	if (next == KNOT_STATE_DONE) {
		// Log transfer even if we still can fail
		xfr_log_finished(data->zone->name,
		                 data->xfr_type == XFR_TYPE_IXFR ||
		                 data->xfr_type == XFR_TYPE_UPTODATE ?
		                 LOG_OPERATION_IXFR : LOG_OPERATION_AXFR,
		                 LOG_DIRECTION_IN, data->remote, &data->stats);

		/*
		 * TODO: Move finialization into finish
		 * callback. And update requestor to allow reset from fallback
		 * as we need IXFR to AXFR failover.
		 */
		if (tsig_unsigned_count(layer->tsig) != 0) {
			return KNOT_STATE_FAIL;
		}

		// Finalize and publish the zone
		int ret;
		switch (data->xfr_type) {
		case XFR_TYPE_IXFR:
			ret = ixfr_finalize(data);
			break;
		case XFR_TYPE_AXFR:
			ret = axfr_finalize(data);
			break;
		default:
			return next;
		}
		if (ret == KNOT_EOK) {
			data->updated = true;
		} else {
			next = KNOT_STATE_FAIL;
		}
	}

	// IXFR to AXFR failover
	if (data->xfr_type == XFR_TYPE_IXFR && next == KNOT_STATE_FAIL) {
		REFRESH_LOG(LOG_WARNING, data->zone->name, data->remote,
		            "fallback to AXFR");
		ixfr_cleanup(data);
		layer->flags |= KNOT_RQ_LAYER_CLOSE;
		data->xfr_type = XFR_TYPE_AXFR;
		return KNOT_STATE_RESET;
	}

	return next;
}

static int refresh_begin(knot_layer_t *layer, void *_data)
{
	layer->data = _data;
	struct refresh_data *data = _data;

	if (data->soa) {
		data->state = STATE_SOA_QUERY;
		data->xfr_type = XFR_TYPE_IXFR;
		data->initial_soa_copy = NULL;
	} else {
		data->state = STATE_TRANSFER;
		data->xfr_type = XFR_TYPE_AXFR;
		data->initial_soa_copy = NULL;
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

static int refresh_finish(knot_layer_t *layer)
{
	struct refresh_data *data = layer->data;

	// clean processing context
	axfr_cleanup(data);
	ixfr_cleanup(data);

	return KNOT_STATE_NOOP;
}

static const knot_layer_api_t REFRESH_API = {
	.begin = refresh_begin,
	.produce = refresh_produce,
	.consume = refresh_consume,
	.reset = refresh_reset,
	.finish = refresh_finish,
};

static size_t max_zone_size(conf_t *conf, const knot_dname_t *zone)
{
	conf_val_t val = conf_zone_get(conf, C_MAX_ZONE_SIZE, zone);
	return conf_int(&val);
}

static int try_refresh(conf_t *conf, zone_t *zone, const conf_remote_t *master, void *ctx)
{
	// TODO: Abstract interface to issue DNS queries. This is almost copy-pasted.

	assert(zone);
	assert(master);

	knot_rrset_t soa = { 0 };
	if (zone->contents) {
		soa = node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	}

	struct refresh_data data = {
		.zone = zone,
		.conf = conf,
		.remote = (struct sockaddr *)&master->addr,
		.soa = zone->contents ? &soa : NULL,
		.max_zone_size = max_zone_size(conf, zone->name),
	};

	query_edns_data_init(&data.edns, conf, zone->name, master->addr.ss_family);

	// TODO: Flag on zone is ugly. Event specific parameters would be nice.
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

	if (ret == KNOT_EOK && ctx) {
		*(bool *)ctx = data.updated;
	}

	return ret;
}

static int64_t min_refresh_interval(conf_t *conf, const knot_dname_t *zone)
{
	conf_val_t val = conf_zone_get(conf, C_MIN_REFRESH_INTERVAL, zone);
	return conf_int(&val);
}

static int64_t max_refresh_interval(conf_t *conf, const knot_dname_t *zone)
{
	conf_val_t val = conf_zone_get(conf, C_MAX_REFRESH_INTERVAL, zone);
	return conf_int(&val);
}

int event_refresh(conf_t *conf, zone_t *zone)
{
	assert(zone);

	if (!zone_is_slave(conf, zone)) {
		return KNOT_EOK;
	}

	bool bootstrap = zone_contents_is_empty(zone->contents);
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

	/* Check for allowed refresh interval limits. */
	int64_t min_refresh = min_refresh_interval(conf, zone->name);
	if(zone->timers.next_refresh < now + min_refresh) {
		zone->timers.next_refresh = now + min_refresh;
	}
	int64_t max_refresh = max_refresh_interval(conf, zone->name);
	if(zone->timers.next_refresh > now + max_refresh) {
		zone->timers.next_refresh = now + max_refresh;
	}

	/* Rechedule events. */
	replan_from_timers(conf, zone);
	if (updated) {
		zone_events_schedule_at(zone, ZONE_EVENT_NOTIFY, time(NULL) + 1);

		conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
		int64_t sync_timeout = conf_int(&val);
		if (sync_timeout == 0) {
			zone_events_schedule_now(zone, ZONE_EVENT_FLUSH);
		}
	}

	if (!bootstrap) {
		mem_trim();
	}

	return KNOT_EOK;
}
