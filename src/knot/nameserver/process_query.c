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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <urcu.h>

#include "libdnssec/tsig.h"
#include "knot/common/log.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/query_module.h"
#include "knot/nameserver/chaos.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/axfr.h"
#include "knot/nameserver/ixfr.h"
#include "knot/nameserver/update.h"
#include "knot/nameserver/nsec_proofs.h"
#include "knot/nameserver/notify.h"
#include "knot/server/server.h"
#include "libknot/libknot.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"

/*! \brief Accessor to query-specific data. */
#define QUERY_DATA(ctx) ((knotd_qdata_t *)(ctx)->data)

static knotd_query_type_t query_type(const knot_pkt_t *pkt)
{
	switch (knot_wire_get_opcode(pkt->wire)) {
	case KNOT_OPCODE_QUERY:
		switch (knot_pkt_qtype(pkt)) {
		case 0 /* RESERVED */: return KNOTD_QUERY_TYPE_INVALID;
		case KNOT_RRTYPE_AXFR: return KNOTD_QUERY_TYPE_AXFR;
		case KNOT_RRTYPE_IXFR: return KNOTD_QUERY_TYPE_IXFR;
		default:               return KNOTD_QUERY_TYPE_NORMAL;
		}
	case KNOT_OPCODE_NOTIFY: return KNOTD_QUERY_TYPE_NOTIFY;
	case KNOT_OPCODE_UPDATE: return KNOTD_QUERY_TYPE_UPDATE;
	default:                 return KNOTD_QUERY_TYPE_INVALID;
	}
}

/*! \brief Reinitialize query data structure. */
static void query_data_init(knot_layer_t *ctx, knotd_qdata_params_t *params,
                            knotd_qdata_extra_t *extra)
{
	/* Initialize persistent data. */
	knotd_qdata_t *data = QUERY_DATA(ctx);
	memset(data, 0, sizeof(*data));
	data->mm = ctx->mm;
	data->params = params;
	data->extra = extra;

	/* Initialize lists. */
	memset(extra, 0, sizeof(*extra));
	init_list(&extra->wildcards);
	init_list(&extra->rrsigs);
}

static int process_query_begin(knot_layer_t *ctx, void *params)
{
	/* Initialize context. */
	assert(ctx);
	ctx->data = mm_alloc(ctx->mm, sizeof(knotd_qdata_t));
	knotd_qdata_extra_t *extra = mm_alloc(ctx->mm, sizeof(*extra));

	/* Initialize persistent data. */
	query_data_init(ctx, params, extra);

	/* Await packet. */
	return KNOT_STATE_CONSUME;
}

static int process_query_reset(knot_layer_t *ctx)
{
	assert(ctx);
	knotd_qdata_t *qdata = QUERY_DATA(ctx);

	/* Remember persistent parameters. */
	knotd_qdata_params_t *params = qdata->params;
	knotd_qdata_extra_t *extra = qdata->extra;

	/* Free allocated data. */
	knot_rrset_clear(&qdata->opt_rr, qdata->mm);
	ptrlist_free(&extra->wildcards, qdata->mm);
	nsec_clear_rrsigs(qdata);
	if (extra->ext_cleanup != NULL) {
		extra->ext_cleanup(qdata);
	}

	/* Initialize persistent data. */
	query_data_init(ctx, params, extra);

	/* Await packet. */
	return KNOT_STATE_CONSUME;
}

static int process_query_finish(knot_layer_t *ctx)
{
	process_query_reset(ctx);
	mm_free(ctx->mm, ctx->data);
	ctx->data = NULL;

	return KNOT_STATE_NOOP;
}

static int process_query_in(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	knotd_qdata_t *qdata = QUERY_DATA(ctx);

	/* Check if at least header is parsed. */
	if (pkt->parsed < KNOT_WIRE_HEADER_SIZE) {
		return KNOT_STATE_NOOP; /* Ignore. */
	}

	/* Accept only queries. */
	if (knot_wire_get_qr(pkt->wire)) {
		return KNOT_STATE_NOOP; /* Ignore. */
	}

	/* Store for processing. */
	qdata->query = pkt;
	qdata->type = query_type(pkt);

	/* Declare having response. */
	return KNOT_STATE_PRODUCE;
}

/*!
 * \brief Create a response for a given query in the INTERNET class.
 */
static int query_internet(knot_pkt_t *pkt, knot_layer_t *ctx)
{
	knotd_qdata_t *data = QUERY_DATA(ctx);

	switch (data->type) {
	case KNOTD_QUERY_TYPE_NORMAL: return internet_process_query(pkt, data);
	case KNOTD_QUERY_TYPE_NOTIFY: return notify_process_query(pkt, data);
	case KNOTD_QUERY_TYPE_AXFR:   return axfr_process_query(pkt, data);
	case KNOTD_QUERY_TYPE_IXFR:   return ixfr_process_query(pkt, data);
	case KNOTD_QUERY_TYPE_UPDATE: return update_process_query(pkt, data);
	default:
		/* Nothing else is supported. */
		data->rcode = KNOT_RCODE_NOTIMPL;
		return KNOT_STATE_FAIL;
	}
}

/*!
 * \brief Create a response for a given query in the CHAOS class.
 */
static int query_chaos(knot_pkt_t *pkt, knot_layer_t *ctx)
{
	knotd_qdata_t *data = QUERY_DATA(ctx);

	/* Nothing except normal queries is supported. */
	if (data->type != KNOTD_QUERY_TYPE_NORMAL) {
		data->rcode = KNOT_RCODE_NOTIMPL;
		return KNOT_STATE_FAIL;
	}

	data->rcode = knot_chaos_answer(pkt);
	if (data->rcode != KNOT_RCODE_NOERROR) {
		return KNOT_STATE_FAIL;
	}

	return KNOT_STATE_DONE;
}

/*! \brief Find zone for given question. */
static const zone_t *answer_zone_find(const knot_pkt_t *query, knot_zonedb_t *zonedb)
{
	uint16_t qtype = knot_pkt_qtype(query);
	uint16_t qclass = knot_pkt_qclass(query);
	const knot_dname_t *qname = knot_pkt_qname(query);
	const zone_t *zone = NULL;

	// search for zone only for IN and ANY classes
	if (qclass != KNOT_CLASS_IN && qclass != KNOT_CLASS_ANY) {
		return NULL;
	}

	/* In case of DS query, we strip the leftmost label when searching for
	 * the zone (but use whole qname in search for the record), as the DS
	 * records are only present in a parent zone.
	 */
	if (qtype == KNOT_RRTYPE_DS) {
		const knot_dname_t *parent = knot_wire_next_label(qname, NULL);
		zone = knot_zonedb_find_suffix(zonedb, parent);
		/* If zone does not exist, search for its parent zone,
		   this will later result to NODATA answer. */
		/*! \note This is not 100% right, it may lead to DS name for example
		 *        when following a CNAME chain, that should also be answered
		 *        from the parent zone (if it exists).
		 */
	}

	if (zone == NULL) {
		if (query_type(query) == KNOTD_QUERY_TYPE_NORMAL) {
			zone = knot_zonedb_find_suffix(zonedb, qname);
		} else {
			// Direct match required.
			zone = knot_zonedb_find(zonedb, qname);
		}
	}

	return zone;
}

static int answer_edns_reserve(knot_pkt_t *resp, knotd_qdata_t *qdata)
{
	if (knot_rrset_empty(&qdata->opt_rr)) {
		return KNOT_EOK;
	}

	/* Reserve size in the response. */
	return knot_pkt_reserve(resp, knot_edns_wire_size(&qdata->opt_rr));
}

static int answer_edns_init(const knot_pkt_t *query, knot_pkt_t *resp,
                            knotd_qdata_t *qdata)
{
	if (!knot_pkt_has_edns(query)) {
		return KNOT_EOK;
	}

	/* Initialize OPT record. */
	int16_t max_payload;
	switch (qdata->params->remote->ss_family) {
	case AF_INET:
		max_payload = conf()->cache.srv_max_ipv4_udp_payload;
		break;
	case AF_INET6:
		max_payload = conf()->cache.srv_max_ipv6_udp_payload;
		break;
	default:
		return KNOT_ERROR;
	}
	int ret = knot_edns_init(&qdata->opt_rr, max_payload, 0,
	                         KNOT_EDNS_VERSION, qdata->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check supported version. */
	if (knot_edns_get_version(query->opt_rr) != KNOT_EDNS_VERSION) {
		qdata->rcode = KNOT_RCODE_BADVERS;
	}

	/* Set DO bit if set (DNSSEC requested). */
	if (knot_pkt_has_dnssec(query)) {
		knot_edns_set_do(&qdata->opt_rr);
	}

	/* Append NSID if requested and available. */
	if (knot_pkt_edns_option(query, KNOT_EDNS_OPTION_NSID) != NULL) {
		conf_val_t *nsid = &conf()->cache.srv_nsid;
		size_t nsid_len;
		const uint8_t *nsid_data = conf_bin(nsid, &nsid_len);

		if (nsid->code != KNOT_EOK) {
			ret = knot_edns_add_option(&qdata->opt_rr,
			                           KNOT_EDNS_OPTION_NSID,
			                           strlen(conf()->hostname),
			                           (uint8_t *)conf()->hostname,
			                           qdata->mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		} else if (nsid_len > 0) {
			ret = knot_edns_add_option(&qdata->opt_rr,
			                           KNOT_EDNS_OPTION_NSID,
			                           nsid_len, nsid_data,
			                           qdata->mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	/* Initialize EDNS Client Subnet if configured and present in query. */
	if (conf()->cache.use_ecs) {
		uint8_t *ecs_opt = knot_pkt_edns_option(query, KNOT_EDNS_OPTION_CLIENT_SUBNET);
		if (ecs_opt != NULL) {
			qdata->ecs = mm_alloc(qdata->mm, sizeof(knot_edns_client_subnet_t));
			if (qdata->ecs == NULL) {
				return KNOT_ENOMEM;
			}
			const uint8_t *ecs_data = knot_edns_opt_get_data(ecs_opt);
			uint16_t ecs_len = knot_edns_opt_get_length(ecs_opt);
			ret = knot_edns_client_subnet_parse(qdata->ecs, ecs_data, ecs_len);
			if (ret != KNOT_EOK) {
				qdata->rcode = KNOT_RCODE_FORMERR;
				return ret;
			}
			qdata->ecs->scope_len = 0;

			/* Reserve space for the option in the answer. */
			ret = knot_edns_reserve_option(&qdata->opt_rr, KNOT_EDNS_OPTION_CLIENT_SUBNET,
			                               ecs_len, NULL, qdata->mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	} else {
		qdata->ecs = NULL;
	}

	return answer_edns_reserve(resp, qdata);
}

static int answer_edns_put(knot_pkt_t *resp, knotd_qdata_t *qdata)
{
	if (knot_rrset_empty(&qdata->opt_rr)) {
		return KNOT_EOK;
	}

	/* Add ECS if present. */
	int ret = KNOT_EOK;
	if (qdata->ecs != NULL) {
		uint8_t *ecs_opt = knot_edns_get_option(&qdata->opt_rr, KNOT_EDNS_OPTION_CLIENT_SUBNET);
		if (ecs_opt != NULL) {
			uint8_t *ecs_data = knot_edns_opt_get_data(ecs_opt);
			uint16_t ecs_len = knot_edns_opt_get_length(ecs_opt);
			ret = knot_edns_client_subnet_write(ecs_data, ecs_len, qdata->ecs);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	/* Reclaim reserved size. */
	ret = knot_pkt_reclaim(resp, knot_edns_wire_size(&qdata->opt_rr));
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint8_t *wire_end = resp->wire + resp->size;

	/* Write to packet. */
	assert(resp->current == KNOT_ADDITIONAL);
	ret = knot_pkt_put(resp, KNOT_COMPR_HINT_NONE, &qdata->opt_rr, 0);
	if (ret == KNOT_EOK) {
		/* Save position of the OPT RR. */
		qdata->extra->opt_rr_pos = wire_end;
	}

	return ret;
}

/*! \brief Initialize response, sizes and find zone from which we're going to answer. */
static int prepare_answer(knot_pkt_t *query, knot_pkt_t *resp, knot_layer_t *ctx)
{
	knotd_qdata_t *qdata = QUERY_DATA(ctx);
	server_t *server = qdata->params->server;

	/* Initialize response. */
	int ret = knot_pkt_init_response(resp, query);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_wire_clear_cd(resp->wire);

	/* Setup EDNS. */
	ret = answer_edns_init(query, resp, qdata);
	if (ret != KNOT_EOK || qdata->rcode != 0) {
		return KNOT_ERROR;
	}

	/* Update maximal answer size. */
	bool has_limit = qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE;
	if (has_limit) {
		resp->max_size = KNOT_WIRE_MIN_PKTSIZE;
		if (knot_pkt_has_edns(query)) {
			uint16_t server;
			switch (qdata->params->remote->ss_family) {
			case AF_INET:
				server = conf()->cache.srv_max_ipv4_udp_payload;
				break;
			case AF_INET6:
				server = conf()->cache.srv_max_ipv6_udp_payload;
				break;
			default:
				return KNOT_ERROR;
			}
			uint16_t client = knot_edns_get_payload(query->opt_rr);
			uint16_t transfer = MIN(client, server);
			resp->max_size = MAX(resp->max_size, transfer);
		}
	} else {
		resp->max_size = KNOT_WIRE_MAX_PKTSIZE;
	}

	/* Query MUST carry a question. */
	const knot_dname_t *qname = knot_pkt_qname(query);
	if (qname == NULL) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	/* Convert query QNAME to lowercase, but keep original QNAME case.
	 * Already checked for absence of compression and length.
	 */
	memcpy(qdata->extra->orig_qname, qname, query->qname_size);
	process_query_qname_case_lower(query);

	/* Find zone for QNAME. */
	qdata->extra->zone = answer_zone_find(query, server->zone_db);

	return KNOT_EOK;
}

static void set_rcode_to_packet(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	uint8_t ext_rcode = KNOT_EDNS_RCODE_HI(qdata->rcode);

	if (ext_rcode != 0) {
		/* No OPT RR and Ext RCODE results in SERVFAIL. */
		if (qdata->extra->opt_rr_pos == NULL) {
			knot_wire_set_rcode(pkt->wire, KNOT_RCODE_SERVFAIL);
			return;
		}

		knot_edns_set_ext_rcode_wire(qdata->extra->opt_rr_pos, ext_rcode);
	}

	knot_wire_set_rcode(pkt->wire, KNOT_EDNS_RCODE_LO(qdata->rcode));
}

static int process_query_err(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(ctx && pkt);

	knotd_qdata_t *qdata = QUERY_DATA(ctx);

	/* Initialize response from query packet. */
	knot_pkt_t *query = qdata->query;
	(void)knot_pkt_init_response(pkt, query);
	knot_wire_clear_cd(pkt->wire);

	/* Set TC bit if required. */
	if (qdata->err_truncated) {
		knot_wire_set_tc(pkt->wire);
	}

	/* Restore original QNAME. */
	process_query_qname_case_restore(pkt, qdata);

	/* Move to Additionals to add OPT and TSIG. */
	if (pkt->current != KNOT_ADDITIONAL) {
		(void)knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	}

	/* Put OPT RR to the additional section. */
	if (answer_edns_reserve(pkt, qdata) != KNOT_EOK ||
	    answer_edns_put(pkt, qdata) != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_FORMERR;
	}

	/* Set final RCODE to packet. */
	if (qdata->rcode == KNOT_RCODE_NOERROR) {
		/* Default RCODE is SERVFAIL if not otherwise specified. */
		qdata->rcode = KNOT_RCODE_SERVFAIL;
	}
	set_rcode_to_packet(pkt, qdata);

	/* Transaction security (if applicable). */
	if (process_query_sign_response(pkt, qdata) != KNOT_EOK) {
		set_rcode_to_packet(pkt, qdata);
	}

	return KNOT_STATE_DONE;
}

#define PROCESS_BEGIN(plan, step, next_state, qdata) \
	if (plan != NULL) { \
		WALK_LIST(step, plan->stage[KNOTD_STAGE_BEGIN]) { \
			next_state = step->process(next_state, pkt, qdata, step->ctx); \
			if (next_state == KNOT_STATE_FAIL) { \
				goto finish; \
			} \
		} \
	}

#define PROCESS_END(plan, step, next_state, qdata) \
	if (plan != NULL) { \
		WALK_LIST(step, plan->stage[KNOTD_STAGE_END]) { \
			next_state = step->process(next_state, pkt, qdata, step->ctx); \
			if (next_state == KNOT_STATE_FAIL) { \
				next_state = process_query_err(ctx, pkt); \
			} \
		} \
	}

static int process_query_out(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);

	rcu_read_lock();

	knotd_qdata_t *qdata = QUERY_DATA(ctx);
	struct query_plan *plan = conf()->query_plan;
	struct query_plan *zone_plan = NULL;
	struct query_step *step = NULL;

	int next_state = KNOT_STATE_PRODUCE;

	/* Check parse state. */
	knot_pkt_t *query = qdata->query;
	if (query->parsed < query->size) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		next_state = KNOT_STATE_FAIL;
		goto finish;
	}

	/* Preprocessing. */
	if (prepare_answer(query, pkt, ctx) != KNOT_EOK) {
		next_state = KNOT_STATE_FAIL;
		goto finish;
	}

	if (qdata->extra->zone != NULL && qdata->extra->zone->query_plan != NULL) {
		zone_plan = qdata->extra->zone->query_plan;
	}

	/* Before query processing code. */
	PROCESS_BEGIN(plan, step, next_state, qdata);
	PROCESS_BEGIN(zone_plan, step, next_state, qdata);

	/* Answer based on qclass. */
	if (next_state == KNOT_STATE_PRODUCE) {
		switch (knot_pkt_qclass(pkt)) {
		case KNOT_CLASS_CH:
			next_state = query_chaos(pkt, ctx);
			break;
		case KNOT_CLASS_ANY:
		case KNOT_CLASS_IN:
			next_state = query_internet(pkt, ctx);
			break;
		default:
			qdata->rcode = KNOT_RCODE_REFUSED;
			next_state = KNOT_STATE_FAIL;
			break;
		}
	}

	/* Postprocessing. */
	if (next_state == KNOT_STATE_DONE || next_state == KNOT_STATE_PRODUCE) {
		/* Restore original QNAME. */
		process_query_qname_case_restore(pkt, qdata);

		/* Move to Additionals to add OPT and TSIG. */
		if (pkt->current != KNOT_ADDITIONAL) {
			(void)knot_pkt_begin(pkt, KNOT_ADDITIONAL);
		}

		/* Put OPT RR to the additional section. */
		if (answer_edns_put(pkt, qdata) != KNOT_EOK) {
			qdata->rcode = KNOT_RCODE_FORMERR;
			next_state = KNOT_STATE_FAIL;
			goto finish;
		}

		/* Transaction security (if applicable). */
		if (process_query_sign_response(pkt, qdata) != KNOT_EOK) {
			next_state = KNOT_STATE_FAIL;
			goto finish;
		}
	}

finish:
	switch (next_state) {
	case KNOT_STATE_NOOP:
		break;
	case KNOT_STATE_FAIL:
		/* Error processing. */
		next_state = process_query_err(ctx, pkt);
		break;
	case KNOT_STATE_FINAL:
		/* Just skipped postprocessing. */
		next_state = KNOT_STATE_DONE;
		break;
	default:
		set_rcode_to_packet(pkt, qdata);
	}

	/* After query processing code. */
	PROCESS_END(plan, step, next_state, qdata);
	PROCESS_END(zone_plan, step, next_state, qdata);

	rcu_read_unlock();

	return next_state;
}

bool process_query_acl_check(conf_t *conf, const knot_dname_t *zone_name,
                             acl_action_t action, knotd_qdata_t *qdata)
{
	knot_pkt_t *query = qdata->query;
	const struct sockaddr_storage *query_source = qdata->params->remote;
	knot_tsig_key_t tsig = { 0 };

	/* Skip if already checked and valid. */
	if (qdata->sign.tsig_key.name != NULL) {
		return true;
	}

	/* Authenticate with NOKEY if the packet isn't signed. */
	if (query->tsig_rr) {
		tsig.name = query->tsig_rr->owner;
		tsig.algorithm = knot_tsig_rdata_alg(query->tsig_rr);
	}

	/* Check if authenticated. */
	conf_val_t acl = conf_zone_get(conf, C_ACL, zone_name);
	if (!acl_allowed(conf, &acl, action, query_source, &tsig)) {
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)query_source);
		const knot_lookup_t *act = knot_lookup_by_id((knot_lookup_t *)acl_actions,
		                                             action);
		char *key_name = knot_dname_to_str_alloc(tsig.name);

		log_zone_debug(zone_name,
		               "ACL, denied, action %s, remote %s, key %s%s%s",
		               (act != NULL) ? act->name : "query",
		               addr_str,
		               (key_name != NULL) ? "'" : "",
		               (key_name != NULL) ? key_name : "none",
		               (key_name != NULL) ? "'" : "");
		free(key_name);

		qdata->rcode = KNOT_RCODE_NOTAUTH;
		qdata->rcode_tsig = KNOT_RCODE_BADKEY;
		return false;
	}

	/* Remember used TSIG key. */
	qdata->sign.tsig_key = tsig;

	return true;
}

int process_query_verify(knotd_qdata_t *qdata)
{
	knot_pkt_t *query = qdata->query;
	knot_sign_context_t *ctx = &qdata->sign;

	/* NOKEY => no verification. */
	if (query->tsig_rr == NULL) {
		return KNOT_EOK;
	}

	/* Keep digest for signing response. */
	/*! \note This memory will be rewritten for multi-pkt answers. */
	ctx->tsig_digest = (uint8_t *)knot_tsig_rdata_mac(query->tsig_rr);
	ctx->tsig_digestlen = knot_tsig_rdata_mac_length(query->tsig_rr);

	/* Checking query. */
	process_query_qname_case_restore(query, qdata);
	int ret = knot_tsig_server_check(query->tsig_rr, query->wire,
	                                 query->size, &ctx->tsig_key);
	process_query_qname_case_lower(query);

	/* Evaluate TSIG check results. */
	switch(ret) {
	case KNOT_EOK:
		qdata->rcode = KNOT_RCODE_NOERROR;
		break;
	case KNOT_TSIG_EBADKEY:
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		qdata->rcode_tsig = KNOT_RCODE_BADKEY;
		break;
	case KNOT_TSIG_EBADSIG:
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		qdata->rcode_tsig = KNOT_RCODE_BADSIG;
		break;
	case KNOT_TSIG_EBADTIME:
		qdata->rcode = KNOT_RCODE_NOTAUTH;
		qdata->rcode_tsig = KNOT_RCODE_BADTIME;
		ctx->tsig_time_signed = knot_tsig_rdata_time_signed(query->tsig_rr);
		break;
	case KNOT_EMALF:
		qdata->rcode = KNOT_RCODE_FORMERR;
		break;
	default:
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		break;
	}

	/* Log possible error. */
	if (qdata->rcode == KNOT_RCODE_SERVFAIL) {
		log_zone_error(qdata->extra->zone->name,
		               "TSIG, verification failed (%s)", knot_strerror(ret));
	} else if (qdata->rcode != KNOT_RCODE_NOERROR) {
		const knot_lookup_t *item = NULL;
		if (qdata->rcode_tsig != KNOT_RCODE_NOERROR) {
			item = knot_lookup_by_id(knot_tsig_rcode_names, qdata->rcode_tsig);
			if (item == NULL) {
				item = knot_lookup_by_id(knot_rcode_names, qdata->rcode_tsig);
			}
		} else {
			item = knot_lookup_by_id(knot_rcode_names, qdata->rcode);
		}

		char *key_name = knot_dname_to_str_alloc(ctx->tsig_key.name);
		log_zone_debug(qdata->extra->zone->name,
		               "TSIG, key '%s', verification failed '%s'",
		               (key_name != NULL) ? key_name : "",
		               (item != NULL) ? item->name : "");
		free(key_name);
	}

	return ret;
}

int process_query_sign_response(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	if (pkt->size == 0) {
		// Nothing to sign.
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	knot_pkt_t *query = qdata->query;
	knot_sign_context_t *ctx = &qdata->sign;

	/* KEY provided and verified TSIG or BADTIME allows signing. */
	if (ctx->tsig_key.name != NULL && knot_tsig_can_sign(qdata->rcode_tsig)) {
		/* Sign query response. */
		size_t new_digest_len = dnssec_tsig_algorithm_size(ctx->tsig_key.algorithm);
		if (ctx->pkt_count == 0) {
			ret = knot_tsig_sign(pkt->wire, &pkt->size, pkt->max_size,
			                     ctx->tsig_digest, ctx->tsig_digestlen,
			                     ctx->tsig_digest, &new_digest_len,
			                     &ctx->tsig_key, qdata->rcode_tsig,
			                     ctx->tsig_time_signed);
		} else {
			ret = knot_tsig_sign_next(pkt->wire, &pkt->size, pkt->max_size,
			                          ctx->tsig_digest, ctx->tsig_digestlen,
			                          ctx->tsig_digest, &new_digest_len,
			                          &ctx->tsig_key,
			                          pkt->wire, pkt->size);
		}
		if (ret != KNOT_EOK) {
			goto fail; /* Failed to sign. */
		} else {
			++ctx->pkt_count;
		}
	} else {
		/* Copy TSIG from query and set RCODE. */
		if (query->tsig_rr && qdata->rcode_tsig != KNOT_RCODE_NOERROR) {
			ret = knot_tsig_add(pkt->wire, &pkt->size, pkt->max_size,
			                    qdata->rcode_tsig, query->tsig_rr);
			if (ret != KNOT_EOK) {
				goto fail; /* Whatever it is, it's server fail. */
			}
		}
	}

	return KNOT_EOK;

	/* Server failure in signing. */
fail:
	qdata->rcode = KNOT_RCODE_SERVFAIL;
	qdata->rcode_tsig = KNOT_RCODE_NOERROR; /* Don't sign again. */
	return ret;
}

/*! \brief Synthesize RRSIG for given parameters, store in 'qdata' for later use */
static int put_rrsig(const knot_dname_t *sig_owner, uint16_t type,
                     const knot_rrset_t *rrsigs, knot_rrinfo_t *rrinfo,
                     knotd_qdata_t *qdata)
{
	knot_rdataset_t synth_rrs;
	knot_rdataset_init(&synth_rrs);
	int ret = knot_synth_rrsig(type, &rrsigs->rrs, &synth_rrs, qdata->mm);
	if (ret == KNOT_ENOENT) {
		// No signature
		return KNOT_EOK;
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Create rrsig info structure. */
	struct rrsig_info *info = mm_alloc(qdata->mm, sizeof(struct rrsig_info));
	if (info == NULL) {
		knot_rdataset_clear(&synth_rrs, qdata->mm);
		return KNOT_ENOMEM;
	}

	/* Store RRSIG into info structure. */
	knot_dname_t *owner_copy = knot_dname_copy(sig_owner, qdata->mm);
	if (owner_copy == NULL) {
		mm_free(qdata->mm, info);
		knot_rdataset_clear(&synth_rrs, qdata->mm);
		return KNOT_ENOMEM;
	}
	knot_rrset_init(&info->synth_rrsig, owner_copy, rrsigs->type,
	                rrsigs->rclass, rrsigs->ttl);
	/* Store filtered signature. */
	info->synth_rrsig.rrs = synth_rrs;

	info->rrinfo = rrinfo;
	add_tail(&qdata->extra->rrsigs, &info->n);

	return KNOT_EOK;
}

int process_query_put_rr(knot_pkt_t *pkt, knotd_qdata_t *qdata,
                         const knot_rrset_t *rr, const knot_rrset_t *rrsigs,
                         uint16_t compr_hint, uint32_t flags)
{
	if (rr->rrs.count < 1) {
		return KNOT_EMALF;
	}

	/* Wildcard expansion applies only for answers. */
	bool expand = false;
	if (pkt->current == KNOT_ANSWER) {
		/* Expand if RR is wildcard & we didn't query for wildcard. */
		expand = (knot_dname_is_wildcard(rr->owner) && !knot_dname_is_wildcard(qdata->name));
	}

	int ret = KNOT_EOK;

	/* If we already have compressed name on the wire and compression hint,
	 * we can just insert RRSet and fake synthesis by using compression
	 * hint. */
	knot_rrset_t to_add;
	if (compr_hint == KNOT_COMPR_HINT_NONE && expand) {
		knot_dname_t *qname_cpy = knot_dname_copy(qdata->name, &pkt->mm);
		if (qname_cpy == NULL) {
			return KNOT_ENOMEM;
		}
		knot_rrset_init(&to_add, qname_cpy, rr->type, rr->rclass, rr->ttl);
		ret = knot_rdataset_copy(&to_add.rrs, &rr->rrs, &pkt->mm);
		if (ret != KNOT_EOK) {
			knot_dname_free(qname_cpy, &pkt->mm);
			return ret;
		}
		to_add.additional = rr->additional;
		flags |= KNOT_PF_FREE;
	} else {
		to_add = *rr;
	}

	uint16_t prev_count = pkt->rrset_count;
	ret = knot_pkt_put_rotate(pkt, compr_hint, &to_add, knot_wire_get_id(qdata->query->wire),
	                          flags);
	if (ret != KNOT_EOK && (flags & KNOT_PF_FREE)) {
		knot_rrset_clear(&to_add, &pkt->mm);
		return ret;
	}

	const bool inserted = (prev_count != pkt->rrset_count);
	if (inserted &&
	    !knot_rrset_empty(rrsigs) && rr->type != KNOT_RRTYPE_RRSIG) {
		// Get rrinfo of just inserted RR.
		knot_rrinfo_t *rrinfo = &pkt->rr_info[pkt->rrset_count - 1];
		ret = put_rrsig(rr->owner, rr->type, rrsigs, rrinfo, qdata);
	}

	return ret;
}

/*! \brief Module implementation. */
const knot_layer_api_t *process_query_layer(void)
{
	static const knot_layer_api_t api = {
		.begin   = &process_query_begin,
		.reset   = &process_query_reset,
		.finish  = &process_query_finish,
		.consume = &process_query_in,
		.produce = &process_query_out,
	};
	return &api;
}
