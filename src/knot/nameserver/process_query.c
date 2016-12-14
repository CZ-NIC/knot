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

#include <urcu.h>

#include "dnssec/tsig.h"
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
#include "libknot/libknot.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"

/*! \brief Accessor to query-specific data. */
#define QUERY_DATA(ctx) ((struct query_data *)(ctx)->data)

/*! \brief Reinitialize query data structure. */
static void query_data_init(knot_layer_t *ctx, void *module_param)
{
	/* Initialize persistent data. */
	struct query_data *data = QUERY_DATA(ctx);
	memset(data, 0, sizeof(struct query_data));
	data->mm = ctx->mm;
	data->param = (struct process_query_param*)module_param;

	/* Initialize lists. */
	init_list(&data->wildcards);
	init_list(&data->rrsigs);
}

static int process_query_begin(knot_layer_t *ctx, void *module_param)
{
	/* Initialize context. */
	assert(ctx);
	ctx->data = mm_alloc(ctx->mm, sizeof(struct query_data));

	/* Initialize persistent data. */
	query_data_init(ctx, module_param);

	/* Await packet. */
	return KNOT_STATE_CONSUME;
}

static int process_query_reset(knot_layer_t *ctx)
{
	assert(ctx);
	struct query_data *qdata = QUERY_DATA(ctx);

	/* Remember persistent parameters. */
	struct process_query_param *module_param = qdata->param;

	/* Free allocated data. */
	ptrlist_free(&qdata->wildcards, qdata->mm);
	nsec_clear_rrsigs(qdata);
	knot_rrset_clear(&qdata->opt_rr, qdata->mm);
	if (qdata->ext_cleanup != NULL) {
		qdata->ext_cleanup(qdata);
	}

	/* Initialize persistent data. */
	query_data_init(ctx, module_param);

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
	struct query_data *qdata = QUERY_DATA(ctx);

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
	qdata->packet_type = knot_pkt_type(pkt);

	/* Declare having response. */
	return KNOT_STATE_PRODUCE;
}

/*!
 * \brief Create a response for a given query in the INTERNET class.
 */
static int query_internet(knot_pkt_t *pkt, knot_layer_t *ctx)
{
	struct query_data *data = QUERY_DATA(ctx);

	switch(data->packet_type) {
	case KNOT_QUERY_NORMAL: return internet_process_query(pkt, data);
	case KNOT_QUERY_NOTIFY: return notify_process_query(pkt, data);
	case KNOT_QUERY_AXFR:   return axfr_process_query(pkt, data);
	case KNOT_QUERY_IXFR:   return ixfr_process_query(pkt, data);
	case KNOT_QUERY_UPDATE: return update_process_query(pkt, data);
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
	struct query_data *data = QUERY_DATA(ctx);

	/* Nothing except normal queries is supported. */
	if (data->packet_type != KNOT_QUERY_NORMAL) {
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
		if (knot_pkt_type(query) == KNOT_QUERY_NORMAL) {
			zone = knot_zonedb_find_suffix(zonedb, qname);
		} else {
			// Direct match required.
			zone = knot_zonedb_find(zonedb, qname);
		}
	}

	return zone;
}

static int answer_edns_reserve(knot_pkt_t *resp, struct query_data *qdata)
{
	if (knot_rrset_empty(&qdata->opt_rr)) {
		return KNOT_EOK;
	}

	/* Reserve size in the response. */
	return knot_pkt_reserve(resp, knot_edns_wire_size(&qdata->opt_rr));
}

static int answer_edns_init(const knot_pkt_t *query, knot_pkt_t *resp,
                            struct query_data *qdata)
{
	if (!knot_pkt_has_edns(query)) {
		return KNOT_EOK;
	}

	/* Initialize OPT record. */
	int16_t max_payload;
	switch (qdata->param->remote->ss_family) {
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
	if (knot_edns_has_option(query->opt_rr, KNOT_EDNS_OPTION_NSID)) {
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

	return answer_edns_reserve(resp, qdata);
}

static int answer_edns_put(knot_pkt_t *resp, struct query_data *qdata)
{
	if (knot_rrset_empty(&qdata->opt_rr)) {
		return KNOT_EOK;
	}

	/* Reclaim reserved size. */
	int ret = knot_pkt_reclaim(resp, knot_edns_wire_size(&qdata->opt_rr));
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint8_t *wire_end = resp->wire + resp->size;

	/* Write to packet. */
	assert(resp->current == KNOT_ADDITIONAL);
	ret = knot_pkt_put(resp, KNOT_COMPR_HINT_NONE, &qdata->opt_rr, 0);
	if (ret == KNOT_EOK) {
		/* Save position of the OPT RR. */
		qdata->opt_rr_pos = wire_end;
	}

	return ret;
}

/*! \brief Initialize response, sizes and find zone from which we're going to answer. */
static int prepare_answer(const knot_pkt_t *query, knot_pkt_t *resp, knot_layer_t *ctx)
{
	struct query_data *qdata = QUERY_DATA(ctx);
	server_t *server = qdata->param->server;

	/* Initialize response. */
	int ret = knot_pkt_init_response(resp, query);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_wire_clear_cd(resp->wire); // TODO: should be inside knot_pkt_init_response.

	/* Query MUST carry a question. */
	const knot_dname_t *qname = knot_pkt_qname(query);
	if (qname == NULL) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	/* Convert query QNAME to lowercase, but keep original QNAME case.
	 * Already checked for absence of compression and length.
	 */
	memcpy(qdata->orig_qname, qname, query->qname_size);
	ret = process_query_qname_case_lower((knot_pkt_t *)query);
	if (ret != KNOT_EOK) {
		return ret;
	}
	/* Find zone for QNAME. */
	qdata->zone = answer_zone_find(query, server->zone_db);

	/* Setup EDNS. */
	ret = answer_edns_init(query, resp, qdata);
	if (ret != KNOT_EOK || qdata->rcode != 0) {
		return KNOT_ERROR;
	}

	/* Update maximal answer size. */
	bool has_limit = qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE;
	if (has_limit) {
		resp->max_size = KNOT_WIRE_MIN_PKTSIZE;
		if (knot_pkt_has_edns(query)) {
			uint16_t server;
			switch (qdata->param->remote->ss_family) {
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

	return ret;
}

static int set_rcode_to_packet(knot_pkt_t *pkt, struct query_data *qdata)
{
	int ret = KNOT_EOK;
	uint8_t ext_rcode = KNOT_EDNS_RCODE_HI(qdata->rcode);

	if (ext_rcode != 0) {
		/* No OPT RR and Ext RCODE results in SERVFAIL. */
		if (qdata->opt_rr_pos == NULL) {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			ret = KNOT_ERROR;
		} else {
			knot_edns_set_ext_rcode_wire(qdata->opt_rr_pos, ext_rcode);
		}
	}

	knot_wire_set_rcode(pkt->wire, KNOT_EDNS_RCODE_LO(qdata->rcode));

	return ret;
}

static int process_query_err(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);
	struct query_data *qdata = QUERY_DATA(ctx);

	/* Initialize response from query packet. */
	knot_pkt_t *query = qdata->query;
	knot_pkt_init_response(pkt, query);
	knot_wire_clear_cd(pkt->wire); // TODO: should be inside knot_pkt_init_response.

	/* Restore original QNAME. */
	process_query_qname_case_restore(pkt, qdata);

	/* Add OPT and TSIG (best effort, send reply anyway if fails). */
	if (pkt->current != KNOT_ADDITIONAL) {
		knot_pkt_begin(pkt, KNOT_ADDITIONAL);
	}

	/* Put OPT RR to the additional section. */
	if (answer_edns_reserve(pkt, qdata) == KNOT_EOK) {
		(void) answer_edns_put(pkt, qdata);
	}

	/* Set final RCODE to packet. */
	(void) set_rcode_to_packet(pkt, qdata);

	/* Transaction security (if applicable). */
	(void) process_query_sign_response(pkt, qdata);

	return KNOT_STATE_DONE;
}

static int process_query_out(knot_layer_t *ctx, knot_pkt_t *pkt)
{
	assert(pkt && ctx);

	rcu_read_lock();

	struct query_data *qdata = QUERY_DATA(ctx);
	struct query_plan *plan = conf()->query_plan;
	struct query_step *step = NULL;

	/* Check parse state. */
	knot_pkt_t *query = qdata->query;
	int next_state = KNOT_STATE_PRODUCE;
	if (query->parsed < query->size) {
		knot_pkt_clear(pkt);
		qdata->rcode = KNOT_RCODE_FORMERR;
		next_state = KNOT_STATE_FAIL;
		goto finish;
	}

	/*
	 * Preprocessing.
	 */

	if (prepare_answer(query, pkt, ctx) != KNOT_EOK) {
		next_state = KNOT_STATE_FAIL;
		goto finish;
	}

	/* Before query processing code. */
	if (plan) {
		WALK_LIST(step, plan->stage[QPLAN_BEGIN]) {
			next_state = step->process(next_state, pkt, qdata, step->ctx);
		}
	}

	/* Answer based on qclass. */
	if (next_state != KNOT_STATE_DONE) {
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

	/*
	 * Postprocessing.
	 */

	if (next_state == KNOT_STATE_DONE || next_state == KNOT_STATE_PRODUCE) {

		/* Restore original QNAME. */
		process_query_qname_case_restore(pkt, qdata);

		if (pkt->current != KNOT_ADDITIONAL) {
			knot_pkt_begin(pkt, KNOT_ADDITIONAL);
		}

		/* Put OPT RR to the additional section. */
		if (answer_edns_put(pkt, qdata) != KNOT_EOK) {
			next_state = KNOT_STATE_FAIL;
			goto finish;
		}

		/* Transaction security (if applicable). */
		if (process_query_sign_response(pkt, qdata) != KNOT_EOK) {
			next_state = KNOT_STATE_FAIL;
		}
	}

finish:
	/* Default RCODE is SERVFAIL if not specified otherwise. */
	if (next_state == KNOT_STATE_FAIL && qdata->rcode == KNOT_RCODE_NOERROR) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
	}

	/* Store Extended RCODE - divide between header and OPT if possible. */
	if (next_state != KNOT_STATE_FAIL) {
		if (set_rcode_to_packet(pkt, qdata) != KNOT_EOK) {
			next_state = KNOT_STATE_FAIL;
		}
	}
	/* In case of NS_PROC_FAIL, RCODE is set in the error-processing function. */

	/* After query processing code. */
	if (plan) {
		WALK_LIST(step, plan->stage[QPLAN_END]) {
			next_state = step->process(next_state, pkt, qdata, step->ctx);
		}
	}

	rcu_read_unlock();

	return next_state;
}

bool process_query_acl_check(conf_t *conf, const knot_dname_t *zone_name,
                             acl_action_t action, struct query_data *qdata)
{
	knot_pkt_t *query = qdata->query;
	const struct sockaddr_storage *query_source = qdata->param->remote;
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
		               "ACL, denied, action '%s', remote '%s', key %s%s%s",
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

int process_query_verify(struct query_data *qdata)
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

	return ret;
}

int process_query_sign_response(knot_pkt_t *pkt, struct query_data *qdata)
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

	return ret;

	/* Server failure in signing. */
fail:
	qdata->rcode = KNOT_RCODE_SERVFAIL;
	qdata->rcode_tsig = KNOT_RCODE_NOERROR; /* Don't sign again. */
	return ret;
}

void process_query_qname_case_restore(knot_pkt_t *pkt, struct query_data *qdata)
{
	/* If original QNAME is empty, Query is either unparsed or for root domain.
	 * Either way, letter case doesn't matter. */
	if (qdata->orig_qname[0] != '\0') {
		memcpy(pkt->wire + KNOT_WIRE_HEADER_SIZE,
		       qdata->orig_qname, qdata->query->qname_size);
	}
}

int process_query_qname_case_lower(knot_pkt_t *pkt)
{
	knot_dname_t *qname = (knot_dname_t *)knot_pkt_qname(pkt);
	return knot_dname_to_lower(qname);
}

/*! \brief Synthesize RRSIG for given parameters, store in 'qdata' for later use */
static int put_rrsig(const knot_dname_t *sig_owner, uint16_t type,
                     const knot_rrset_t *rrsigs, knot_rrinfo_t *rrinfo,
                     struct query_data *qdata)
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
	knot_rrset_init(&info->synth_rrsig, owner_copy, rrsigs->type, rrsigs->rclass);
	/* Store filtered signature. */
	info->synth_rrsig.rrs = synth_rrs;

	info->rrinfo = rrinfo;
	add_tail(&qdata->rrsigs, &info->n);

	return KNOT_EOK;
}

int process_query_put_rr(knot_pkt_t *pkt, struct query_data *qdata,
                         const knot_rrset_t *rr, const knot_rrset_t *rrsigs,
                         uint16_t compr_hint, uint32_t flags)
{
	if (rr->rrs.rr_count < 1) {
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
		knot_rrset_init(&to_add, qname_cpy, rr->type, rr->rclass);
		ret = knot_rdataset_copy(&to_add.rrs, &rr->rrs, &pkt->mm);
		if (ret != KNOT_EOK) {
			knot_dname_free(&qname_cpy, &pkt->mm);
			return ret;
		}
		to_add.additional = rr->additional;
		flags |= KNOT_PF_FREE;
	} else {
		to_add = *rr;
	}

	uint16_t prev_count = pkt->rrset_count;
	ret = knot_pkt_put(pkt, compr_hint, &to_add, flags);
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
		.fail    = &process_query_err
	};
	return &api;
}
