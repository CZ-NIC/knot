/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <netinet/in.h>
#include <sys/socket.h>

#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
#include "knot/common/qps_limiter.h"
#endif
#include "contrib/dnstap/dnstap.h"
#include "contrib/dnstap/dnstap.pb-c.h"
#include "contrib/dnstap/message.h"
#include "contrib/dnstap/writer.h"
#include "contrib/time.h"
#include "knot/include/module.h"
#include "dnstapcounter.h"

#define MOD_SINK	"\x04""sink"
#define MOD_IDENTITY	"\x08""identity"
#define MOD_VERSION	"\x07""version"
#define MOD_QUERIES	"\x0B""log-queries"
#define MOD_RESPONSES	"\x0D""log-responses"
#define MOD_COMBINED  "\x0F""query-with-resp"
#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
#define MOD_QPS_LIMIT "\x09""qps-limit"
#define MOD_ERR_LIMIT "\x09""err-limit"
#endif

const yp_item_t dnstap_conf[] = {
	{ MOD_SINK,      YP_TSTR,  YP_VNONE },
	{ MOD_IDENTITY,  YP_TSTR,  YP_VNONE },
	{ MOD_VERSION,   YP_TSTR,  YP_VNONE },
	{ MOD_QUERIES,   YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_RESPONSES, YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_COMBINED,  YP_TBOOL, YP_VBOOL = { false } },
#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
	{ MOD_QPS_LIMIT, YP_TINT,  YP_VINT = { 0, INT32_MAX, 0 } },
	{ MOD_ERR_LIMIT, YP_TINT,  YP_VINT = { 0, INT32_MAX, 0 } },
#endif
	{ NULL }
};

int dnstap_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t sink = knotd_conf_check_item(args, MOD_SINK);
	if (sink.count == 0 || sink.single.string[0] == '\0') {
		args->err_str = "no sink specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

typedef struct {
	struct fstrm_iothr *iothread;
	char *identity;
	size_t identity_len;
	char *version;
	size_t version_len;
	bool log_query_with_resp;
#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
	qps_limiter_t qps_limiter;
#endif
} dnstap_ctx_t;

static knotd_state_t log_message(knotd_state_t state, const knot_pkt_t *pkt,
                                 knotd_qdata_t *qdata, knotd_mod_t *mod, struct timespec *tv)
{
	assert(pkt && qdata && mod);

	/* Skip empty packet. */
	if (state == KNOTD_STATE_NOOP) {
		return state;
	}

	dnstap_ctx_t *ctx = knotd_mod_ctx(mod);

	struct fstrm_iothr_queue *ioq =
		fstrm_iothr_get_input_queue_idx(ctx->iothread, qdata->params->thread_id);

	void *wire2 = NULL;
	size_t len_wire2 = 0;
	/* Determine query / response. */
	Dnstap__Message__Type msgtype = DNSTAP__MESSAGE__TYPE__AUTH_QUERY;
	if (knot_wire_get_qr(pkt->wire)) {
		msgtype = DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE;

		if (ctx->log_query_with_resp) {
			wire2 = qdata->query->wire;
			len_wire2 = qdata->query->size;
		}
	}

	/* Determine whether we run on UDP/TCP. */
	int protocol = IPPROTO_TCP;
	if (qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE) {
		protocol = IPPROTO_UDP;
	}

	/* Create a dnstap message. */
	Dnstap__Message msg;
	int ret = dt_message_fill(&msg, msgtype,
	                          (const struct sockaddr *)knotd_qdata_remote_addr(qdata),
	                          (const struct sockaddr *)knotd_qdata_local_addr(qdata),
	                          protocol, pkt->wire, pkt->size, tv, wire2, len_wire2, &qdata->query_time);
	if (ret != KNOT_EOK) {
		return state;
	}

	Dnstap__Dnstap dnstap = DNSTAP__DNSTAP__INIT;
	dnstap.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dnstap.message = &msg;

	/* Set message version and identity. */
	if (ctx->identity_len > 0) {
		dnstap.identity.data = (uint8_t *)ctx->identity;
		dnstap.identity.len = ctx->identity_len;
		dnstap.has_identity = 1;
	}
	if (ctx->version_len > 0) {
		dnstap.version.data = (uint8_t *)ctx->version;
		dnstap.version.len = ctx->version_len;
		dnstap.has_version = 1;
	}

	/* Pack the message. */
	uint8_t *frame = NULL;
	size_t size = 0;
	dt_pack(&dnstap, &frame, &size);
	if (frame == NULL) {
		return state;
	}

	/* Submit a request. */
	fstrm_res res = fstrm_iothr_submit(ctx->iothread, ioq, frame, size,
	                                   fstrm_free_wrapper, NULL);
	if (res != fstrm_res_success) {
		free(frame);
		return state;
	}

	return state;
}

/*! \brief Submit message - query. */
static knotd_state_t dnstap_message_log_query(knotd_state_t state, knot_pkt_t *pkt,
                                              knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(qdata);
	struct timespec tv;
	clock_gettime(CLOCK_REALTIME_COARSE, &tv);

	knotd_mod_stats_incr(
        mod,
        qdata->params->thread_id,
        dnstap_counter_log_emitted,
        log_emitted_QUERY,
        1);

	return log_message(state, qdata->query, qdata, mod, &tv);
}

/*! \brief Submit message - response. */
static knotd_state_t dnstap_message_log_response(knotd_state_t state, knot_pkt_t *pkt,
                                                 knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	struct timespec tv;
	clock_gettime(CLOCK_REALTIME_COARSE, &tv);

	knotd_mod_stats_incr(
        mod,
        qdata->params->thread_id,
        dnstap_counter_log_emitted,
        log_emitted_RESPONSE,
        1);

	return log_message(state, pkt, qdata, mod, &tv);
}


#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
/*! \brief Submit message - query. */
static knotd_state_t dnstap_message_log_query_limit(knotd_state_t state, knot_pkt_t *pkt,
                                              knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	struct timespec tv;
	clock_gettime(CLOCK_REALTIME_COARSE, &tv);

	dnstap_ctx_t *ctx = knotd_mod_ctx(mod);
	if (qps_limiter_is_allowed(&ctx->qps_limiter, tv.tv_sec, false)) {
		knotd_mod_stats_incr(
			mod,
			qdata->params->thread_id,
			dnstap_counter_log_emitted,
			log_emitted_QUERY,
			1);

		return log_message(state, qdata->query, qdata, mod, &tv);
	} else {
		knotd_mod_stats_incr(
			mod,
			qdata->params->thread_id,
			dnstap_counter_log_dropped,
			log_dropped_QUERY,
			1);

		return state;
	}
}

/*! \brief Submit message - response. */
static knotd_state_t dnstap_message_log_response_limit(knotd_state_t state, knot_pkt_t *pkt,
                                                 knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	struct timespec tv;
	clock_gettime(CLOCK_REALTIME_COARSE, &tv);

	bool err = KNOT_RCODE_SERVFAIL == knot_wire_get_rcode(pkt->wire);

	dnstap_ctx_t *ctx = knotd_mod_ctx(mod);
	if (qps_limiter_is_allowed(&ctx->qps_limiter, tv.tv_sec, err)) {
		knotd_mod_stats_incr(
			mod,
			qdata->params->thread_id,
			dnstap_counter_log_emitted,
			log_emitted_RESPONSE,
			1);

		return log_message(state, pkt, qdata, mod, &tv);
	} else {
		knotd_mod_stats_incr(
			mod,
			qdata->params->thread_id,
			dnstap_counter_log_dropped,
			log_dropped_RESPONSE,
			1);

		return state;
	}
}
#endif

/*! \brief Create a UNIX socket sink. */
static struct fstrm_writer* dnstap_unix_writer(const char *path)
{
	struct fstrm_unix_writer_options *opt = NULL;
	struct fstrm_writer_options *wopt = NULL;
	struct fstrm_writer *writer = NULL;

	opt = fstrm_unix_writer_options_init();
	if (opt == NULL) {
		goto finish;
	}
	fstrm_unix_writer_options_set_socket_path(opt, path);

	wopt = fstrm_writer_options_init();
	if (wopt == NULL) {
		goto finish;
	}
	fstrm_writer_options_add_content_type(wopt, DNSTAP_CONTENT_TYPE,
	                                      strlen(DNSTAP_CONTENT_TYPE));
	writer = fstrm_unix_writer_init(opt, wopt);

finish:
	fstrm_unix_writer_options_destroy(&opt);
	fstrm_writer_options_destroy(&wopt);
	return writer;
}

/*! \brief Create a basic file writer sink. */
static struct fstrm_writer* dnstap_file_writer(const char *path)
{
	struct fstrm_file_options *fopt = NULL;
	struct fstrm_writer_options *wopt = NULL;
	struct fstrm_writer *writer = NULL;

	fopt = fstrm_file_options_init();
	if (fopt == NULL) {
		goto finish;
	}
	fstrm_file_options_set_file_path(fopt, path);

	wopt = fstrm_writer_options_init();
	if (wopt == NULL) {
		goto finish;
	}
	fstrm_writer_options_add_content_type(wopt, DNSTAP_CONTENT_TYPE,
	                                      strlen(DNSTAP_CONTENT_TYPE));
	writer = fstrm_file_writer_init(fopt, wopt);

finish:
	fstrm_file_options_destroy(&fopt);
	fstrm_writer_options_destroy(&wopt);
	return writer;
}

/*! \brief Create a log sink according to the path string. */
static struct fstrm_writer* dnstap_writer(const char *path)
{
	const char *prefix = "unix:";
	const size_t prefix_len = strlen(prefix);

	/* UNIX socket prefix. */
	if (strlen(path) > prefix_len && strncmp(path, prefix, prefix_len) == 0) {
		return dnstap_unix_writer(path + prefix_len);
	}

	return dnstap_file_writer(path);
}

int dnstap_load(knotd_mod_t *mod)
{
	/* Create dnstap context. */
	dnstap_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	/* Set identity. */
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_IDENTITY);
	if (conf.count == 1) {
		ctx->identity = (conf.single.string != NULL) ?
		                strdup(conf.single.string) : NULL;
	} else {
		knotd_conf_t host = knotd_conf_env(mod, KNOTD_CONF_ENV_HOSTNAME);
		ctx->identity = strdup(host.single.string);
	}
	ctx->identity_len = (ctx->identity != NULL) ? strlen(ctx->identity) : 0;

	/* Set version. */
	conf = knotd_conf_mod(mod, MOD_VERSION);
	if (conf.count == 1) {
		ctx->version = (conf.single.string != NULL) ?
		               strdup(conf.single.string) : NULL;
	} else {
		knotd_conf_t version = knotd_conf_env(mod, KNOTD_CONF_ENV_VERSION);
		ctx->version = strdup(version.single.string);
	}
	ctx->version_len = (ctx->version != NULL) ? strlen(ctx->version) : 0;

	/* Set sink. */
	conf = knotd_conf_mod(mod, MOD_SINK);
	const char *sink = conf.single.string;

	/* Set log_queries. */
	conf = knotd_conf_mod(mod, MOD_QUERIES);
	const bool log_queries = conf.single.boolean;

	/* Set log_responses. */
	conf = knotd_conf_mod(mod, MOD_RESPONSES);
	const bool log_responses = conf.single.boolean;

#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
	/* Get QPS_limit. */
	conf = knotd_conf_mod(mod, MOD_QPS_LIMIT);
	ctx->qps_limiter.log_qps = conf.single.integer;

	/* Get Err QPS_limit. */
	conf = knotd_conf_mod(mod, MOD_ERR_LIMIT);
	ctx->qps_limiter.log_err_qps = conf.single.integer;

	/* Get Log query with resp. */
	conf = knotd_conf_mod(mod, MOD_COMBINED);
	ctx->log_query_with_resp = conf.single.boolean;

	bool limit_by_qps = ctx->qps_limiter.log_qps || ctx->qps_limiter.log_err_qps;

	if (limit_by_qps) {
		if (qps_limiter_init(&ctx->qps_limiter) != KNOT_EOK) {
			goto fail;
		}
	}
#endif

	/* Initialize the writer and the options. */
	struct fstrm_writer *writer = dnstap_writer(sink);
	if (writer == NULL) {
		goto fail;
	}

	struct fstrm_iothr_options *opt = fstrm_iothr_options_init();
	if (opt == NULL) {
		fstrm_writer_destroy(&writer);
		goto fail;
	}

	/* Initialize queues. */
	fstrm_iothr_options_set_num_input_queues(opt, knotd_mod_threads(mod));

	/* Create the I/O thread. */
	ctx->iothread = fstrm_iothr_init(opt, &writer);
	fstrm_iothr_options_destroy(&opt);
	if (ctx->iothread == NULL) {
		fstrm_writer_destroy(&writer);
		goto fail;
	}

	knotd_mod_ctx_set(mod, ctx);

	/* Hook to the query plan. */
	if (log_queries) {
		knotd_mod_hook(mod, KNOTD_STAGE_BEGIN,
#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
			limit_by_qps ? dnstap_message_log_query_limit :
#endif
			dnstap_message_log_query);
	}
	if (log_responses) {
		knotd_mod_hook(mod, KNOTD_STAGE_END,
#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
			limit_by_qps ? dnstap_message_log_response_limit :
#endif
			dnstap_message_log_response);
	}

	if (KNOT_EOK != dnstap_create_counters(mod)) {
        goto fail;
    }

	return KNOT_EOK;
fail:
	knotd_mod_log(mod, LOG_ERR, "failed to init sink '%s'", sink);

#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
	qps_limiter_cleanup(&ctx->qps_limiter);
#endif
	free(ctx->identity);
	free(ctx->version);
	free(ctx);

	return KNOT_ENOMEM;
}

void dnstap_unload(knotd_mod_t *mod)
{
	dnstap_ctx_t *ctx = knotd_mod_ctx(mod);
	dnstap_delete_counters(mod);

	fstrm_iothr_destroy(&ctx->iothread);
#ifdef ENABLE_THROTTLE_DNSTAP_LOGS
	qps_limiter_cleanup(&ctx->qps_limiter);
#endif
	free(ctx->identity);
	free(ctx->version);
	free(ctx);
}

KNOTD_MOD_API(dnstap, KNOTD_MOD_FLAG_SCOPE_ANY,
              dnstap_load, dnstap_unload, dnstap_conf, dnstap_conf_check);
