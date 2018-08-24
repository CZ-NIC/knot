/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/dnstap/dnstap.h"
#include "contrib/dnstap/dnstap.pb-c.h"
#include "contrib/dnstap/message.h"
#include "contrib/dnstap/writer.h"
#include "contrib/time.h"
#include "knot/include/module.h"

#define MOD_SINK	"\x04""sink"
#define MOD_IDENTITY	"\x08""identity"
#define MOD_VERSION	"\x07""version"
#define MOD_QUERIES	"\x0B""log-queries"
#define MOD_RESPONSES	"\x0D""log-responses"

const yp_item_t dnstap_conf[] = {
	{ MOD_SINK,      YP_TSTR,  YP_VNONE },
	{ MOD_IDENTITY,  YP_TSTR,  YP_VNONE },
	{ MOD_VERSION,   YP_TSTR,  YP_VNONE },
	{ MOD_QUERIES,   YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_RESPONSES, YP_TBOOL, YP_VBOOL = { true } },
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
} dnstap_ctx_t;

static knotd_state_t log_message(knotd_state_t state, const knot_pkt_t *pkt,
                                 knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	/* Skip empty packet. */
	if (state == KNOTD_STATE_NOOP) {
		return state;
	}

	dnstap_ctx_t *ctx = knotd_mod_ctx(mod);

	struct fstrm_iothr_queue *ioq =
		fstrm_iothr_get_input_queue_idx(ctx->iothread, qdata->params->thread_id);

	/* Unless we want to measure the time it takes to process each query,
	 * we can treat Q/R times the same. */
	struct timespec tv = { .tv_sec = time(NULL) };

	/* Determine query / response. */
	Dnstap__Message__Type msgtype = DNSTAP__MESSAGE__TYPE__AUTH_QUERY;
	if (knot_wire_get_qr(pkt->wire)) {
		msgtype = DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE;
	}

	/* Determine whether we run on UDP/TCP. */
	int protocol = IPPROTO_TCP;
	if (qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE) {
		protocol = IPPROTO_UDP;
	}

	/* Create a dnstap message. */
	Dnstap__Message msg;
	int ret = dt_message_fill(&msg, msgtype,
	                          (const struct sockaddr *)qdata->params->remote,
	                          NULL, /* todo: fill me! */
				  protocol, pkt->wire, pkt->size, &tv);
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

	return log_message(state, qdata->query, qdata, mod);
}

/*! \brief Submit message - response. */
static knotd_state_t dnstap_message_log_response(knotd_state_t state, knot_pkt_t *pkt,
                                                 knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	return log_message(state, pkt, qdata, mod);
}

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
	knotd_conf_t udp = knotd_conf_env(mod, KNOTD_CONF_ENV_WORKERS_UDP);
	knotd_conf_t tcp = knotd_conf_env(mod, KNOTD_CONF_ENV_WORKERS_TCP);
	size_t qcount = udp.single.integer + tcp.single.integer;
	fstrm_iothr_options_set_num_input_queues(opt, qcount);

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
		knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, dnstap_message_log_query);
	}
	if (log_responses) {
		knotd_mod_hook(mod, KNOTD_STAGE_END, dnstap_message_log_response);
	}

	return KNOT_EOK;
fail:
	knotd_mod_log(mod, LOG_ERR, "failed to init sink '%s'", sink);

	free(ctx->identity);
	free(ctx->version);
	free(ctx);

	return KNOT_ENOMEM;
}

void dnstap_unload(knotd_mod_t *mod)
{
	dnstap_ctx_t *ctx = knotd_mod_ctx(mod);

	fstrm_iothr_destroy(&ctx->iothread);
	free(ctx->identity);
	free(ctx->version);
	free(ctx);
}

KNOTD_MOD_API(dnstap, KNOTD_MOD_FLAG_SCOPE_ANY,
              dnstap_load, dnstap_unload, dnstap_conf, dnstap_conf_check);
