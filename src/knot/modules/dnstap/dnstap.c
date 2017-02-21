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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>

#include "contrib/dnstap/dnstap.h"
#include "contrib/dnstap/dnstap.pb-c.h"
#include "contrib/dnstap/message.h"
#include "contrib/dnstap/writer.h"
#include "contrib/mempattern.h"
#include "contrib/time.h"
#include "knot/modules/dnstap/dnstap.h"

/* Module configuration scheme. */
#define MOD_SINK	"\x04""sink"
#define MOD_IDENTITY	"\x08""identity"
#define MOD_VERSION	"\x07""version"
#define MOD_QUERIES	"\x0B""log-queries"
#define MOD_RESPONSES	"\x0D""log-responses"

const yp_item_t scheme_mod_dnstap[] = {
	{ C_ID,          YP_TSTR,  YP_VNONE },
	{ MOD_SINK,      YP_TSTR,  YP_VSTR = { "" } },
	{ MOD_IDENTITY,  YP_TSTR,  YP_VNONE },
	{ MOD_VERSION,   YP_TSTR,  YP_VSTR = { "Knot DNS " PACKAGE_VERSION } },
	{ MOD_QUERIES,   YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_RESPONSES, YP_TBOOL, YP_VBOOL = { true } },
	{ C_COMMENT,     YP_TSTR,  YP_VNONE },
	{ NULL }
};

int check_mod_dnstap(conf_check_t *args)
{
	conf_val_t sink = conf_rawid_get_txn(args->conf, args->txn, C_MOD_DNSTAP,
	                                     MOD_SINK, args->id, args->id_len);
	if (conf_str(&sink)[0] == '\0') {
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

static int log_message(int state, const knot_pkt_t *pkt, struct query_data *qdata,
                       dnstap_ctx_t *ctx)
{
	assert(pkt && qdata && ctx);

	/* Skip empty packet. */
	if (pkt->size == 0) {
		return state;
	}

	struct fstrm_iothr_queue *ioq =
		fstrm_iothr_get_input_queue_idx(ctx->iothread, qdata->param->thread_id);

	/* Unless we want to measure the time it takes to process each query,
	 * we can treat Q/R times the same. */
	struct timespec tv = time_now();

	/* Determine query / response. */
	Dnstap__Message__Type msgtype = DNSTAP__MESSAGE__TYPE__AUTH_QUERY;
	if (knot_wire_get_qr(pkt->wire)) {
		msgtype = DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE;
	}

	/* Determine whether we run on UDP/TCP. */
	int protocol = IPPROTO_TCP;
	if (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) {
		protocol = IPPROTO_UDP;
	}

	/* Create a dnstap message. */
	Dnstap__Message msg;
	int ret = dt_message_fill(&msg, msgtype,
	                          (const struct sockaddr *)qdata->param->remote,
	                          NULL, /* todo: fill me! */
	                          protocol, pkt->wire, pkt->size, &tv, &tv);
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
static int dnstap_message_log_query(int state, knot_pkt_t *pkt, struct query_data *qdata,
                                    void *ctx)
{
	assert(qdata);

	return log_message(state, qdata->query, qdata, ctx);
}

/*! \brief Submit message - response. */
static int dnstap_message_log_response(int state, knot_pkt_t *pkt, struct query_data *qdata,
                                       void *ctx)
{
	return log_message(state, pkt, qdata, ctx);
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

int dnstap_load(struct query_module *self)
{
	assert(self);

	/* Create dnstap context. */
	dnstap_ctx_t *ctx = mm_alloc(self->mm, sizeof(*ctx));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	conf_val_t val;

	/* Set identity. */
	val = conf_mod_get(self->config, MOD_IDENTITY, self->id);
	if (val.code == KNOT_EOK) {
		const char *ident = conf_str(&val);
		ctx->identity = (ident != NULL) ? strdup(ident) : NULL;
	} else {
		ctx->identity = strdup(self->config->hostname);
	}
	ctx->identity_len = (ctx->identity != NULL) ? strlen(ctx->identity) : 0;

	/* Set version. */
	val = conf_mod_get(self->config, MOD_VERSION, self->id);
	ctx->version = strdup(conf_str(&val)); // Default ensures != NULL.
	ctx->version_len = strlen(ctx->version);

	/* Set sink. */
	val = conf_mod_get(self->config, MOD_SINK, self->id);
	const char *sink = conf_str(&val);

	/* Set log_queries. */
	val = conf_mod_get(self->config, MOD_QUERIES, self->id);
	const bool log_queries = conf_bool(&val);

	/* Set log_responses. */
	val = conf_mod_get(self->config, MOD_RESPONSES, self->id);
	const bool log_responses = conf_bool(&val);

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
	size_t qcount = conf_udp_threads(self->config) +
	                conf_tcp_threads(self->config);
	fstrm_iothr_options_set_num_input_queues(opt, qcount);

	/* Create the I/O thread. */
	ctx->iothread = fstrm_iothr_init(opt, &writer);
	fstrm_iothr_options_destroy(&opt);
	if (ctx->iothread == NULL) {
		fstrm_writer_destroy(&writer);
		goto fail;
	}

	self->ctx = ctx;

	/* Hook to the query plan. */
	if (log_queries) {
		query_module_step(self, QPLAN_BEGIN, dnstap_message_log_query);
	}
	if (log_responses) {
		query_module_step(self, QPLAN_END, dnstap_message_log_response);
	}

	return KNOT_EOK;
fail:
	MODULE_ERR(C_MOD_DNSTAP, "failed to init sink '%s'", sink);

	free(ctx->identity);
	free(ctx->version);
	mm_free(self->mm, ctx);

	return KNOT_ENOMEM;
}

void dnstap_unload(struct query_module *self)
{
	assert(self);

	dnstap_ctx_t *ctx = self->ctx;

	fstrm_iothr_destroy(&ctx->iothread);
	free(ctx->identity);
	free(ctx->version);
	mm_free(self->mm, ctx);
}
