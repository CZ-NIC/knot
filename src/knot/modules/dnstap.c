/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/log.h"
#include "knot/modules/dnstap.h"
#include "knot/nameserver/process_query.h"
#include "contrib/dnstap/dnstap.pb-c.h"
#include "contrib/dnstap/writer.h"
#include "contrib/dnstap/message.h"
#include "contrib/dnstap/dnstap.h"
#include "libknot/libknot.h"

/* Module configuration scheme. */
#define MOD_SINK	"\x04""sink"

const yp_item_t scheme_mod_dnstap[] = {
	{ C_ID,      YP_TSTR, YP_VNONE },
	{ MOD_SINK,  YP_TSTR, YP_VNONE },
	{ C_COMMENT, YP_TSTR, YP_VNONE },
	{ NULL }
};

int check_mod_dnstap(conf_check_t *args)
{
	conf_val_t sink = conf_rawid_get_txn(args->conf, args->txn, C_MOD_DNSTAP,
	                                     MOD_SINK, args->id, args->id_len);
	if (sink.code != KNOT_EOK) {
		args->err_str = "no sink specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int log_message(int state, const knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

	int ret = KNOT_ERROR;
	struct fstrm_iothr* iothread = ctx;
	struct fstrm_iothr_queue *ioq = fstrm_iothr_get_input_queue_idx(iothread, qdata->param->thread_id);

	/* Unless we want to measure the time it takes to process each query,
	 * we can treat Q/R times the same. */
	struct timeval tv;
	gettimeofday(&tv, NULL);

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
	ret = dt_message_fill(&msg, msgtype,
	                      (const struct sockaddr *)qdata->param->remote,
	                      NULL, /* todo: fill me! */
	                      protocol,
	                      pkt->wire, pkt->size, &tv, &tv);
	if (ret != KNOT_EOK) {
		return KNOT_STATE_FAIL;
	}
	Dnstap__Dnstap dnstap = DNSTAP__DNSTAP__INIT;
	dnstap.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dnstap.message = (Dnstap__Message *)&msg;

	/* Pack the message. */
	uint8_t *frame = NULL;
	size_t size = 0;
	dt_pack(&dnstap, &frame, &size);
	if (frame == NULL) {
		return KNOT_STATE_FAIL;
	}

	/* Submit a request. */
	fstrm_res res = fstrm_iothr_submit(iothread, ioq, frame, size,
	                                   fstrm_free_wrapper, NULL);
	if (res != fstrm_res_success) {
		free(frame);
		state = KNOT_STATE_FAIL;
	}

	return state;
}

/*! \brief Submit message. */
static int dnstap_message_log(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return KNOT_STATE_FAIL;
	}

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
	fstrm_writer_options_add_content_type(wopt,
		(const uint8_t *) DNSTAP_CONTENT_TYPE,
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
	fstrm_writer_options_add_content_type(wopt,
		(const uint8_t *) DNSTAP_CONTENT_TYPE,
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

int dnstap_load(struct query_plan *plan, struct query_module *self,
                const knot_dname_t *zone)
{
	if (plan == NULL || self == NULL) {
		return KNOT_EINVAL;
	}

	conf_val_t val = conf_mod_get(self->config, MOD_SINK, self->id);
	const char *sink = conf_str(&val);

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
	struct fstrm_iothr* iothread = fstrm_iothr_init(opt, &writer);
	fstrm_iothr_options_destroy(&opt);

	if (iothread == NULL) {
		fstrm_writer_destroy(&writer);
		goto fail;
	}

	self->ctx = iothread;

	/* Hook to the query plan. */
	query_plan_step(plan, QPLAN_BEGIN, dnstap_message_log, self->ctx);
	query_plan_step(plan, QPLAN_END, dnstap_message_log, self->ctx);

	return KNOT_EOK;
fail:
	MODULE_ERR(C_MOD_DNSTAP, "failed to init sink '%s'", sink);
	return KNOT_ENOMEM;
}

int dnstap_unload(struct query_module *self)
{
	if (self == NULL) {
		return KNOT_EINVAL;
	}

	struct fstrm_iothr* iothread = self->ctx;
	fstrm_iothr_destroy(&iothread);
	return KNOT_EOK;
}
