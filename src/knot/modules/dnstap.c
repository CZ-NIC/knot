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

#include "knot/modules/dnstap.h"
#include "knot/nameserver/query_module.h"
#include "knot/nameserver/process_query.h"
#include "dnstap/dnstap.pb-c.h"
#include "dnstap/writer.h"
#include "dnstap/message.h"
#include "dnstap/dnstap.h"
#include "common/descriptor.h"

/* Defines. */
#define MODULE_ERR(msg...) log_zone_error("Module 'dnstap': " msg)

static int log_message(int state, const knot_pkt_t *pkt, struct query_data *qdata, void *ctx, const Dnstap__Message__Type msgtype)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return NS_PROC_FAIL;
	}

	char *qname = knot_dname_to_str(knot_pkt_qname(pkt));
	MODULE_ERR("answer_log: %s (%u ancount)\n", qname, knot_wire_get_ancount(pkt->wire));
	free(qname);

	struct fstrm_iothr* iothread = ctx;
	struct fstrm_iothr_queue *ioq = fstrm_iothr_get_input_queue_idx(iothread, 0);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	Dnstap__Message msg;
	int ret = dt_message_fill(&msg, msgtype,
					(const struct sockaddr *)qdata->param->query_source, IPPROTO_UDP,
					pkt->wire, pkt->size, NULL, &tv);
	assert(ret == KNOT_EOK);

	/* deal with it later (ret) */
	Dnstap__Dnstap dnstap = DNSTAP__DNSTAP__INIT;
	dnstap.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dnstap.message = (Dnstap__Message *)&msg;
	uint8_t *frame = NULL;
	size_t size = 0;
	dt_pack(&dnstap, &frame, &size);
	assert(size > 0);
	assert(frame);
	/* return value */
	fstrm_res res = fstrm_iothr_submit(iothread, ioq, frame, size, fstrm_free_wrapper, NULL);
	if (res != fstrm_res_success) {
		free(frame);
		assert(0);
	}

	/* return value */

	return state;
}

static int dnstap_answer_log(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return NS_PROC_FAIL;
	}
	log_message(state, qdata->query, qdata, ctx, DNSTAP__MESSAGE__TYPE__AUTH_QUERY);
	log_message(state, pkt, qdata, ctx, DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE);
	return state;
}

int dnstap_load(struct query_plan *plan, struct query_module *self)
{

	/* Save in query module, it takes ownership from now on. */
	dt_writer_t *writer = dt_writer_create(self->param, "something");
	assert(writer);
	struct fstrm_iothr_options* opt = fstrm_iothr_options_init();
	assert(opt);
	fstrm_iothr_options_set_queue_model(opt, FSTRM_IOTHR_QUEUE_MODEL_MPSC);
	struct fstrm_iothr* iothread = fstrm_iothr_init(opt, &writer->fw);
	self->ctx = iothread;
	assert(iothread);

	query_plan_step(plan, QPLAN_END, dnstap_answer_log, self->ctx);

	return KNOT_EOK;
}

int dnstap_unload(struct query_module *self)
{
	struct fstrm_iothr* iothread = self->ctx;
	fstrm_iothr_destroy(&iothread);
	self->ctx = NULL;
	return KNOT_EOK;
}
