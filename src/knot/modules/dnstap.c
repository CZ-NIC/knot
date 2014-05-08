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
#include "common/descriptor.h"

/* Defines. */
#define MODULE_ERR(msg...) log_zone_error("Module 'dnstap': " msg)

static int dnstap_query_log(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return NS_PROC_FAIL;
	}

	char *qname = knot_dname_to_str(knot_pkt_qname(pkt));
	MODULE_ERR("query_log: %s\n", qname);
	free(qname);

	return state;
}

static int dnstap_answer_log(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return NS_PROC_FAIL;
	}

	char *qname = knot_dname_to_str(knot_pkt_qname(pkt));
	MODULE_ERR("answer_log: %s (%u ancount)\n", qname, knot_wire_get_ancount(pkt->wire));
	free(qname);

	return state;
}

int dnstap_load(struct query_plan *plan, struct query_module *self)
{

	/* Save in query module, it takes ownership from now on. */
	self->ctx = 0x1;

	query_plan_step(plan, QPLAN_BEGIN, dnstap_query_log, self->ctx);
	query_plan_step(plan, QPLAN_END, dnstap_answer_log, self->ctx);

	return KNOT_EOK;
}

int dnstap_unload(struct query_module *self)
{
	return KNOT_EOK;
}
