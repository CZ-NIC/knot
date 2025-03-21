/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>
#include <string.h>
#include <stdlib.h>

#include "libknot/libknot.h"
#include "knot/nameserver/query_module.h"

/* Universal processing stage. */
knotd_state_t state_visit(knotd_state_t state, knot_pkt_t *pkt, knotd_qdata_t *qdata,
                          knotd_mod_t *mod)
{
	/* Visit current state */
	bool *state_map = (bool *)mod;
	state_map[state] = true;

	return state + 1;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Create a map of expected steps. */
	bool state_map[KNOTD_STAGES] = { false };

	/* Prepare query plan. */
	struct query_plan *plan = query_plan_create();
	ok(plan != NULL, "query_plan: create");
	if (plan == NULL) {
		goto fatal;
	}

	/* Register all stage visits. */
	int ret = KNOT_EOK;
	for (unsigned stage = KNOTD_STAGE_PROTO_BEGIN; stage < KNOTD_STAGES; ++stage) {
		ret = query_plan_step(plan, stage, QUERY_HOOK_TYPE_GENERAL, state_visit, state_map);
		if (ret != KNOT_EOK) {
			break;
		}
	}
	is_int(KNOT_EOK, ret, "query_plan: planned all steps");

	/* Execute the plan. */
	int state = 0, next_state = 0;
	for (unsigned stage = KNOTD_STAGE_PROTO_BEGIN; stage < KNOTD_STAGES; ++stage) {
		struct query_step *step = NULL;
		WALK_LIST(step, plan->stage[stage]) {
			next_state = step->general_hook(state, NULL, NULL, step->ctx);
			if (next_state != state + 1) {
				break;
			}
			state = next_state;
		}
	}
	ok(state == KNOTD_STAGES, "query_plan: executed all steps");

	/* Verify if all steps executed their callback. */
	for (state = 0; state < KNOTD_STAGES; ++state) {
		if (state_map[state] == false) {
			break;
		}
	}
	ok(state == KNOTD_STAGES, "query_plan: executed all callbacks");

fatal:
	/* Free the query plan. */
	query_plan_free(plan);

	return 0;
}
