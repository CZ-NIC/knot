/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/include/module.h"

static knotd_in_state_t ecs_process(knotd_in_state_t state, knot_pkt_t *pkt,
                                    knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	if (qdata->ecs != NULL) {
		qdata->ecs->scope_len = qdata->ecs->source_len;
	}

	return state;
}

int ecs_load(knotd_mod_t *mod)
{
	return knotd_mod_in_hook(mod, KNOTD_STAGE_PREANSWER, ecs_process);
}

KNOTD_MOD_API(ecs, KNOTD_MOD_FLAG_SCOPE_ZONE | KNOTD_MOD_FLAG_OPT_CONF,
              ecs_load, NULL, NULL, NULL);
