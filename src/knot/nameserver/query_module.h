/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "libknot/libknot.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/include/module.h"
#include "knot/server/server.h"
#include "contrib/ucw/lists.h"

#ifdef HAVE_ATOMIC
 #define ATOMIC_GET(src) __atomic_load_n(&(src), __ATOMIC_RELAXED)
#else
 #define ATOMIC_GET(src) (src)
#endif

#define KNOTD_STAGES (KNOTD_STAGE_END + 1)

typedef unsigned (*query_step_process_f)
	(unsigned state, knot_pkt_t *pkt, knotd_qdata_t *qdata, knotd_mod_t *mod);

/*! \brief Single processing step in query processing. */
struct query_step {
	node_t node;
	void *ctx;
	query_step_process_f process;
};

/*! Query plan represents a sequence of steps needed for query processing
 *  divided into several stages, where each stage represents a current response
 *  assembly phase, for example 'before processing', 'answer section' and so on.
 */
struct query_plan {
	list_t stage[KNOTD_STAGES];
};

/*! \brief Create an empty query plan. */
struct query_plan *query_plan_create(void);

/*! \brief Free query plan and all planned steps. */
void query_plan_free(struct query_plan *plan);

/*! \brief Plan another step for given stage. */
int query_plan_step(struct query_plan *plan, knotd_stage_t stage,
                    query_step_process_f process, void *ctx);

/*! \brief Open query module identified by name. */
knotd_mod_t *query_module_open(conf_t *conf, server_t *server, conf_mod_id_t *mod_id,
                               struct query_plan *plan, const knot_dname_t *zone);

/*! \brief Close query module. */
void query_module_close(knotd_mod_t *module);

/*! \brief Close and open existing query module. */
void query_module_reset(conf_t *conf, knotd_mod_t *module, struct query_plan *new_plan);

typedef char* (*mod_idx_to_str_f)(uint32_t idx, uint32_t count);

typedef struct {
	const char *name;
	mod_idx_to_str_f idx_to_str; // unused if count == 1
	uint32_t offset; // offset of counters in stats_vals[thread_id]
	uint32_t count;
} mod_ctr_t;

struct knotd_mod {
	node_t node;
	conf_t *config;
	server_t *server;
	conf_mod_id_t *id;
	struct query_plan *plan;
	const knot_dname_t *zone;
	const knotd_mod_api_t *api;
	kdnssec_ctx_t *dnssec;
	zone_keyset_t *keyset;
	zone_sign_ctx_t *sign_ctx;
	mod_ctr_t *stats_info;
	uint64_t **stats_vals;
	uint32_t stats_count;
	void *ctx;
};

void knotd_mod_stats_free(knotd_mod_t *mod);
