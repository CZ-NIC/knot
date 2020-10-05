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

#include "knot/include/module.h"

#include <stdio.h>

#include "contrib/sockaddr.h"

#define MOD_LEVEL	"\x05""level"

// TODO: almost copy-pasted from conf/schema.c
static const knot_lookup_t log_severities[] = {
	{ (LOG_CRIT),    "critical" },
	{ (LOG_ERR),     "error" },
	{ (LOG_WARNING), "warning" },
	{ (LOG_NOTICE),  "notice" },
	{ (LOG_INFO),    "info" },
	{ (LOG_DEBUG),   "debug" },
	{ 0, NULL }
};

const yp_item_t querylog_conf[] = {
	{ MOD_LEVEL,   YP_TOPT, YP_VOPT = { log_severities, 6 } },
	{ NULL }
};

typedef struct {
	int level;
} querylog_ctx_t;

static const char *query_type_str[] = { "invalid", "normal", "AXFR", "IXFR", "NOTIFY", "DDNS" };

static knotd_state_t querylog_process(knotd_state_t state, knot_pkt_t *pkt,
                                      knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	querylog_ctx_t *ctx = knotd_mod_ctx(mod);

	char qname[KNOT_DNAME_TXT_MAXLEN] = { 0 };
	char qtype[16] = { 0 };
	char addr_src[SOCKADDR_STRLEN] = { 0 };

	knot_dname_to_str(qname, knot_pkt_qname(pkt), sizeof(qname));
	knot_rrtype_to_string(knot_pkt_qtype(pkt), qtype, sizeof(qtype));
	sockaddr_tostr(addr_src, sizeof(addr_src), qdata->params->remote);

	knotd_mod_log(mod, ctx->level, "QUERY, %s, qname %s qtype %s from %s",
	              query_type_str[qdata->type], qname, qtype, addr_src);

	return state;
}

int querylog_load(knotd_mod_t *mod)
{
	querylog_ctx_t *ctx = calloc(1, sizeof(querylog_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	knotd_conf_t conf_level = knotd_conf_mod(mod, MOD_LEVEL);
	ctx->level = conf_level.single.integer;

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, querylog_process);
}

void querylog_unload(knotd_mod_t *mod)
{
	querylog_ctx_t *ctx = knotd_mod_ctx(mod);
	free(ctx);
}

KNOTD_MOD_API(querylog, KNOTD_MOD_FLAG_SCOPE_ANY,
              querylog_load, querylog_unload, querylog_conf, NULL);
