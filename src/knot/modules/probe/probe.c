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

#include "contrib/macros.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"
#include "knot/nameserver/xfr.h" // Dependency on qdata->extra!
#include "libknot/libknot.h"

#define MOD_PREFIX	"\x06""prefix"

#define OTHER		"other"

const yp_item_t probe_conf[] = {
	{ MOD_PREFIX,     YP_TSTR,  YP_VSTR  = { "/tmp/knot-probe-" } },
	{ NULL }
};

enum {
	CTR_PROTOCOL,
	CTR_OPERATION,
	CTR_REQ_BYTES,
	CTR_RESP_BYTES,
	CTR_EDNS,
	CTR_FLAG,
	CTR_RCODE,
	CTR_REQ_EOPT,
	CTR_RESP_EOPT,
	CTR_NODATA,
	CTR_QTYPE,
	CTR_QSIZE,
	CTR_RSIZE,
};


typedef struct {
	yp_name_t *conf_name;
	size_t conf_offset;
	uint32_t count;
	knotd_mod_idx_to_str_f fcn;
} ctr_desc_t;


#define RCODE_BADSIG	15 // Unassigned code internally used for BADSIG.
#define RCODE_OTHER	(KNOT_RCODE_BADCOOKIE + 1) // Other RCODES.

#define EOPT_OTHER		(KNOT_EDNS_MAX_OPTION_CODE + 1)
#define req_eopt_to_str		eopt_to_str
#define resp_eopt_to_str	eopt_to_str

enum {
	QTYPE_OTHER  =   0,
	QTYPE_MIN1   =   1,
	QTYPE_MAX1   =  65,
	QTYPE_MIN2   =  99,
	QTYPE_MAX2   = 110,
	QTYPE_MIN3   = 255,
	QTYPE_MAX3   = 260,
	QTYPE_SHIFT2 = QTYPE_MIN2 - QTYPE_MAX1 - 1,
	QTYPE_SHIFT3 = QTYPE_SHIFT2 + QTYPE_MIN3 - QTYPE_MAX2 - 1,
	QTYPE__COUNT = QTYPE_MAX3 - QTYPE_SHIFT3 + 1
};


#define BUCKET_SIZE	16
#define QSIZE_MAX_IDX	(288 / BUCKET_SIZE)
#define RSIZE_MAX_IDX	(4096 / BUCKET_SIZE)

// static const ctr_desc_t ctr_descs[] = {
 	#define item(macro, name, count) \
 		[CTR_##macro] = { MOD_##macro, offsetof(stats_t, name), (count), name##_to_str }
// 	item(PROTOCOL,   protocol,   PROTOCOL__COUNT),
// 	item(OPERATION,  operation,  OPERATION__COUNT),
// 	item(REQ_BYTES,  req_bytes,  REQ_BYTES__COUNT),
// 	item(RESP_BYTES, resp_bytes, RESP_BYTES__COUNT),
// 	item(EDNS,       edns,       EDNS__COUNT),
// 	item(FLAG,       flag,       FLAG__COUNT),
// 	item(RCODE,      rcode,      RCODE_OTHER + 1),
// 	item(REQ_EOPT,   req_eopt,   EOPT_OTHER + 1),
// 	item(RESP_EOPT,  resp_eopt,  EOPT_OTHER + 1),
// 	item(NODATA,     nodata,     NODATA__COUNT),
// 	item(QTYPE,      qtype,      QTYPE__COUNT),
// 	item(QSIZE,      qsize,      QSIZE_MAX_IDX + 1),
// 	item(RSIZE,      rsize,      RSIZE_MAX_IDX + 1),
// 	{ NULL }
// };

struct probe_ctx {
	knot_probe_channel_wo_t *probes;
	size_t probe_count;
};

static knotd_state_t transfer(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata);

	unsigned tid = qdata->params->thread_id;
	struct probe_ctx *p = knotd_mod_ctx(mod);
	knot_probe_channel_wo_t *probe = &(p->probes[tid % p->probe_count]);
	
	
	const knot_probe_datagram_t d = {
		.port_src = 12345,
		.port_dst = tid
	};
	memcpy(d.dns_header, pkt->wire, sizeof(d.dns_header));
	knot_probe_channel_send(probe, (uint8_t *)&d, sizeof(d), 0);

	return state;
}

int probe_load(knotd_mod_t *mod)
{
	struct probe_ctx *p = (struct probe_ctx *)malloc(sizeof(*p));
	p->probe_count = 10;
	p->probes = (knot_probe_channel_wo_t *)calloc(p->probe_count, sizeof(knot_probe_channel_wo_t));
	if (p->probes == NULL) {
		return KNOT_ENOMEM;
	}
	for (knot_probe_channel_wo_t *it = p->probes; it < &p->probes[p->probe_count]; ++it) {
		knot_probe_channel_wo_init(it, "/tmp/knot-probe-", (it - p->probes));
	}

	knotd_mod_ctx_set(mod, p);

	return knotd_mod_hook(mod, KNOTD_STAGE_END, transfer);
}

void probe_unload(knotd_mod_t *mod)
{
	struct probe_ctx *p = (knot_probe_channel_wo_t *)knotd_mod_ctx(mod);
	for (int i = 0; i < p->probe_count; ++i) {
		knot_probe_channel_close(&p->probes[i]);
	}
	free(p->probes);
	free(knotd_mod_ctx(mod));
	knotd_mod_ctx_set(mod, NULL);
}

KNOTD_MOD_API(probe, KNOTD_MOD_FLAG_SCOPE_GLOBAL | KNOTD_MOD_FLAG_OPT_CONF,
              probe_load, probe_unload, probe_conf, NULL);
