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

#define MOD_PROTOCOL	"\x10""request-protocol"
#define MOD_OPERATION	"\x10""server-operation"
#define MOD_REQ_BYTES	"\x0D""request-bytes"
#define MOD_RESP_BYTES	"\x0E""response-bytes"
#define MOD_EDNS	"\x0D""edns-presence"
#define MOD_FLAG	"\x0D""flag-presence"
#define MOD_RCODE	"\x0D""response-code"
#define MOD_REQ_EOPT	"\x13""request-edns-option"
#define MOD_RESP_EOPT	"\x14""response-edns-option"
#define MOD_NODATA	"\x0C""reply-nodata"
#define MOD_QTYPE	"\x0A""query-type"
#define MOD_QSIZE	"\x0A""query-size"
#define MOD_RSIZE	"\x0A""reply-size"

#define OTHER		"other"

const yp_item_t probe_conf[] = {
	{ MOD_PROTOCOL,   YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_OPERATION,  YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_REQ_BYTES,  YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_RESP_BYTES, YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_EDNS,       YP_TBOOL, YP_VNONE },
	{ MOD_FLAG,       YP_TBOOL, YP_VNONE },
	{ MOD_RCODE,      YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_REQ_EOPT,   YP_TBOOL, YP_VNONE },
	{ MOD_RESP_EOPT,  YP_TBOOL, YP_VNONE },
	{ MOD_NODATA,     YP_TBOOL, YP_VNONE },
	{ MOD_QTYPE,      YP_TBOOL, YP_VNONE },
	{ MOD_QSIZE,      YP_TBOOL, YP_VNONE },
	{ MOD_RSIZE,      YP_TBOOL, YP_VNONE },
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

// enum {
// 	OPERATION_QUERY = 0,
// 	OPERATION_UPDATE,
// 	OPERATION_NOTIFY,
// 	OPERATION_AXFR,
// 	OPERATION_IXFR,
// 	OPERATION_INVALID,
// 	OPERATION__COUNT
// };

// static char *operation_to_str(uint32_t idx, uint32_t count)
// {
// 	switch (idx) {
// 	case OPERATION_QUERY:   return strdup("query");
// 	case OPERATION_UPDATE:  return strdup("update");
// 	case OPERATION_NOTIFY:  return strdup("notify");
// 	case OPERATION_AXFR:    return strdup("axfr");
// 	case OPERATION_IXFR:    return strdup("ixfr");
// 	case OPERATION_INVALID: return strdup("invalid");
// 	default:                assert(0); return NULL;
// 	}
// }

// enum {
// 	PROTOCOL_UDP4 = 0,
// 	PROTOCOL_TCP4,
// 	PROTOCOL_UDP6,
// 	PROTOCOL_TCP6,
// 	PROTOCOL_UDP4_XDP,
// 	PROTOCOL_UDP6_XDP,
// 	PROTOCOL__COUNT
// };

// static char *protocol_to_str(uint32_t idx, uint32_t count)
// {
// 	switch (idx) {
// 	case PROTOCOL_UDP4:     return strdup("udp4");
// 	case PROTOCOL_TCP4:     return strdup("tcp4");
// 	case PROTOCOL_UDP6:     return strdup("udp6");
// 	case PROTOCOL_TCP6:     return strdup("tcp6");
// 	case PROTOCOL_UDP4_XDP: return strdup("udp4-xdp");
// 	case PROTOCOL_UDP6_XDP: return strdup("udp6-xdp");
// 	default:                assert(0); return NULL;
// 	}
// }

// enum {
// 	REQ_BYTES_QUERY = 0,
// 	REQ_BYTES_UPDATE,
// 	REQ_BYTES_OTHER,
// 	REQ_BYTES__COUNT
// };

// static char *req_bytes_to_str(uint32_t idx, uint32_t count)
// {
// 	switch (idx) {
// 	case REQ_BYTES_QUERY:  return strdup("query");
// 	case REQ_BYTES_UPDATE: return strdup("update");
// 	case REQ_BYTES_OTHER:  return strdup(OTHER);
// 	default:               assert(0); return NULL;
// 	}
// }

// enum {
// 	RESP_BYTES_REPLY = 0,
// 	RESP_BYTES_TRANSFER,
// 	RESP_BYTES_OTHER,
// 	RESP_BYTES__COUNT
// };

// static char *resp_bytes_to_str(uint32_t idx, uint32_t count)
// {
// 	switch (idx) {
// 	case RESP_BYTES_REPLY:    return strdup("reply");
// 	case RESP_BYTES_TRANSFER: return strdup("transfer");
// 	case RESP_BYTES_OTHER:    return strdup(OTHER);
// 	default:                  assert(0); return NULL;
// 	}
// }

// enum {
// 	EDNS_REQ = 0,
// 	EDNS_RESP,
// 	EDNS__COUNT
// };

// static char *edns_to_str(uint32_t idx, uint32_t count)
// {
// 	switch (idx) {
// 	case EDNS_REQ:  return strdup("request");
// 	case EDNS_RESP: return strdup("response");
// 	default:        assert(0); return NULL;
// 	}
// }

// enum {
// 	FLAG_DO = 0,
// 	FLAG_TC,
// 	FLAG__COUNT
// };

// static char *flag_to_str(uint32_t idx, uint32_t count)
// {
// 	switch (idx) {
// 	case FLAG_TC: return strdup("TC");
// 	case FLAG_DO: return strdup("DO");
// 	default:      assert(0); return NULL;
// 	}
// }

// enum {
// 	NODATA_A = 0,
// 	NODATA_AAAA,
// 	NODATA_OTHER,
// 	NODATA__COUNT
// };

// static char *nodata_to_str(uint32_t idx, uint32_t count)
// {
// 	switch (idx) {
// 	case NODATA_A:     return strdup("A");
// 	case NODATA_AAAA:  return strdup("AAAA");
// 	case NODATA_OTHER: return strdup(OTHER);
// 	default:           assert(0); return NULL;
// 	}
// }

#define RCODE_BADSIG	15 // Unassigned code internally used for BADSIG.
#define RCODE_OTHER	(KNOT_RCODE_BADCOOKIE + 1) // Other RCODES.

// static char *rcode_to_str(uint32_t idx, uint32_t count)
// {
// 	const knot_lookup_t *rcode = NULL;

// 	switch (idx) {
// 	case RCODE_BADSIG:
// 		rcode = knot_lookup_by_id(knot_tsig_rcode_names, KNOT_RCODE_BADSIG);
// 		break;
// 	case RCODE_OTHER:
// 		return strdup(OTHER);
// 	default:
// 		rcode = knot_lookup_by_id(knot_rcode_names, idx);
// 		break;
// 	}

// 	if (rcode != NULL) {
// 		return strdup(rcode->name);
// 	} else {
// 		return NULL;
// 	}
// }

#define EOPT_OTHER		(KNOT_EDNS_MAX_OPTION_CODE + 1)
#define req_eopt_to_str		eopt_to_str
#define resp_eopt_to_str	eopt_to_str

// static char *eopt_to_str(uint32_t idx, uint32_t count)
// {
// 	if (idx >= EOPT_OTHER) {
// 		return strdup(OTHER);
// 	}

// 	char str[32];
// 	if (knot_opt_code_to_string(idx, str, sizeof(str)) < 0) {
// 		return NULL;
// 	} else {
// 		return strdup(str);
// 	}
// }

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

// static char *qtype_to_str(uint32_t idx, uint32_t count)
// {
// 	if (idx == QTYPE_OTHER) {
// 		return strdup(OTHER);
// 	}

// 	uint16_t qtype;

// 	if (idx <= QTYPE_MAX1) {
// 		qtype = idx;
// 		assert(qtype >= QTYPE_MIN1 && qtype <= QTYPE_MAX1);
// 	} else if (idx <= QTYPE_MAX2 - QTYPE_SHIFT2) {
// 		qtype = idx + QTYPE_SHIFT2;
// 		assert(qtype >= QTYPE_MIN2 && qtype <= QTYPE_MAX2);
// 	} else {
// 		qtype = idx + QTYPE_SHIFT3;
// 		assert(qtype >= QTYPE_MIN3 && qtype <= QTYPE_MAX3);
// 	}

// 	char str[32];
// 	if (knot_rrtype_to_string(qtype, str, sizeof(str)) < 0) {
// 		return NULL;
// 	} else {
// 		return strdup(str);
// 	}
// }

#define BUCKET_SIZE	16
#define QSIZE_MAX_IDX	(288 / BUCKET_SIZE)
#define RSIZE_MAX_IDX	(4096 / BUCKET_SIZE)

// static char *size_to_str(uint32_t idx, uint32_t count)
// {
// 	char str[16];

// 	int ret;
// 	if (idx < count - 1) {
// 		ret = snprintf(str, sizeof(str), "%u-%u", idx * BUCKET_SIZE,
// 		               (idx + 1) * BUCKET_SIZE - 1);
// 	} else {
// 		ret = snprintf(str, sizeof(str), "%u-65535", idx * BUCKET_SIZE);
// 	}

// 	if (ret <= 0 || (size_t)ret >= sizeof(str)) {
// 		return NULL;
// 	} else {
// 		return strdup(str);
// 	}
// }

// static char *qsize_to_str(uint32_t idx, uint32_t count)
// {
// 	return size_to_str(idx, count);
// }

// static char *rsize_to_str(uint32_t idx, uint32_t count)
// {
// 	return size_to_str(idx, count);
// }

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

// static void incr_edns_option(knotd_mod_t *mod, unsigned thr_id, const knot_pkt_t *pkt, unsigned ctr_name)
// {
// 	if (!knot_pkt_has_edns(pkt)) {
// 		return;
// 	}

// 	knot_rdata_t *rdata = pkt->opt_rr->rrs.rdata;
// 	if (rdata == NULL || rdata->len == 0) {
// 		return;
// 	}

// 	wire_ctx_t wire = wire_ctx_init_const(rdata->data, rdata->len);
// 	while (wire_ctx_available(&wire) > 0) {
// 		uint16_t opt_code = wire_ctx_read_u16(&wire);
// 		uint16_t opt_len = wire_ctx_read_u16(&wire);
// 		wire_ctx_skip(&wire, opt_len);
// 		if (wire.error != KNOT_EOK) {
// 			break;
// 		}
// 		knotd_mod_stats_incr(mod, thr_id, ctr_name, MIN(opt_code, EOPT_OTHER), 1);
// 	}
// }

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
	memcpy(pkt->wire, d.dns_header, sizeof(d.dns_header));
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
