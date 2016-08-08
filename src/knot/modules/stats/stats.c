/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/mempattern.h"
#include "libknot/libknot.h"
#include "knot/modules/stats/stats.h"
#include "knot/nameserver/axfr.h"

#define MOD_PROTOCOL	"\x10""request-protocol"
#define MOD_OPERATION	"\x10""server-operation"
#define MOD_REQ_BYTES	"\x0D""request-bytes"
#define MOD_RESP_BYTES	"\x0E""response-bytes"
#define MOD_EDNS	"\x0D""edns-presence"
#define MOD_FLAG	"\x0D""flag-presence"
#define MOD_RCODE	"\x0D""response-code"
#define MOD_NODATA	"\x0C""reply-nodata"
#define MOD_QTYPE	"\x0A""query-type"
#define MOD_QSIZE	"\x0A""query-size"
#define MOD_RSIZE	"\x0A""reply-size"

#define OTHER		"other"

const yp_item_t scheme_mod_stats[] = {
	{ C_ID,           YP_TSTR,  YP_VNONE },
	{ MOD_PROTOCOL,   YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_OPERATION,  YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_REQ_BYTES,  YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_RESP_BYTES, YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_EDNS,       YP_TBOOL, YP_VNONE },
	{ MOD_FLAG,       YP_TBOOL, YP_VNONE },
	{ MOD_RCODE,      YP_TBOOL, YP_VBOOL = { true } },
	{ MOD_NODATA,     YP_TBOOL, YP_VNONE },
	{ MOD_QTYPE,      YP_TBOOL, YP_VNONE },
	{ MOD_QSIZE,      YP_TBOOL, YP_VNONE },
	{ MOD_RSIZE,      YP_TBOOL, YP_VNONE },
	{ C_COMMENT,      YP_TSTR,  YP_VNONE },
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
	CTR_NODATA,
	CTR_QTYPE,
	CTR_QSIZE,
	CTR_RSIZE,
};

typedef struct {
	mod_ctr_t *counters;
	bool protocol;
	bool operation;
	bool req_bytes;
	bool resp_bytes;
	bool edns;
	bool flag;
	bool rcode;
	bool nodata;
	bool qtype;
	bool qsize;
	bool rsize;
} stats_t;

typedef struct {
	yp_name_t *conf_name;
	size_t conf_offset;
	uint32_t count;
	mod_idx_to_str_f fcn;
} ctr_desc_t;

enum {
	OPERATION_QUERY = 0,
	OPERATION_UPDATE,
	OPERATION_NOTIFY,
	OPERATION_AXFR,
	OPERATION_IXFR,
	OPERATION_INVALID,
	OPERATION__COUNT
};

static char *operation_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case OPERATION_QUERY:   return strdup("query");
	case OPERATION_UPDATE:  return strdup("update");
	case OPERATION_NOTIFY:  return strdup("notify");
	case OPERATION_AXFR:    return strdup("axfr");
	case OPERATION_IXFR:    return strdup("ixfr");
	case OPERATION_INVALID: return strdup("invalid");
	default:                assert(0); return NULL;
	}
}

enum {
	PROTOCOL_UDP4 = 0,
	PROTOCOL_TCP4,
	PROTOCOL_UDP6,
	PROTOCOL_TCP6,
	PROTOCOL__COUNT
};

static char *protocol_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case PROTOCOL_UDP4: return strdup("udp4");
	case PROTOCOL_TCP4: return strdup("tcp4");
	case PROTOCOL_UDP6: return strdup("udp6");
	case PROTOCOL_TCP6: return strdup("tcp6");
	default:            assert(0); return NULL;
	}
}

enum {
	REQ_BYTES_QUERY = 0,
	REQ_BYTES_UPDATE,
	REQ_BYTES_OTHER,
	REQ_BYTES__COUNT
};

static char *req_bytes_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case REQ_BYTES_QUERY:  return strdup("query");
	case REQ_BYTES_UPDATE: return strdup("update");
	case REQ_BYTES_OTHER:  return strdup(OTHER);
	default:               assert(0); return NULL;
	}
}

enum {
	RESP_BYTES_REPLY = 0,
	RESP_BYTES_TRANSFER,
	RESP_BYTES_OTHER,
	RESP_BYTES__COUNT
};

static char *resp_bytes_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case RESP_BYTES_REPLY:    return strdup("reply");
	case RESP_BYTES_TRANSFER: return strdup("transfer");
	case RESP_BYTES_OTHER:    return strdup(OTHER);
	default:                  assert(0); return NULL;
	}
}

enum {
	EDNS_REQ = 0,
	EDNS_RESP,
	EDNS__COUNT
};

static char *edns_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case EDNS_REQ:  return strdup("request");
	case EDNS_RESP: return strdup("response");
	default:        assert(0); return NULL;
	}
}

enum {
	FLAG_DO = 0,
	FLAG_TC,
	FLAG__COUNT
};

static char *flag_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case FLAG_TC: return strdup("TC");
	case FLAG_DO: return strdup("DO");
	default:      assert(0); return NULL;
	}
}

enum {
	NODATA_A = 0,
	NODATA_AAAA,
	NODATA_OTHER,
	NODATA__COUNT
};

static char *nodata_to_str(uint32_t idx, uint32_t count)
{
	switch (idx) {
	case NODATA_A:     return strdup("A");
	case NODATA_AAAA:  return strdup("AAAA");
	case NODATA_OTHER: return strdup(OTHER);
	default:           assert(0); return NULL;
	}
}

#define RCODE_BADSIG	15 // Unassigned code internally used for BADSIG.
#define RCODE_OTHER	(KNOT_RCODE_BADCOOKIE + 1) // Other RCODES.

static char *rcode_to_str(uint32_t idx, uint32_t count)
{
	const knot_lookup_t *rcode = NULL;

	switch (idx) {
	case RCODE_BADSIG:
		rcode = knot_lookup_by_id(knot_tsig_rcode_names, KNOT_RCODE_BADSIG);
		break;
	case RCODE_OTHER:
		return strdup(OTHER);
	default:
		rcode = knot_lookup_by_id(knot_rcode_names, idx);
		break;
	}

	if (rcode != NULL) {
		return strdup(rcode->name);
	} else {
		return NULL;
	}
}

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

static char *qtype_to_str(uint32_t idx, uint32_t count)
{
	if (idx == QTYPE_OTHER) {
		return strdup(OTHER);
	}

	uint16_t qtype;

	if (idx <= QTYPE_MAX1) {
		qtype = idx;
		assert(qtype >= QTYPE_MIN1 && qtype <= QTYPE_MAX1);
	} else if (idx <= QTYPE_MAX2 - QTYPE_SHIFT2) {
		qtype = idx + QTYPE_SHIFT2;
		assert(qtype >= QTYPE_MIN2 && qtype <= QTYPE_MAX2);
	} else {
		qtype = idx + QTYPE_SHIFT3;
		assert(qtype >= QTYPE_MIN3 && qtype <= QTYPE_MAX3);
	}

	char str[32];
	if (knot_rrtype_to_string(qtype, str, sizeof(str)) < 0) {
		return NULL;
	} else {
		return strdup(str);
	}
}

#define BUCKET_SIZE	16

static char *size_to_str(uint32_t idx, uint32_t count)
{
	char str[16];

	int ret;
	if (idx < count - 1) {
		ret = snprintf(str, sizeof(str), "%u-%u", idx * BUCKET_SIZE,
		               (idx + 1) * BUCKET_SIZE - 1);
	} else {
		ret = snprintf(str, sizeof(str), "%u-65535", idx * BUCKET_SIZE);
	}

	if (ret <= 0 || (size_t)ret >= sizeof(str)) {
		return NULL;
	} else {
		return strdup(str);
	}
}

static char *qsize_to_str(uint32_t idx, uint32_t count) {
	return size_to_str(idx, count);
}

static char *rsize_to_str(uint32_t idx, uint32_t count) {
	return size_to_str(idx, count);
}

static const ctr_desc_t ctr_descs[] = {
	#define item(macro, name, count) \
		[CTR_##macro] = { MOD_##macro, offsetof(stats_t, name), (count), name##_to_str }
	item(PROTOCOL,   protocol,   PROTOCOL__COUNT),
	item(OPERATION,  operation,  OPERATION__COUNT),
	item(REQ_BYTES,  req_bytes,  REQ_BYTES__COUNT),
	item(RESP_BYTES, resp_bytes, RESP_BYTES__COUNT),
	item(EDNS,       edns,       EDNS__COUNT),
	item(FLAG,       flag,       FLAG__COUNT),
	item(RCODE,      rcode,      RCODE_OTHER + 1),
	item(NODATA,     nodata,     NODATA__COUNT),
	item(QTYPE,      qtype,      QTYPE__COUNT),
	item(QSIZE,      qsize,      288 / BUCKET_SIZE + 1),
	item(RSIZE,      rsize,      4096 / BUCKET_SIZE + 1),
	{ NULL }
};

static int update_counters(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	assert(pkt && qdata && ctx);

	stats_t *stats = ctx;

	uint16_t operation;
	unsigned xfr_packets = 0;

	// Get the server operation.
	switch (qdata->packet_type) {
	case KNOT_QUERY_NORMAL:
		operation = OPERATION_QUERY;
		break;
	case KNOT_QUERY_UPDATE:
		operation = OPERATION_UPDATE;
		break;
	case KNOT_QUERY_NOTIFY:
		operation = OPERATION_NOTIFY;
		break;
	case KNOT_QUERY_AXFR:
		operation = OPERATION_AXFR;
		if (qdata->ext != NULL) {
			xfr_packets = ((struct xfr_proc *)qdata->ext)->npkts;
		}
		break;
	case KNOT_QUERY_IXFR:
		operation = OPERATION_IXFR;
		if (qdata->ext != NULL) {
			xfr_packets = ((struct xfr_proc *)qdata->ext)->npkts;
		}
		break;
	default:
		operation = OPERATION_INVALID;
		break;
	}

	// Count request bytes.
	if (stats->req_bytes) {
		switch (operation) {
		case OPERATION_QUERY:
			mod_ctrs_incr(stats->counters, CTR_REQ_BYTES,
			              REQ_BYTES_QUERY, qdata->query->size);
			break;
		case OPERATION_UPDATE:
			mod_ctrs_incr(stats->counters, CTR_REQ_BYTES,
			              REQ_BYTES_UPDATE, qdata->query->size);
			break;
		default:
			if (xfr_packets <= 1) {
				mod_ctrs_incr(stats->counters, CTR_REQ_BYTES,
				              REQ_BYTES_OTHER, qdata->query->size);
			}
			break;
		}
	}

	// Count response bytes.
	if (stats->resp_bytes) {
		switch (operation) {
		case OPERATION_QUERY:
			mod_ctrs_incr(stats->counters, CTR_RESP_BYTES,
			              RESP_BYTES_REPLY, pkt->size);
			break;
		case OPERATION_AXFR:
		case OPERATION_IXFR:
			mod_ctrs_incr(stats->counters, CTR_RESP_BYTES,
			              RESP_BYTES_TRANSFER, pkt->size);
			break;
		default:
			mod_ctrs_incr(stats->counters, CTR_RESP_BYTES,
			              RESP_BYTES_OTHER, pkt->size);
			break;
		}
	}

	// Get the extended response code.
	uint16_t rcode = qdata->rcode;
	if (qdata->rcode_tsig != KNOT_RCODE_NOERROR) {
		rcode = qdata->rcode_tsig;
	}

	// Count the response code.
	if (stats->rcode && pkt->size > 0) {
		if (xfr_packets <= 1 || rcode != KNOT_RCODE_NOERROR) {
			if (xfr_packets > 1) {
				assert(rcode != KNOT_RCODE_NOERROR);
				// Ignore the leading XFR message NOERROR.
				mod_ctrs_decr(stats->counters, CTR_RCODE,
				              KNOT_RCODE_NOERROR, 1);
			}

			if (qdata->rcode_tsig == KNOT_RCODE_BADSIG) {
				mod_ctrs_incr(stats->counters, CTR_RCODE,
				              RCODE_BADSIG, 1);
			} else {
				mod_ctrs_incr(stats->counters, CTR_RCODE,
				              rcode, 1);
			}
		}
	}

	// Return if non-first transfer message.
	if (xfr_packets > 1) {
		return state;
	}

	// Count the server opearation.
	if (stats->operation) {
		mod_ctrs_incr(stats->counters, CTR_OPERATION, operation, 1);
	}

	// Count the request protocol.
	if (stats->protocol) {
		if (qdata->param->remote->ss_family == AF_INET) {
			if (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) {
				mod_ctrs_incr(stats->counters, CTR_PROTOCOL,
				              PROTOCOL_UDP4, 1);
			} else {
				mod_ctrs_incr(stats->counters, CTR_PROTOCOL,
				              PROTOCOL_TCP4, 1);
			}
		} else {
			if (qdata->param->proc_flags & NS_QUERY_LIMIT_SIZE) {
				mod_ctrs_incr(stats->counters, CTR_PROTOCOL,
				              PROTOCOL_UDP6, 1);
			} else {
				mod_ctrs_incr(stats->counters, CTR_PROTOCOL,
				              PROTOCOL_TCP6, 1);
			}
		}
	}

	// Count EDNS occurrences.
	if (stats->edns) {
		if (qdata->query->opt_rr != NULL) {
			mod_ctrs_incr(stats->counters, CTR_EDNS, EDNS_REQ, 1);
		}
		if (pkt->opt_rr != NULL && pkt->size > 0) {
			mod_ctrs_incr(stats->counters, CTR_EDNS, EDNS_RESP, 1);
		}
	}

	// Count interesting message header flags.
	if (stats->flag) {
		if (pkt->size > 0 && knot_wire_get_tc(pkt->wire)) {
			mod_ctrs_incr(stats->counters, CTR_FLAG, FLAG_TC, 1);
		}
		if (pkt->opt_rr != NULL && knot_edns_do(pkt->opt_rr)) {
			mod_ctrs_incr(stats->counters, CTR_FLAG, FLAG_DO, 1);
		}
	}

	// Return if not query operation.
	if (operation != OPERATION_QUERY) {
		return state;
	}

	// Count NODATA reply (RFC 2308, Section 2.2).
	if (stats->nodata && rcode == KNOT_RCODE_NOERROR && pkt->size > 0 &&
	    knot_wire_get_ancount(pkt->wire) == 0 && !knot_wire_get_tc(pkt->wire) &&
	    (knot_wire_get_nscount(pkt->wire) == 0 ||
	     knot_pkt_rr(knot_pkt_section(pkt, KNOT_AUTHORITY), 0)->type == KNOT_RRTYPE_SOA)) {
		switch (knot_pkt_qtype(qdata->query)) {
		case KNOT_RRTYPE_A:
			mod_ctrs_incr(stats->counters, CTR_NODATA, NODATA_A, 1);
			break;
		case KNOT_RRTYPE_AAAA:
			mod_ctrs_incr(stats->counters, CTR_NODATA, NODATA_AAAA, 1);
			break;
		default:
			mod_ctrs_incr(stats->counters, CTR_NODATA, NODATA_OTHER, 1);
			break;
		}
	}

	// Count the query type.
	if (stats->qtype) {
		uint16_t qtype = knot_pkt_qtype(qdata->query);

		uint16_t idx;
		switch (qtype) {
		case QTYPE_MIN1 ... QTYPE_MAX1: idx = qtype; break;
		case QTYPE_MIN2 ... QTYPE_MAX2: idx = qtype - QTYPE_SHIFT2; break;
		case QTYPE_MIN3 ... QTYPE_MAX3: idx = qtype - QTYPE_SHIFT3; break;
		default:                        idx = QTYPE_OTHER; break;
		}

		mod_ctrs_incr(stats->counters, CTR_QTYPE, idx, 1);
	}

	// Count the query size.
	if (stats->qsize) {
		mod_ctrs_incr(stats->counters, CTR_QSIZE,
		              qdata->query->size / BUCKET_SIZE, 1);
	}

	// Count the reply size.
	if (stats->rsize && pkt->size > 0) {
		mod_ctrs_incr(stats->counters, CTR_RSIZE,
		              pkt->size / BUCKET_SIZE, 1);
	}

	return state;
}

int stats_load(struct query_plan *plan, struct query_module *self,
               const knot_dname_t *zone)
{
	assert(self);

	stats_t *stats = mm_alloc(self->mm, sizeof(*stats));
	if (stats == NULL) {
		return KNOT_ENOMEM;
	}

	for (const ctr_desc_t *desc = ctr_descs; desc->conf_name != NULL; desc++) {
		conf_val_t val = conf_mod_get(self->config, desc->conf_name, self->id);
		bool enabled = conf_bool(&val);

		// Initialize corresponding configuration item.
		*(bool *)((uint8_t *)stats + desc->conf_offset) = enabled;

		int ret = mod_stats_add(self, enabled ? desc->conf_name + 1 : NULL,
		                        desc->count, desc->fcn);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	stats->counters = self->stats;
	self->ctx = stats;

	return query_plan_step(plan, QPLAN_END, update_counters, self->ctx);
}

void stats_unload(struct query_module *self)
{
	assert(self);

	stats_t *stats = self->ctx;

	mm_free(self->mm, stats);
}
