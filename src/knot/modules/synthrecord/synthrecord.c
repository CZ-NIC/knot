/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/ctype.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"

#define MOD_NET		"\x07""network"
#define MOD_ORIGIN	"\x06""origin"
#define MOD_PREFIX	"\x06""prefix"
#define MOD_TTL		"\x03""ttl"
#define MOD_TYPE	"\x04""type"

/*! \brief Supported answer synthesis template types. */
enum synth_template_type {
	SYNTH_NULL    = 0,
	SYNTH_FORWARD = 1,
	SYNTH_REVERSE = 2
};

static const knot_lookup_t synthetic_types[] = {
	{ SYNTH_FORWARD, "forward" },
	{ SYNTH_REVERSE, "reverse" },
	{ 0, NULL }
};

int check_prefix(knotd_conf_check_args_t *args)
{
	if (strchr((const char *)args->data, '.') != NULL) {
		args->err_str = "dot '.' is not allowed";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

const yp_item_t synth_record_conf[] = {
	{ MOD_TYPE,   YP_TOPT,   YP_VOPT = { synthetic_types, SYNTH_NULL } },
	{ MOD_PREFIX, YP_TSTR,   YP_VSTR = { "" }, YP_FNONE, { check_prefix } },
	{ MOD_ORIGIN, YP_TDNAME, YP_VNONE },
	{ MOD_TTL,    YP_TINT,   YP_VINT = { 0, UINT32_MAX, 3600, YP_STIME } },
	{ MOD_NET,    YP_TNET,   YP_VNONE, YP_FMULTI },
	{ NULL }
};

int synth_record_conf_check(knotd_conf_check_args_t *args)
{
	// Check type.
	knotd_conf_t type = knotd_conf_check_item(args, MOD_TYPE);
	if (type.count == 0) {
		args->err_str = "no synthesis type specified";
		return KNOT_EINVAL;
	}

	// Check origin.
	knotd_conf_t origin = knotd_conf_check_item(args, MOD_ORIGIN);
	if (origin.count == 0 && type.single.option == SYNTH_REVERSE) {
		args->err_str = "no origin specified";
		return KNOT_EINVAL;
	}
	if (origin.count != 0 && type.single.option == SYNTH_FORWARD) {
		args->err_str = "origin not allowed with forward type";
		return KNOT_EINVAL;
	}

	// Check network subnet.
	knotd_conf_t net = knotd_conf_check_item(args, MOD_NET);
	if (net.count == 0) {
		args->err_str = "no network subnet specified";
		return KNOT_EINVAL;
	}
	knotd_conf_free(&net);

	return KNOT_EOK;
}

#define ARPA_ZONE_LABELS	2
#define IPV4_ADDR_LABELS	4
#define IPV6_ADDR_LABELS	32
#define IPV4_ARPA_DNAME		(uint8_t *)"\x07""in-addr""\x04""arpa"
#define IPV6_ARPA_DNAME		(uint8_t *)"\x03""ip6""\x04""arpa"

/*!
 * \brief Synthetic response template.
 */
typedef struct {
	struct sockaddr_storage addr;
	struct sockaddr_storage addr_max;
	int addr_mask;
} synth_templ_addr_t;

typedef struct {
	enum synth_template_type type;
	char *prefix;
	size_t prefix_len;
	char *zone;
	size_t zone_len;
	uint32_t ttl;
	size_t addr_count;
	synth_templ_addr_t *addr;
} synth_template_t;

/*! \brief Substitute all occurrences of given character. */
static void str_subst(char *str, size_t len, char from, char to)
{
	for (int i = 0; i < len; ++i) {
		if (str[i] == from) {
			str[i] = to;
		}
	}
}

/*! \brief Separator character for address family. */
static char str_separator(int addr_family)
{
	if (addr_family == AF_INET6) {
		return ':';
	}
	return '.';
}

/*! \brief Return true if query type is satisfied with provided address family. */
static bool query_satisfied_by_family(uint16_t qtype, int family)
{
	switch (qtype) {
	case KNOT_RRTYPE_A:    return family == AF_INET;
	case KNOT_RRTYPE_AAAA: return family == AF_INET6;
	case KNOT_RRTYPE_ANY:  return true;
	default:               return false;
	}
}

/*! \brief Parse address from reverse query QNAME and return address family. */
static int reverse_addr_parse(knotd_qdata_t *qdata, char *addr_str, int *addr_family)
{
	/* QNAME required format is [address].[subnet/zone]
	 * f.e.  [1.0...0].[h.g.f.e.0.0.0.0.d.c.b.a.ip6.arpa] represents
	 *       [abcd:0:efgh::1] */
	const knot_dname_t *label = qdata->name;
	const uint8_t *wire = qdata->query->wire;

	switch (knot_dname_labels(label, wire)) {
	case IPV4_ADDR_LABELS + ARPA_ZONE_LABELS:
		*addr_family = AF_INET;

		const knot_dname_t *label1 = label;
		const knot_dname_t *label2 = knot_wire_next_label(label1, wire);
		const knot_dname_t *label3 = knot_wire_next_label(label2, wire);
		const knot_dname_t *label4 = knot_wire_next_label(label3, wire);
		assert(label1 && label2 && label3 && label4);

		label = knot_wire_next_label(label4, wire);
		if (!knot_dname_is_equal(label, IPV4_ARPA_DNAME)) {
			return KNOT_EINVAL;
		}

		 // 255.255.255.255
		wire_ctx_t ctx = wire_ctx_init((uint8_t *)addr_str,
		                               IPV4_ADDR_LABELS * 3 + 3 + 1);
		wire_ctx_write(&ctx, label4 + 1, label4[0]);
		wire_ctx_write_u8(&ctx, '.');
		wire_ctx_write(&ctx, label3 + 1, label3[0]);
		wire_ctx_write_u8(&ctx, '.');
		wire_ctx_write(&ctx, label2 + 1, label2[0]);
		wire_ctx_write_u8(&ctx, '.');
		wire_ctx_write(&ctx, label1 + 1, label1[0]);
		wire_ctx_write_u8(&ctx, '\0');
		if (ctx.error != KNOT_EOK) {
			return ctx.error;
		}

		return KNOT_EOK;
	case IPV6_ADDR_LABELS + ARPA_ZONE_LABELS:
		*addr_family = AF_INET6;

		// 1-char labels + separators.
		const int addr_len = IPV6_ADDR_LABELS + 7;
		for (int i = 1; i <= addr_len; i++) {
			if (i % 5 == 0) {
				addr_str[addr_len - i] = ':';
			} else if (label[0] == 1) {
				addr_str[addr_len - i] = label[1];
				label = knot_wire_next_label(label, wire);
				assert(label);
			} else {
				return KNOT_EINVAL;
			}
		}
		addr_str[addr_len] = '\0';

		if (!knot_dname_is_equal(label, IPV6_ARPA_DNAME)) {
			return KNOT_EINVAL;
		}

		return KNOT_EOK;
	default:
		return KNOT_EINVAL;
	}
}

static int forward_addr_parse(knotd_qdata_t *qdata, const synth_template_t *tpl,
                              char *addr_str, int *addr_family)
{
	const knot_dname_t *label = qdata->name;

	// Check for prefix mismatch.
	if (label[0] <= tpl->prefix_len ||
	    memcmp(label + 1, tpl->prefix, tpl->prefix_len) != 0) {
		return KNOT_EINVAL;
	}

	// Copy address part.
	int addr_len = label[0] - tpl->prefix_len;
	memcpy(addr_str, label + 1 + tpl->prefix_len, addr_len);
	addr_str[addr_len] = '\0';

	// Determine query family: v6 if *-ABCD.zone.
	const char *last_octet = addr_str + addr_len;
	while (last_octet > addr_str && is_xdigit(*--last_octet));
	*addr_family = (last_octet + 5 == addr_str + addr_len ? AF_INET6 : AF_INET);

	// Restore correct address format.
	const char sep = str_separator(*addr_family);
	str_subst(addr_str, addr_len, '-', sep);

	return KNOT_EOK;
}

static int addr_parse(knotd_qdata_t *qdata, const synth_template_t *tpl, char *addr_str,
                      int *addr_family)
{
	switch (tpl->type) {
	case SYNTH_REVERSE: return reverse_addr_parse(qdata, addr_str, addr_family);
	case SYNTH_FORWARD: return forward_addr_parse(qdata, tpl, addr_str, addr_family);
	default:            return KNOT_EINVAL;
	}
}

static knot_dname_t *synth_ptrname(uint8_t *out, const char *addr_str,
                                   const synth_template_t *tpl, int addr_family)
{
	char ptrname[KNOT_DNAME_TXT_MAXLEN];
	int addr_len = strlen(addr_str);
	const char sep = str_separator(addr_family);

	// PTR right-hand value is [prefix][address][zone]
	wire_ctx_t ctx = wire_ctx_init((uint8_t *)ptrname, sizeof(ptrname));
	wire_ctx_write(&ctx, tpl->prefix, tpl->prefix_len);
	wire_ctx_write(&ctx, addr_str, addr_len);
	wire_ctx_write_u8(&ctx, '.');
	wire_ctx_write(&ctx, tpl->zone, tpl->zone_len);
	wire_ctx_write_u8(&ctx, '\0');
	if (ctx.error != KNOT_EOK) {
		return NULL;
	}

	// Substitute address separator by '-'.
	str_subst(ptrname + tpl->prefix_len, addr_len, sep, '-');

	// Convert to domain name.
	return knot_dname_from_str(out, ptrname, KNOT_DNAME_MAXLEN);
}

static int reverse_rr(char *addr_str, const synth_template_t *tpl, knot_pkt_t *pkt,
                      knot_rrset_t *rr, int addr_family)
{
	// Synthetize PTR record data.
	uint8_t ptrname[KNOT_DNAME_MAXLEN];
	if (synth_ptrname(ptrname, addr_str, tpl, addr_family) == NULL) {
		return KNOT_EINVAL;
	}

	rr->type = KNOT_RRTYPE_PTR;
	knot_rrset_add_rdata(rr, ptrname, knot_dname_size(ptrname), &pkt->mm);

	return KNOT_EOK;
}

static int forward_rr(char *addr_str, const synth_template_t *tpl, knot_pkt_t *pkt,
                      knot_rrset_t *rr, int addr_family)
{
	struct sockaddr_storage query_addr;
	sockaddr_set(&query_addr, addr_family, addr_str, 0);

	// Specify address type and data.
	if (addr_family == AF_INET6) {
		rr->type = KNOT_RRTYPE_AAAA;
		const struct sockaddr_in6* ip = (const struct sockaddr_in6*)&query_addr;
		knot_rrset_add_rdata(rr, (const uint8_t *)&ip->sin6_addr,
		                     sizeof(struct in6_addr), &pkt->mm);
	} else if (addr_family == AF_INET) {
		rr->type = KNOT_RRTYPE_A;
		const struct sockaddr_in* ip = (const struct sockaddr_in*)&query_addr;
		knot_rrset_add_rdata(rr, (const uint8_t *)&ip->sin_addr,
		                     sizeof(struct in_addr), &pkt->mm);
	} else {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static knot_rrset_t *synth_rr(char *addr_str, const synth_template_t *tpl, knot_pkt_t *pkt,
                              knotd_qdata_t *qdata, int addr_family)
{
	knot_rrset_t *rr = knot_rrset_new(qdata->name, 0, KNOT_CLASS_IN, tpl->ttl,
	                                  &pkt->mm);
	if (rr == NULL) {
		return NULL;
	}

	// Fill in the specific data.
	int ret = KNOT_ERROR;
	switch (tpl->type) {
	case SYNTH_REVERSE: ret = reverse_rr(addr_str, tpl, pkt, rr, addr_family); break;
	case SYNTH_FORWARD: ret = forward_rr(addr_str, tpl, pkt, rr, addr_family); break;
	default: break;
	}

	if (ret != KNOT_EOK) {
		knot_rrset_free(rr, &pkt->mm);
		return NULL;
	}

	return rr;
}

/*! \brief Check if query fits the template requirements. */
static knotd_in_state_t template_match(knotd_in_state_t state, const synth_template_t *tpl,
                                       knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	int provided_af = AF_UNSPEC;
	struct sockaddr_storage query_addr;
	char addr_str[SOCKADDR_STRLEN];
	assert(SOCKADDR_STRLEN > KNOT_DNAME_MAXLABELLEN);

	// Parse address from query name.
	if (addr_parse(qdata, tpl, addr_str, &provided_af) != KNOT_EOK ||
	    sockaddr_set(&query_addr, provided_af, addr_str, 0) != KNOT_EOK) {
		return state;
	}

	// Try all available addresses.
	int i;
	for (i = 0; i < tpl->addr_count; i++) {
		if (tpl->addr[i].addr_max.ss_family == AF_UNSPEC) {
			if (sockaddr_net_match((struct sockaddr *)&query_addr,
			                       (struct sockaddr *)&tpl->addr[i].addr,
			                       tpl->addr[i].addr_mask)) {
				break;
			}
		} else {
			if (sockaddr_range_match((struct sockaddr *)&query_addr,
			                         (struct sockaddr *)&tpl->addr[i].addr,
			                         (struct sockaddr *)&tpl->addr[i].addr_max)) {
				break;
			}
		}
	}
	if (i >= tpl->addr_count) {
		return state;
	}

	// Check if the request is for an available query type.
	uint16_t qtype = knot_pkt_qtype(qdata->query);
	switch (tpl->type) {
	case SYNTH_FORWARD:
		if (!query_satisfied_by_family(qtype, provided_af)) {
			qdata->rcode = KNOT_RCODE_NOERROR;
			return KNOTD_IN_STATE_NODATA;
		}
		break;
	case SYNTH_REVERSE:
		if (qtype != KNOT_RRTYPE_PTR && qtype != KNOT_RRTYPE_ANY) {
			qdata->rcode = KNOT_RCODE_NOERROR;
			return KNOTD_IN_STATE_NODATA;
		}
		break;
	default:
		return state;
	}

	// Synthetise record from template.
	knot_rrset_t *rr = synth_rr(addr_str, tpl, pkt, qdata, provided_af);
	if (rr == NULL) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return KNOTD_IN_STATE_ERROR;
	}

	// Insert synthetic response into packet.
	if (knot_pkt_put(pkt, 0, rr, KNOT_PF_FREE) != KNOT_EOK) {
		return KNOTD_IN_STATE_ERROR;
	}

	// Authoritative response.
	knot_wire_set_aa(pkt->wire);

	return KNOTD_IN_STATE_HIT;
}

static knotd_in_state_t solve_synth_record(knotd_in_state_t state, knot_pkt_t *pkt,
                                           knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	// Applicable when search in zone fails.
	if (state != KNOTD_IN_STATE_MISS) {
		return state;
	}

	// Check if template fits.
	return template_match(state, knotd_mod_ctx(mod), pkt, qdata);
}

int synth_record_load(knotd_mod_t *mod)
{
	// Create synthesis template.
	synth_template_t *tpl = calloc(1, sizeof(*tpl));
	if (tpl == NULL) {
		return KNOT_ENOMEM;
	}

	// Set type.
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_TYPE);
	tpl->type = conf.single.option;

	/* Set prefix. */
	conf = knotd_conf_mod(mod, MOD_PREFIX);
	tpl->prefix = strdup(conf.single.string);
	tpl->prefix_len = strlen(tpl->prefix);

	// Set origin if generating reverse record.
	if (tpl->type == SYNTH_REVERSE) {
		conf = knotd_conf_mod(mod, MOD_ORIGIN);
		tpl->zone = knot_dname_to_str_alloc(conf.single.dname);
		if (tpl->zone == NULL) {
			free(tpl->prefix);
			free(tpl);
			return KNOT_ENOMEM;
		}
		tpl->zone_len = strlen(tpl->zone);
	}

	// Set ttl.
	conf = knotd_conf_mod(mod, MOD_TTL);
	tpl->ttl = conf.single.integer;

	// Set address.
	conf = knotd_conf_mod(mod, MOD_NET);
	tpl->addr_count = conf.count;
	tpl->addr = calloc(conf.count, sizeof(*tpl->addr));
	if (tpl->addr == NULL) {
		knotd_conf_free(&conf);
		free(tpl->zone);
		free(tpl->prefix);
		free(tpl);
		return KNOT_ENOMEM;
	}
	for (size_t i = 0; i < conf.count; i++) {
		tpl->addr[i].addr = conf.multi[i].addr;
		tpl->addr[i].addr_max = conf.multi[i].addr_max;
		tpl->addr[i].addr_mask = conf.multi[i].addr_mask;
	}
	knotd_conf_free(&conf);

	knotd_mod_ctx_set(mod, tpl);

	return knotd_mod_in_hook(mod, KNOTD_STAGE_ANSWER, solve_synth_record);
}

void synth_record_unload(knotd_mod_t *mod)
{
	synth_template_t *tpl = knotd_mod_ctx(mod);

	free(tpl->addr);
	free(tpl->zone);
	free(tpl->prefix);
	free(tpl);
}

KNOTD_MOD_API(synthrecord, KNOTD_MOD_FLAG_SCOPE_ZONE,
              synth_record_load, synth_record_unload, synth_record_conf,
              synth_record_conf_check);
