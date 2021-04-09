/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "contrib/macros.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/wire_ctx.h"
#include "knot/include/module.h"

#define MOD_NET		"\x07""network"
#define MOD_ORIGIN	"\x06""origin"
#define MOD_PREFIX	"\x06""prefix"
#define MOD_TTL		"\x03""ttl"
#define MOD_TYPE	"\x04""type"
#define MOD_SHORT	"\x0d""reverse-short"

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
	{ MOD_SHORT,  YP_TBOOL,  YP_VBOOL = { true } },
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

	// Check reverse-short parameter is only for reverse synthrecord.
	knotd_conf_t reverse_short = knotd_conf_check_item(args, MOD_SHORT);
	if (reverse_short.count != 0 && type.single.option == SYNTH_FORWARD) {
		args->err_str = "reverse-short not allowed with forward type";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

#define ARPA_ZONE_LABELS	2
#define IPV4_ADDR_LABELS	4
#define IPV6_ADDR_LABELS	32
#define IPV4_ARPA_DNAME		(uint8_t *)"\x07""in-addr""\x04""arpa"
#define IPV6_ARPA_DNAME		(uint8_t *)"\x03""ip6""\x04""arpa"
#define IPV4_ARPA_LEN		14
#define IPV6_ARPA_LEN		10

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
	bool reverse_short;
} synth_template_t;

typedef union {
	uint32_t b32;
	uint8_t b4[4];
} addr_block_t;

/*! \brief Write one IPV4 address block without redundant leading zeros. */
static unsigned block_write(addr_block_t *block, char *addr_str)
{
	unsigned len = 0;

	if (block->b4[0] != '0') {
		addr_str[len++] = block->b4[0];
	}
	if (len > 0 || block->b4[1] != '0') {
		addr_str[len++] = block->b4[1];
	}
	if (len > 0 || block->b4[2] != '0') {
		addr_str[len++] = block->b4[2];
	}
	addr_str[len++] = block->b4[3];

	return len;
}

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
	return (addr_family == AF_INET6) ? ':' : '.';
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
static int reverse_addr_parse(knotd_qdata_t *qdata, const synth_template_t *tpl,
                              char *addr_str, int *addr_family, bool *parent)
{
	/* QNAME required format is [address].[subnet/zone]
	 * f.e.  [1.0...0].[h.g.f.e.0.0.0.0.d.c.b.a.ip6.arpa] represents
	 *       [abcd:0:efgh::1] */
	const knot_dname_t *label = qdata->name; // uncompressed name

	static const char ipv4_zero[] = "0.0.0.0";

	bool can_ipv4 = true;
	bool can_ipv6 = true;
	unsigned labels = 0;

	uint8_t buf4[16], *buf4_end = buf4 + sizeof(buf4), *buf4_pos = buf4_end;
	uint8_t buf6[32], *buf6_end = buf6 + sizeof(buf6), *buf6_pos = buf6_end;

	for ( ; labels < IPV6_ADDR_LABELS; labels++) {
		if (unlikely(*label == 0)) {
			return KNOT_EINVAL;
		}
		if (label[1] == 'i') {
			break;
		}
		if (labels < IPV4_ADDR_LABELS) {
			switch (*label) {
			case 1:
				assert(buf4 + 1 < buf4_pos && buf6 < buf6_pos);
				*--buf6_pos = label[1];
				*--buf4_pos = label[1];
				*--buf4_pos = '.';
				break;
			case 2:
			case 3:
				assert(buf4 + *label < buf4_pos);
				can_ipv6 = false;
				buf4_pos -= *label;
				memcpy(buf4_pos, label + 1, *label);
				*--buf4_pos = '.';
				break;
			default:
				return KNOT_EINVAL;
			}
		} else {
			can_ipv4 = false;
			if (!can_ipv6 || *label != 1) {
				return KNOT_EINVAL;
			}
			assert(buf6 < buf6_pos);
			*--buf6_pos = label[1];

		}
		label += *label + sizeof(*label);
	}

	if (can_ipv4 && knot_dname_is_equal(label, IPV4_ARPA_DNAME)) {
		*addr_family = AF_INET;
		*parent = (labels < IPV4_ADDR_LABELS);
		int buf4_overweight = (buf4_end - buf4_pos) - (2 * labels);
		assert(buf4_overweight >= 0);
		memcpy(addr_str + buf4_overweight, ipv4_zero, sizeof(ipv4_zero));
		if (labels > 0) {
			buf4_pos++; // skip leading '.'
			memcpy(addr_str, buf4_pos, buf4_end - buf4_pos);
		}
		return KNOT_EOK;
	} else if (can_ipv6 && knot_dname_is_equal(label, IPV6_ARPA_DNAME)) {
		*addr_family = AF_INET6;
		*parent = (labels < IPV6_ADDR_LABELS);

		addr_block_t blocks[8] = { { 0 } };
		int compr_start = -1, compr_end = -1;

		unsigned buf6_len = buf6_end - buf6_pos;
		memcpy(blocks, buf6_pos, buf6_len);
		memset(((uint8_t *)blocks) + buf6_len, 0x30, sizeof(blocks) - buf6_len);

		for (int i = 0; i < 8; i++) {
			addr_block_t *block = &blocks[i];

			/* The Unicode string MUST NOT contain "--" in the third and fourth
			   character positions and MUST NOT start or end with a "-".
			   So we will not compress first, second, and last address blocks
			   for simplicity. And we will not compress a single block.

			   i:             0 1 2 3 4 5 6 7
			   label block:   H:G:F:E:D:C:B:A
			   address block: A B C D E F G H
			   compressibles:     0 0 0 0 0
			                      0 0 0 0
			                      0 0 0
			                      0 0
			 */
			// Check for trailing zero dual-blocks.
			if (tpl->reverse_short && i > 1 && i < 6 &&
			    block[0].b32 == 0x30303030UL && block[1].b32 == 0x30303030UL) {
				if (compr_start == -1) {
					compr_start = i;
				}
			} else {
				if (compr_start != -1 && compr_end == -1) {
					compr_end = i;
				}
			}
		}

		// Write address blocks.
		unsigned addr_len = 0;
		for (int i = 0; i < 8; i++) {
			if (compr_start == -1 || i < compr_start || i > compr_end) {
				// Write regular address block.
				if (tpl->reverse_short) {
					addr_len += block_write(&blocks[i], addr_str + addr_len);
				} else {
					assert(sizeof(blocks[i]) == 4);
					memcpy(addr_str + addr_len, &blocks[i], 4);
					addr_len += 4;
				}
				// Write separator
				if (i < 7) {
					addr_str[addr_len++] = ':';
				}
			} else if (compr_start != -1 && compr_end == i) {
				// Write compression double colon.
				addr_str[addr_len++] = ':';
			}
		}
		addr_str[addr_len] = '\0';

		return KNOT_EOK;
	}

	return KNOT_EINVAL;
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
	unsigned addr_len = label[0] - tpl->prefix_len;
	memcpy(addr_str, label + 1 + tpl->prefix_len, addr_len);
	addr_str[addr_len] = '\0';

	// Determine address family.
	unsigned hyphen_cnt = 0;
	const char *ch = addr_str;
	while (hyphen_cnt < 4 && ch < addr_str + addr_len) {
		if (*ch == '-') {
			hyphen_cnt++;
			if (*++ch == '-') { // Check for shortened IPv6 notation.
				hyphen_cnt = 4;
				break;
			}
		}
		ch++;
	}
	// Valid IPv4 address looks like A-B-C-D.
	*addr_family = (hyphen_cnt == 3) ? AF_INET : AF_INET6;

	// Restore correct address format.
	const char sep = str_separator(*addr_family);
	str_subst(addr_str, addr_len, '-', sep);

	return KNOT_EOK;
}

static int addr_parse(knotd_qdata_t *qdata, const synth_template_t *tpl, char *addr_str,
                      int *addr_family, bool *parent)
{
	switch (tpl->type) {
	case SYNTH_REVERSE: return reverse_addr_parse(qdata, tpl, addr_str, addr_family, parent);
	case SYNTH_FORWARD: return forward_addr_parse(qdata, tpl, addr_str, addr_family);
	default:            return KNOT_EINVAL;
	}
}

static knot_dname_t *synth_ptrname(uint8_t *out, const char *addr_str,
                                   const synth_template_t *tpl, int addr_family)
{
	knot_dname_txt_storage_t ptrname;
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
	// Synthesize PTR record data.
	knot_dname_storage_t ptrname;
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
	bool parent = false; // querying empty-non-terminal being (possibly indirect) parent of synthesized name

	// Parse address from query name.
	if (addr_parse(qdata, tpl, addr_str, &provided_af, &parent) != KNOT_EOK ||
	    sockaddr_set(&query_addr, provided_af, addr_str, 0) != KNOT_EOK) {
		return state;
	}

	// Try all available addresses.
	int i;
	for (i = 0; i < tpl->addr_count; i++) {
		if (tpl->addr[i].addr_max.ss_family == AF_UNSPEC) {
			if (sockaddr_net_match(&query_addr, &tpl->addr[i].addr,
			                       tpl->addr[i].addr_mask)) {
				break;
			}
		} else {
			if (sockaddr_range_match(&query_addr, &tpl->addr[i].addr,
			                         &tpl->addr[i].addr_max)) {
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
		assert(!parent);
		if (!query_satisfied_by_family(qtype, provided_af)) {
			qdata->rcode = KNOT_RCODE_NOERROR;
			return KNOTD_IN_STATE_NODATA;
		}
		break;
	case SYNTH_REVERSE:
		if (parent || (qtype != KNOT_RRTYPE_PTR && qtype != KNOT_RRTYPE_ANY)) {
			qdata->rcode = KNOT_RCODE_NOERROR;
			return KNOTD_IN_STATE_NODATA;
		}
		break;
	default:
		return state;
	}

	// Synthesize record from template.
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

	// Set address shortening.
	if (tpl->type == SYNTH_REVERSE) {
		conf = knotd_conf_mod(mod, MOD_SHORT);
		tpl->reverse_short = conf.single.boolean;
	}

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
