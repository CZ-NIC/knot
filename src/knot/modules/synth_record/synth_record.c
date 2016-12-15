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
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "knot/modules/synth_record/synth_record.h"

/* Module configuration scheme. */
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

int check_prefix(conf_check_t *args)
{
	if (strchr((const char *)args->data, '.') != NULL) {
		args->err_str = "dot '.' is not allowed";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

const yp_item_t scheme_mod_synth_record[] = {
	{ C_ID,       YP_TSTR,   YP_VNONE },
	{ MOD_TYPE,   YP_TOPT,   YP_VOPT = { synthetic_types, SYNTH_NULL } },
	{ MOD_PREFIX, YP_TSTR,   YP_VSTR = { "" }, YP_FNONE, { check_prefix } },
	{ MOD_ORIGIN, YP_TDNAME, YP_VNONE },
	{ MOD_TTL,    YP_TINT,   YP_VINT = { 0, UINT32_MAX, 3600, YP_STIME } },
	{ MOD_NET,    YP_TDATA,  YP_VDATA = { 0, NULL, addr_range_to_bin,
	                                      addr_range_to_txt }, YP_FMULTI },
	{ C_COMMENT,  YP_TSTR,   YP_VNONE },
	{ NULL }
};

int check_mod_synth_record(conf_check_t *args)
{
	// Check type.
	conf_val_t type = conf_rawid_get_txn(args->conf, args->txn, C_MOD_SYNTH_RECORD,
	                                     MOD_TYPE, args->id, args->id_len);
	if (type.code != KNOT_EOK) {
		args->err_str = "no synthesis type specified";
		return KNOT_EINVAL;
	}

	// Check origin.
	conf_val_t origin = conf_rawid_get_txn(args->conf, args->txn, C_MOD_SYNTH_RECORD,
	                                       MOD_ORIGIN, args->id, args->id_len);
	if (origin.code != KNOT_EOK && conf_opt(&type) == SYNTH_REVERSE) {
		args->err_str = "no origin specified";
		return KNOT_EINVAL;
	}
	if (origin.code == KNOT_EOK && conf_opt(&type) == SYNTH_FORWARD) {
		args->err_str = "origin not allowed with forward type";
		return KNOT_EINVAL;
	}

	// Check network subnet.
	conf_val_t net = conf_rawid_get_txn(args->conf, args->txn, C_MOD_SYNTH_RECORD,
	                                    MOD_NET, args->id, args->id_len);
	if (net.code != KNOT_EOK) {
		args->err_str = "no network subnet specified";
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

/* Defines. */
#define ARPA_ZONE_LABELS 2

/*!
 * \brief Synthetic response template.
 */
typedef struct synth_template {
	node_t node;
	enum synth_template_type type;
	char *prefix;
	char *zone;
	uint32_t ttl;
	struct sockaddr_storage addr;
	struct sockaddr_storage addr_max;
	int mask;
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
static int reverse_addr_parse(struct query_data *qdata, synth_template_t *tpl, char *addr_str)
{
	/* QNAME required format is [address].[subnet/zone]
	 * f.e.  [1.0...0].[h.g.f.e.0.0.0.0.d.c.b.a.ip6.arpa] represents
	 *       [abcd:0:efgh::1] */
	const knot_dname_t* label = qdata->name;
	const uint8_t *query_wire = qdata->query->wire;

	/* Push labels on stack for reverse walkthrough. */
	const uint8_t* label_stack[KNOT_DNAME_MAXLABELS];
	const uint8_t** sp = label_stack;
	int label_count = knot_dname_labels(label, query_wire);
	while(label_count > ARPA_ZONE_LABELS) {
		*sp++ = label;
		label = knot_wire_next_label(label, query_wire);
		--label_count;
	}

	/* Write formatted address string. */
	char sep = str_separator(tpl->addr.ss_family);
	int sep_frequency = 1;
	if (sep == ':') {
		sep_frequency = 4; /* Separator per 4 hexdigits. */
	}

	char *dst = addr_str;
	label_count = 0;
	while(sp != label_stack) {
		label = *--sp;
		/* Write separator for each Nth label. */
		if (label_count == sep_frequency) {
			*dst = sep;
			dst += 1;
			label_count = 0;
		}
		/* Write label */
		memcpy(dst, label + 1, label[0]);
		dst += label[0];
		label_count += 1;
	}

	return KNOT_EOK;
}

static int forward_addr_parse(struct query_data *qdata, synth_template_t *tpl, char *addr_str)
{
	/* Find prefix label count (additive to prefix length). */
	const knot_dname_t *addr_label = qdata->name;

	/* Mismatch if label shorter/equal than prefix. */
	int prefix_len = strlen(tpl->prefix);
	if (addr_label == NULL || addr_label[0] <= prefix_len) {
		return KNOT_EINVAL;
	}

	int addr_len = *addr_label - prefix_len;
	memcpy(addr_str, addr_label + 1 + prefix_len, addr_len);

	/* Restore correct address format. */
	char sep = str_separator(tpl->addr.ss_family);
	str_subst(addr_str, addr_len, '-', sep);

	return KNOT_EOK;
}

static int addr_parse(struct query_data *qdata, synth_template_t *tpl, char *addr_str)
{
	/* Check if we have at least 1 label below zone. */
	int zone_labels = knot_dname_labels(qdata->zone->name, NULL);
	int query_labels = knot_dname_labels(qdata->name, qdata->query->wire);
	if (query_labels < zone_labels + 1) {
		return KNOT_EINVAL;
	}

	switch (tpl->type) {
	case SYNTH_REVERSE: return reverse_addr_parse(qdata, tpl, addr_str);
	case SYNTH_FORWARD: return forward_addr_parse(qdata, tpl, addr_str);
	default:            return KNOT_EINVAL;
	}
}

static knot_dname_t *synth_ptrname(const char *addr_str, synth_template_t *tpl)
{
	/* PTR right-hand value is [prefix][address][zone] */
	char ptrname[KNOT_DNAME_MAXLEN] = {'\0'};
	int prefix_len = strlen(tpl->prefix);
	int addr_len = strlen(addr_str);
	int zone_len = strlen(tpl->zone);

	/* Check required space (zone requires extra leading dot). */
	if (prefix_len + addr_len + zone_len + 1 >= KNOT_DNAME_MAXLEN) {
		return NULL;
	}

	/* Write prefix string. */
	memcpy(ptrname, tpl->prefix, prefix_len);
	int written = prefix_len;

	/* Write address with substituted separator to '-'. */
	char sep = str_separator(tpl->addr.ss_family);
	memcpy(ptrname + written, addr_str, addr_len);
	str_subst(ptrname + written, addr_len, sep, '-');
	written += addr_len;

	/* Write zone name. */
	ptrname[written] = '.';
	written += 1;
	memcpy(ptrname + written, tpl->zone, zone_len);

	/* Convert to domain name. */
	return knot_dname_from_str_alloc(ptrname);
}

static int reverse_rr(char *addr_str, synth_template_t *tpl, knot_pkt_t *pkt, knot_rrset_t *rr)
{
	/* Synthetize PTR record data. */
	knot_dname_t *ptrname = synth_ptrname(addr_str, tpl);
	if (ptrname == NULL) {
		return KNOT_ENOMEM;
	}

	rr->type = KNOT_RRTYPE_PTR;
	knot_rrset_add_rdata(rr, ptrname, knot_dname_size(ptrname), tpl->ttl, &pkt->mm);
	knot_dname_free(&ptrname, NULL);

	return KNOT_EOK;
}

static int forward_rr(char *addr_str, synth_template_t *tpl, knot_pkt_t *pkt, knot_rrset_t *rr)
{
	struct sockaddr_storage query_addr = {'\0'};
	sockaddr_set(&query_addr, tpl->addr.ss_family, addr_str, 0);

	/* Specify address type and data. */
	if (tpl->addr.ss_family == AF_INET6) {
		rr->type = KNOT_RRTYPE_AAAA;
		const struct sockaddr_in6* ip = (const struct sockaddr_in6*)&query_addr;
		knot_rrset_add_rdata(rr, (const uint8_t *)&ip->sin6_addr, sizeof(struct in6_addr),
		                  tpl->ttl, &pkt->mm);
	} else if (tpl->addr.ss_family == AF_INET) {
		rr->type = KNOT_RRTYPE_A;
		const struct sockaddr_in* ip = (const struct sockaddr_in*)&query_addr;
		knot_rrset_add_rdata(rr, (const uint8_t *)&ip->sin_addr, sizeof(struct in_addr),
		                  tpl->ttl, &pkt->mm);
	} else {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static knot_rrset_t *synth_rr(char *addr_str, synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	knot_rrset_t *rr = knot_rrset_new(qdata->name, 0, KNOT_CLASS_IN,
	                                  &pkt->mm);
	if (rr == NULL) {
		return NULL;
	}

	/* Fill in the specific data. */
	int ret = KNOT_ERROR;
	switch (tpl->type) {
	case SYNTH_REVERSE: ret = reverse_rr(addr_str, tpl, pkt, rr); break;
	case SYNTH_FORWARD: ret = forward_rr(addr_str, tpl, pkt, rr); break;
	default: break;
	}

	if (ret != KNOT_EOK) {
		knot_rrset_free(&rr, &pkt->mm);
		return NULL;
	}

	return rr;
}

/*! \brief Check if query fits the template requirements. */
static int template_match(int state, synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Parse address from query name. */
	char addr_str[SOCKADDR_STRLEN] = { '\0' };
	int ret = addr_parse(qdata, tpl, addr_str);
	if (ret != KNOT_EOK) {
		return state; /* Can't identify addr in QNAME, not applicable. */
	}

	/* Match against template netblock. */
	struct sockaddr_storage query_addr = { '\0' };
	int provided_af = tpl->addr.ss_family;
	ret = sockaddr_set(&query_addr, provided_af, addr_str, 0);
	if (ret != KNOT_EOK) {
		return state;
	}
	if (tpl->addr_max.ss_family == AF_UNSPEC) {
		if (!sockaddr_net_match((struct sockaddr *)&query_addr,
		                        (struct sockaddr *)&tpl->addr,
		                        tpl->mask)) {
			return state; /* Out of our netblock, not applicable. */
		}
	} else {
		if (!sockaddr_range_match((struct sockaddr *)&query_addr,
		                          (struct sockaddr *)&tpl->addr,
		                          (struct sockaddr *)&tpl->addr_max)) {
			return state; /* Out of our netblock, not applicable. */
		}
	}

	/* Check if the request is for an available query type. */
	uint16_t qtype = knot_pkt_qtype(qdata->query);
	switch (tpl->type) {
	case SYNTH_FORWARD:
		if (!query_satisfied_by_family(qtype, provided_af)) {
			qdata->rcode = KNOT_RCODE_NOERROR;
			return NODATA;
		}
		break;
	case SYNTH_REVERSE:
		if (qtype != KNOT_RRTYPE_PTR && qtype != KNOT_RRTYPE_ANY) {
			qdata->rcode = KNOT_RCODE_NOERROR;
			return NODATA;
		}
		break;
	default:
		break;
	}

	/* Synthetise record from template. */
	knot_rrset_t *rr = synth_rr(addr_str, tpl, pkt, qdata);
	if (rr == NULL) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return ERROR;
	}

	/* Insert synthetic response into packet. */
	if (knot_pkt_put(pkt, 0, rr, KNOT_PF_FREE) != KNOT_EOK) {
		return ERROR;
	}

	/* Authoritative response. */
	knot_wire_set_aa(pkt->wire);

	return HIT;
}

static int solve_synth_record(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
{
	if (pkt == NULL || qdata == NULL || ctx == NULL) {
		return ERROR;
	}

	/* Applicable when search in zone fails. */
	if (state != MISS) {
		return state;
	}

	/* Check if template fits. */
	return template_match(state, (synth_template_t *)ctx, pkt, qdata);
}

int synth_record_load(struct query_plan *plan, struct query_module *self,
                      const knot_dname_t *zone)
{
	if (plan == NULL || self == NULL) {
		return KNOT_EINVAL;
	}

	/* Create synthesis template. */
	struct synth_template *tpl = mm_alloc(self->mm, sizeof(struct synth_template));
	if (tpl == NULL) {
		return KNOT_ENOMEM;
	}

	conf_val_t val;

	/* Set type. */
	val = conf_mod_get(self->config, MOD_TYPE, self->id);
	tpl->type = conf_opt(&val);

	/* Set prefix. */
	val = conf_mod_get(self->config, MOD_PREFIX, self->id);
	tpl->prefix = strdup(conf_str(&val));

	/* Set origin if generating reverse record. */
	if (tpl->type == SYNTH_REVERSE) {
		val = conf_mod_get(self->config, MOD_ORIGIN, self->id);
		tpl->zone = knot_dname_to_str_alloc(conf_dname(&val));
		if (tpl->zone == NULL) {
			free(tpl->prefix);
			mm_free(self->mm, tpl);
			return KNOT_ENOMEM;
		}
	}

	/* Set ttl. */
	val = conf_mod_get(self->config, MOD_TTL, self->id);
	tpl->ttl = conf_int(&val);

	/* Set address. */
	val = conf_mod_get(self->config, MOD_NET, self->id);
	tpl->addr = conf_addr_range(&val, &tpl->addr_max, &tpl->mask);

	self->ctx = tpl;

	return query_plan_step(plan, QPLAN_ANSWER, solve_synth_record, self->ctx);
}

int synth_record_unload(struct query_module *self)
{
	if (self == NULL) {
		return KNOT_EINVAL;
	}

	synth_template_t *tpl = (synth_template_t *)self->ctx;
	free(tpl->zone);
	free(tpl->prefix);
	mm_free(self->mm, tpl);
	return KNOT_EOK;
}
