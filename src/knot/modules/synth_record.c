/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/modules/synth_record.h"
#include "knot/nameserver/query_module.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/internet.h"
#include "knot/conf/conf.h"
#include "common/descriptor.h"

/* Defines. */
#define ARPA_ZONE_LABELS 2
#define MODULE_ERR(msg...) log_zone_error("Module 'synth_record': " msg)

/*! \brief Supported answer synthesis template types. */
enum synth_template_type {
	SYNTH_NULL = -1,
	SYNTH_FORWARD,
	SYNTH_REVERSE
};

/*!
 * \brief Synthetic response template.
 */
typedef struct synth_template {
	node_t node;
	enum synth_template_type type;
	const char *prefix;
	const char *zone;
	uint32_t ttl;
	conf_iface_t subnet;
} synth_template_t;

/*! \brief Substitute all occurences of given character. */
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
	char sep = str_separator(tpl->subnet.addr.ss_family);
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
	char sep = str_separator(tpl->subnet.addr.ss_family);
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
	char sep = str_separator(tpl->subnet.addr.ss_family);
	memcpy(ptrname + written, addr_str, addr_len);
	str_subst(ptrname + written, addr_len, sep, '-');
	written += addr_len;

	/* Write zone name. */
	ptrname[written] = '.';
	written += 1;
	memcpy(ptrname + written, tpl->zone, zone_len);

	/* Convert to domain name. */
	return knot_dname_from_str(ptrname);
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
	sockaddr_set(&query_addr, tpl->subnet.addr.ss_family, addr_str, 0);

	/* Specify address type and data. */
	if (tpl->subnet.addr.ss_family == AF_INET6) {
		rr->type = KNOT_RRTYPE_AAAA;
		const struct sockaddr_in6* ip = (const struct sockaddr_in6*)&query_addr;
		knot_rrset_add_rdata(rr, (const uint8_t *)&ip->sin6_addr, sizeof(struct in6_addr),
		                  tpl->ttl, &pkt->mm);
	} else if (tpl->subnet.addr.ss_family == AF_INET) {
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
	int provided_af = tpl->subnet.addr.ss_family;
	ret = sockaddr_set(&query_addr, provided_af, addr_str, 0);
	if (ret == KNOT_EOK) {
		ret = netblock_match(&tpl->subnet, &query_addr);
	}
	if (ret != 0) {
		return state; /* Out of our netblock, not applicable. */
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

int solve_synth_record(int state, knot_pkt_t *pkt, struct query_data *qdata, void *ctx)
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

int synth_record_load(struct query_plan *plan, struct query_module *self)
{
	/* Parse first token. */
	char *saveptr = NULL;
	char *token = strtok_r(self->param, " ", &saveptr);
	if (token == NULL) {
		return KNOT_EFEWDATA;
	}

	/* Create synthesis template. */
	struct synth_template *tpl = mm_alloc(self->mm, sizeof(struct synth_template));
	if (tpl == NULL) {
		return KNOT_ENOMEM;
	}

	/* Save in query module, it takes ownership from now on. */
	self->ctx = tpl;

	/* Supported types: reverse, forward */
	if (strcmp(token, "reverse") == 0) {
		tpl->type = SYNTH_REVERSE;
	} else if (strcmp(token, "forward") == 0) {
		tpl->type = SYNTH_FORWARD;
	} else {
		MODULE_ERR("invalid type '%s'.\n", token);
		return KNOT_ENOTSUP;
	}

	/* Parse format string. */
	tpl->prefix = strtok_r(NULL, " ", &saveptr);
	if (strchr(tpl->prefix, '.') != NULL) {
		MODULE_ERR("dots '.' are not allowed in the prefix.\n");
		return KNOT_EMALF;
	}

	/* Parse zone if generating reverse record. */
	if (tpl->type == SYNTH_REVERSE) {
		tpl->zone = strtok_r(NULL, " ", &saveptr);
		knot_dname_t *check_name = knot_dname_from_str(tpl->zone);
		if (check_name == NULL) {
			MODULE_ERR("invalid zone '%s'.\n", tpl->zone);
			return KNOT_EMALF;
		}
		knot_dname_free(&check_name, NULL);
	}

	/* Parse TTL. */
	tpl->ttl = strtol(strtok_r(NULL, " ", &saveptr), NULL, 10);

	/* Parse address. */
	token = strtok_r(NULL, " ", &saveptr);
	char *subnet = strchr(token, '/');
	if (subnet) {
		subnet[0] = '\0';
		tpl->subnet.prefix = strtol(subnet + 1, NULL, 10);
	}

	/* Estimate family. */
	int family = AF_INET;
	int prefix_max = IPV4_PREFIXLEN;
	if (strchr(token, ':') != NULL) {
		family = AF_INET6;
		prefix_max = IPV6_PREFIXLEN;
	}

	/* Check subnet. */
	if (tpl->subnet.prefix > prefix_max) {
		MODULE_ERR("invalid address prefix '%s'.\n", subnet);
		return KNOT_EMALF;
	}

	int ret = sockaddr_set(&tpl->subnet.addr, family, token, 0);
	if (ret != KNOT_EOK) {
		MODULE_ERR("invalid address '%s'.\n", token);
		return KNOT_EMALF;
	}

	return query_plan_step(plan, QPLAN_ANSWER, solve_synth_record, tpl);
}

int synth_record_unload(struct query_module *self)
{
	mm_free(self->mm, self->ctx);
	return KNOT_EOK;
}
