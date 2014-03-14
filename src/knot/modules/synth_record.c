#include "knot/modules/synth_record.h"
#include "knot/nameserver/query_module.h"
#include "knot/nameserver/process_query.h"
#include "knot/nameserver/internet.h"
#include "common/descriptor.h"

/* Defines. */
#define ARPA_ZONE_LABELS 2
#define IP4_ARPA_NAME (const uint8_t *)("\x7""in-addr""\x4""arpa""\x0")
#define IP6_ARPA_NAME (const uint8_t *)("\x3""ip6""\x4""arpa""\x0")
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
	netblock_t subnet;
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

/*! \brief Parse address from reverse query QNAME and return address family. */
static int reverse_addr_parse(struct query_data *qdata, char *addr_str)
{
	/* QNAME required format is [address].[subnet/zone]
	 * f.e.  [1.0...0].[h.g.f.e.0.0.0.0.d.c.b.a.ip6.arpa] represents
	 *       [abcd:0:efgh::1] */
	const knot_dname_t* label = knot_pkt_qname(qdata->query);
	const uint8_t *query_wire = qdata->query->wire;

	/* Check if we have at least 3 last labels for arpa zone and label. */
	int label_count = knot_dname_labels(label, query_wire);
	if (label_count <= ARPA_ZONE_LABELS) {
		return AF_UNSPEC;
	}

	/* Push labels on stack for reverse walkthrough. */
	const uint8_t* label_stack[KNOT_DNAME_MAXLABELS];
	const uint8_t** sp = label_stack;
	while(label_count > ARPA_ZONE_LABELS) {
		*sp++ = label;
		label = knot_wire_next_label(label, query_wire);
		--label_count;
	}

	/* Check remaining suffix if we're matching IPv6/IPv4 */
	int family = AF_UNSPEC;
	if (knot_dname_is_equal(label, IP4_ARPA_NAME)) {
		family = AF_INET;
	} else if (knot_dname_is_equal(label, IP6_ARPA_NAME)) {
		family = AF_INET6;
	} else {
		return AF_UNSPEC;
	}

	/* Write formatted address string. */
	char sep = str_separator(family);
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

	return family;
}

static int forward_addr_parse(struct query_data *qdata, synth_template_t *tpl, char *addr_str)
{
	/* Find prefix label count (additive to prefix length). */
	const knot_dname_t *addr_label = knot_pkt_qname(qdata->query);

	/* Mismatch extra labels after address. */
	int query_labels = knot_dname_labels(addr_label, qdata->query->wire);
	int zone_labels = knot_dname_labels(qdata->zone->name, NULL);
	if (query_labels - zone_labels != 1) {
		return KNOT_EINVAL;
	}

	/* Mismatch if label shorter/equal than prefix. */
	int prefix_len = strlen(tpl->prefix);
	if (addr_label == NULL || addr_label[0] <= prefix_len) {
		return KNOT_EINVAL;
	}
	
	int addr_len = *addr_label - prefix_len;
	memcpy(addr_str, addr_label + 1 + prefix_len, addr_len);
	
	/* Restore correct address format. */
	char sep = str_separator(tpl->subnet.ss.ss_family);
	str_subst(addr_str, addr_len, '-', sep);
	
	/* Get family from QTYPE. */
	switch(knot_pkt_qtype(qdata->query)) {
	case KNOT_RRTYPE_A:    return AF_INET;
	case KNOT_RRTYPE_AAAA: return AF_INET6;
	default:               return KNOT_EINVAL;
	}
}

static int addr_parse(struct query_data *qdata, synth_template_t *tpl, char *addr_str)
{
	switch(tpl->type) {
	case SYNTH_REVERSE: return reverse_addr_parse(qdata, addr_str);
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
	char sep = str_separator(tpl->subnet.ss.ss_family);
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

static knot_rrset_t *reverse_rr(char *addr_str, synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Synthetize PTR record. */
	knot_dname_t* qname = knot_dname_copy(knot_pkt_qname(qdata->query));
	knot_rrset_t *rr = knot_rrset_new(qname, KNOT_RRTYPE_PTR, KNOT_CLASS_IN, &pkt->mm);
	if (rr == NULL) {
		knot_dname_free(&qname);
		return NULL;
	}

	/* Synthetize PTR record data. */
	knot_dname_t *ptrname = synth_ptrname(addr_str, tpl);
	if (ptrname == NULL) {
		return NULL;
	}
	knot_rrset_add_rr(rr, ptrname, knot_dname_size(ptrname), tpl->ttl, &pkt->mm);
	knot_dname_free(&ptrname);

	return rr;
}

static knot_rrset_t *forward_rr(char *addr_str, synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Decide synthetic record A/AAAA type. */
	int family = tpl->subnet.ss.ss_family;
	uint16_t rr_class = KNOT_RRTYPE_A;
	if (family == AF_INET6) {
		rr_class = KNOT_RRTYPE_AAAA;
	}

	knot_dname_t* qname = knot_dname_copy(knot_pkt_qname(qdata->query));
	knot_rrset_t *rr = knot_rrset_new(qname, rr_class, KNOT_CLASS_IN, &pkt->mm);
	if (rr == NULL) {
		knot_dname_free(&qname);
		return NULL;
	}

	struct sockaddr_storage query_addr = {'\0'};
	sockaddr_set(&query_addr, family, addr_str, 0);

	/* Append address. */
	if (family == AF_INET6) {
		const struct sockaddr_in6* ip = (const struct sockaddr_in6*)&query_addr;
		knot_rrset_add_rr(rr, (const uint8_t *)&ip->sin6_addr, sizeof(struct in6_addr),
		                  tpl->ttl, &pkt->mm);
	} else {
		const struct sockaddr_in* ip = (const struct sockaddr_in*)&query_addr;
		knot_rrset_add_rr(rr, (const uint8_t *)&ip->sin_addr, sizeof(struct in_addr),
		                  tpl->ttl, &pkt->mm);
	}

	return rr;
}

static knot_rrset_t *synth_rr(char *addr_str, synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	switch(tpl->type) {
	case SYNTH_REVERSE: return reverse_rr(addr_str, tpl, pkt, qdata);
	case SYNTH_FORWARD: return forward_rr(addr_str, tpl, pkt, qdata);
	default:            return NULL;
	}
}

/*! \brief Check if query fits the template requirements. */
static int template_match(int state, synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Parse address from query name. */
	char addr_str[SOCKADDR_STRLEN] = { '\0' };
	int family = addr_parse(qdata, tpl, addr_str);
	if (family != AF_INET && family != AF_INET6) {
		return state; /* Can't identify addr in QNAME, not applicable. */
	}

	/* Match against template netblock. */
	struct sockaddr_storage query_addr;
	int ret = sockaddr_set(&query_addr, family, addr_str, 0);
	if (ret == KNOT_EOK) {
		ret = netblock_match(&tpl->subnet, &query_addr);
	}
	if (ret != 0) {
		return state; /* Out of our netblock, not applicable. */
	}

	/* Synthetise record from template. */
	knot_rrset_t *rr = synth_rr(addr_str, tpl, pkt, qdata);
	if (rr == NULL) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return ERROR;
	}

	/*! \todo Minimal TTL if not configured, after SOA record API cleanup. */

	/* Create empty response with PTR record in AN. */
	knot_pkt_init_response(pkt, qdata->query);
	if (knot_pkt_put(pkt, COMPR_HINT_QNAME, rr, KNOT_PF_FREE) != KNOT_EOK) {
		return ERROR;
	}

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
		knot_dname_free(&check_name);
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
	if (strchr(token, ':') != NULL) {
		family = AF_INET6;
	}

	int ret = sockaddr_set(&tpl->subnet.ss, family, token, 0);
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
