#include "knot/nameserver/synth_record.h"
#include "knot/nameserver/internet.h"
#include "common/descriptor.h"

#define ARPA_ZONE_LABELS 2
#define IP4_ARPA_NAME (const uint8_t *)("\x7""in-addr""\x4""arpa""\x0")
#define IP6_ARPA_NAME (const uint8_t *)("\x3""ip6""\x4""arpa""\x0")

/*! \brief Parse address from reverse query QNAME and return address family. */
static int reverse_addr_parse(struct query_data *qdata, char *addr_str)
{
	/* QNAME required format is [address].[subnet/zone]
	 * f.e.  [1.0...0].[h.g.f.e.0.0.0.0.d.c.b.a.ip6.arpa] represents
	 *       [abcd:0:efgh::1] */
	const knot_dname_t* label = knot_pkt_qname(qdata->query);
	const uint8_t *query_wire = qdata->query->wire;

	/* Check if we have at least 2 last labels for arpa zone. */
	int label_count = knot_dname_labels(label, query_wire);
	if (label_count < ARPA_ZONE_LABELS) {
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
	char sep = '.';
	int  sep_frequency = 1;
	if (knot_dname_is_equal(label, IP4_ARPA_NAME)) {
		family = AF_INET;
	} else if (knot_dname_is_equal(label, IP6_ARPA_NAME)) {
		/* Conversion from dotted form to hex. */
		family = AF_INET6;
		sep = ':';
		sep_frequency = 4;
	} else {
		return AF_UNSPEC;
	}

	/* Write formatted address string. */
	label_count = 0;

	char *dst = addr_str;
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

static knot_dname_t *synth_ptrname(const char *addr_str, synth_template_t *tpl)
{
	/* PTR right-hand value is [prefix][addresbs][suffix] */
	char ptrname[KNOT_DNAME_MAXLEN] = {'\0'};
	ssize_t written = 0;
	ssize_t to_write = 0;

	/* Tokenize result string. */
	const char *format = tpl->format;
	const char *sub = NULL;
	while ((sub = strchr(format, '%')) != NULL) {
		/* Find substitution closure. */
		const char *sub_end = strchr(sub + 1, '%');
		if (sub_end == NULL) {
			return NULL; /* Unpaired substitution. */
		}
		/* Write prefix string. */
		to_write = sub - format;
		if (written + to_write < sizeof(ptrname)) {
			memcpy(ptrname + written, format, to_write);
			written += to_write;
		}
		/* Write substitution. */
		to_write = strlen(addr_str);
		if (written + to_write < sizeof(ptrname)) {
			memcpy(ptrname + written, addr_str, to_write);
			for (int i = 0; i < to_write; ++i) {
				if (ptrname[written + i] == '.' ||
				    ptrname[written + i] == ':') {
					ptrname[written + i] = '-';
				}
			}
			written += to_write;
		}
		format = sub_end + 1;
	}

	/* Write remainder. */
	to_write = strlen(format);
	if (written + to_write < sizeof(ptrname)) {
		memcpy(ptrname + written, format, to_write);
		written += to_write;
	}

	/* Convert to domain name. */
	return knot_dname_from_str(ptrname);
}

static int reverse_match(synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	/* Parse address from query name. */
	char addr_str[SOCKADDR_STRLEN] = { '\0' };
	int family = reverse_addr_parse(qdata, addr_str);
	if (family == AF_UNSPEC) {
		qdata->rcode = KNOT_RCODE_NXDOMAIN; /* Invalid address in our authority. */
		return NS_PROC_FAIL;
	}

	/* Match against template netblock. */
	struct sockaddr_storage query_addr;
	int ret = sockaddr_set(&query_addr, family, addr_str, 0);
	if (ret == KNOT_EOK) {
		ret = netblock_match(&tpl->subnet, &query_addr);
	}
	if (ret != 0) {
		return NS_PROC_NOOP; /* Not applicable. */
	}

	/* Synthetize PTR record. */
	knot_dname_t* qname = knot_dname_copy(knot_pkt_qname(qdata->query));
	knot_rrset_t *rr = knot_rrset_new(qname, KNOT_RRTYPE_PTR, KNOT_CLASS_IN, &pkt->mm);
	if (rr == NULL) {
		knot_dname_free(&qname);
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}

	/* Synthetize PTR record data. */
	knot_dname_t *ptrname = synth_ptrname(addr_str, tpl);
	if (ptrname == NULL) {
		qdata->rcode = KNOT_RCODE_SERVFAIL;
		return NS_PROC_FAIL;
	}
	knot_rrset_add_rr(rr, ptrname, knot_dname_size(ptrname), tpl->ttl, &pkt->mm);

	/*! \todo Minimal TTL if not configured, after SOA record API cleanup. */

	/* Create empty response with PTR record in AN. */
	knot_pkt_init_response(pkt, qdata->query);
	if (knot_pkt_put(pkt, COMPR_HINT_QNAME, rr, KNOT_PF_FREE) != KNOT_EOK) {
		return NS_PROC_FAIL;
	}

	return NS_PROC_DONE;
}

static int forward_match(synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	return NS_PROC_FAIL;
}

/*! \brief Check if query fits the template requirements. */
static int template_match(synth_template_t *tpl, knot_pkt_t *pkt, struct query_data *qdata)
{
	switch(tpl->type) {
	case SYNTH_REVERSE: return reverse_match(tpl, pkt, qdata);
	case SYNTH_FORWARD: return forward_match(tpl, pkt, qdata);
	default:            return NS_PROC_NOOP;
	}
}

bool synth_answer_possible(struct query_data *qdata)
{
	/*! \note This might be used for synth responses in general (like CH stub),
	 *        then requirements should be in the template. */

	/* Synthetic response is possible if we have non-empty
	 * list of synth templates and name resolution fails. */
	return qdata->packet_type == KNOT_QUERY_NORMAL &&
	       qdata->rcode       == KNOT_RCODE_NXDOMAIN &&
	       qdata->zone && !EMPTY_LIST(qdata->zone->conf->synth_templates);
}

int synth_answer(knot_pkt_t *pkt, struct query_data *qdata)
{
	if (pkt == NULL || qdata == NULL || qdata->zone == NULL) {
		return NS_PROC_NOOP;
	}

	/* Check valid zone. */
	NS_NEED_ZONE(qdata, KNOT_RCODE_REFUSED);

	/* Scan template list. */
	conf_zone_t *zone_config = qdata->zone->conf;
	synth_template_t *tpl = NULL;
	WALK_LIST(tpl, zone_config->synth_templates) {
		/* Check if template fits. */
		int next_state = template_match(tpl, pkt, qdata);
		if (next_state != NS_PROC_NOOP) {
			return next_state; /* Template matched. */
		}
	}

	/* Cannot synthetize answer. */
	return NS_PROC_FAIL;
}
