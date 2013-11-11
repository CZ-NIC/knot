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

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/socket.h>
#include <unistd.h>

#include "utils/nsupdate/nsupdate_exec.h"
#include "utils/common/params.h"
#include "utils/common/msg.h"
#include "utils/common/exec.h"
#include "utils/common/netio.h"
#include "utils/common/token.h"
#include "common/errcode.h"
#include "common/mempattern.h"
#include "common/descriptor.h"
#include "libknot/libknot.h"

/* Declarations of cmd parse functions. */
typedef int (*cmd_handle_f)(const char *lp, nsupdate_params_t *params);
int cmd_add(const char* lp, nsupdate_params_t *params);
int cmd_answer(const char* lp, nsupdate_params_t *params);
int cmd_class(const char* lp, nsupdate_params_t *params);
int cmd_debug(const char* lp, nsupdate_params_t *params);
int cmd_del(const char* lp, nsupdate_params_t *params);
int cmd_gsstsig(const char* lp, nsupdate_params_t *params);
int cmd_key(const char* lp, nsupdate_params_t *params);
int cmd_local(const char* lp, nsupdate_params_t *params);
int cmd_oldgsstsig(const char* lp, nsupdate_params_t *params);
int cmd_origin(const char* lp, nsupdate_params_t *params);
int cmd_prereq(const char* lp, nsupdate_params_t *params);
int cmd_realm(const char* lp, nsupdate_params_t *params);
int cmd_send(const char* lp, nsupdate_params_t *params);
int cmd_server(const char* lp, nsupdate_params_t *params);
int cmd_show(const char* lp, nsupdate_params_t *params);
int cmd_ttl(const char* lp, nsupdate_params_t *params);
int cmd_update(const char* lp, nsupdate_params_t *params);
int cmd_zone(const char* lp, nsupdate_params_t *params);

/* Sorted list of commands.
 * This way we could identify command byte-per-byte and
 * cancel early if the next is lexicographically greater.
 */
const char* cmd_array[] = {
	"\x3" "add",
	"\x6" "answer",
	"\x5" "class",         /* {classname} */
	"\x5" "debug",
	"\x3" "del",
	"\x6" "delete",
	"\x7" "gsstsig",
	"\x3" "key",           /* {name} {secret} */
	"\x5" "local",         /* {address} [port] */
	"\xa" "oldgsstsig",
	"\x6" "origin",        /* {name} */
	"\x6" "prereq",        /* (nx|yx)(domain|rrset) {domain-name} ... */
	"\x5" "realm",         /* {[realm_name]} */
	"\x4" "send",
	"\x6" "server",        /* {servername} [port] */
	"\x4" "show",
	"\x3" "ttl",           /* {seconds} */
	"\x6" "update",        /* (add|delete) {domain-name} ... */
	"\x4" "zone",          /* {zonename} */
	NULL
};

cmd_handle_f cmd_handle[] = {
	cmd_add,
	cmd_answer,
	cmd_class,
	cmd_debug,
	cmd_del,
	cmd_del,         /* delete/del synonyms */
	cmd_gsstsig,
	cmd_key,
	cmd_local,
	cmd_oldgsstsig,
	cmd_origin,
	cmd_prereq,
	cmd_realm,
	cmd_send,
	cmd_server,
	cmd_show,
	cmd_ttl,
	cmd_update,
	cmd_zone,
};

/* {prereq} command table. */
const char* pq_array[] = {
        "\x8" "nxdomain",
        "\x7" "nxrrset",
        "\x8" "yxdomain",
        "\x7" "yxrrset",
        NULL
};
enum {
	PQ_NXDOMAIN = 0,
	PQ_NXRRSET,
	PQ_YXDOMAIN,
	PQ_YXRRSET,
	UP_ADD,
	UP_DEL
};

/* RR parser flags */
enum {
	PARSE_NODEFAULT = 1 << 0, /* Do not fill defaults. */
	PARSE_NAMEONLY  = 1 << 1  /* Parse only name. */
};

static int dname_isvalid(const char *lp, size_t len) {
	knot_dname_t *dn = knot_dname_from_str(lp);
	if (dn == NULL) {
		return 0;
	}
	knot_dname_free(&dn);
	return 1;
}

/* This is probably redundant, but should be a bit faster so let's keep it. */
static int parse_full_rr(scanner_t *s, const char* lp)
{
	if (scanner_process(lp, lp + strlen(lp), 0, s) < 0) {
		return KNOT_EPARSEFAIL;
	}
	char nl = '\n'; /* Ensure newline after complete RR */
	if (scanner_process(&nl, &nl+sizeof(char), 1, s) < 0) { /* Terminate */
		return KNOT_EPARSEFAIL;
	}

	/* Class must not differ from specified. */
	if (s->r_class != s->default_class) {
		char cls_s[16] = {0};
		knot_rrclass_to_string(s->default_class, cls_s, sizeof(cls_s));
		ERR("class mismatch: '%s'\n", cls_s);
		return KNOT_EPARSEFAIL;
	}

	return KNOT_EOK;
}

static int parse_partial_rr(scanner_t *s, const char *lp, unsigned flags) {
	int ret = KNOT_EOK;
	char b1[32], b2[32]; /* Should suffice for both class/type */

	/* Extract owner. */
	size_t len = strcspn(lp, SEP_CHARS);
	knot_dname_t *owner = knot_dname_from_str(lp);
	if (owner == NULL) {
		return KNOT_EPARSEFAIL;
	}

	s->r_owner_length = knot_dname_size(owner);
	memcpy(s->r_owner, owner, s->r_owner_length);
	lp = tok_skipspace(lp + len);

	/* Initialize */
	s->r_type = KNOT_RRTYPE_ANY;
	s->r_class = s->default_class;
	s->r_data_length = 0;
	if (flags & PARSE_NODEFAULT) {
		s->r_ttl = 0;
	} else {
		s->r_ttl = s->default_ttl;
	}

	/* Parse only name? */
	if (flags & PARSE_NAMEONLY) {
		knot_dname_free(&owner);
		return KNOT_EOK;
	}

	/* Now there could be [ttl] [class] [type [data...]]. */
	/*! \todo support for fancy time format in ttl */
	char *np = NULL;
	long ttl = strtol(lp, &np, 10);
	if (ttl >= 0 && np && (*np == '\0' || isspace((unsigned char)(*np)))) {
		s->r_ttl = ttl;
		DBG("%s: parsed ttl=%lu\n", __func__, ttl);
		lp = tok_skipspace(np);
	}

	len = strcspn(lp, SEP_CHARS); /* Try to find class */
	memset(b1, 0, sizeof(b1));
	strncpy(b1, lp, len < sizeof(b1) ? len : sizeof(b1));

	uint16_t v;
	if (knot_rrclass_from_string(b1, &v) == 0) {
		s->r_class = v;
		DBG("%s: parsed class=%u\n", __func__, s->r_class);
		lp = tok_skipspace(lp + len);
	}

	/* Class must not differ from specified. */
	if (s->r_class != s->default_class) {
		char cls_s[16] = {0};
		knot_rrclass_to_string(s->default_class, cls_s, sizeof(cls_s));
		ERR("class mismatch: '%s'\n", cls_s);
		knot_dname_free(&owner);
		return KNOT_EPARSEFAIL;
	}

	len = strcspn(lp, SEP_CHARS); /* Type */
	memset(b2, 0, sizeof(b2));
	strncpy(b2, lp, len < sizeof(b2) ? len : sizeof(b2));
	if (knot_rrtype_from_string(b2, &v) == 0) {
		s->r_type = v;
		DBG("%s: parsed type=%u '%s'\n", __func__, s->r_type, b2);
		lp = tok_skipspace(lp + len);
	}

	/* Remainder */
	if (*lp == '\0') {
		knot_dname_free(&owner);
		return ret; /* No RDATA */
	}

	/* Synthetize full RR line to prevent consistency errors. */
	char *owner_s = knot_dname_to_str(owner);
	knot_rrclass_to_string(s->r_class, b1, sizeof(b1));
	knot_rrtype_to_string(s->r_type,   b2, sizeof(b2));

	/* Need to parse rdata, synthetize input. */
	char *rr = sprintf_alloc("%s %u %s %s %s\n",
	                         owner_s, s->r_ttl, b1, b2, lp);
	if (scanner_process(rr, rr + strlen(rr), 1, s) < 0) {
		ret = KNOT_EPARSEFAIL;
	}

	free(owner_s);
	free(rr);
	knot_dname_free(&owner);
	return ret;
}

static srv_info_t *parse_host(const char *lp, const char* default_port)
{
	/* Extract server address. */
	srv_info_t *srv = NULL;
	size_t len = strcspn(lp, SEP_CHARS);
	char *addr = strndup(lp, len);
	if (!addr) return NULL;
	DBG("%s: parsed addr: %s\n", __func__, addr);

	/* Store port/service if present. */
	lp = tok_skipspace(lp + len);
	if (*lp == '\0') {
		srv = srv_info_create(addr, default_port);
		free(addr);
		return srv;
	}

	len = strcspn(lp, SEP_CHARS);
	char *port = strndup(lp, len);
	if (!port) {
		free(addr);
		return NULL;
	}
	DBG("%s: parsed port: %s\n", __func__, port);

	/* Create server struct. */
	srv = srv_info_create(addr, port);
	free(addr);
	free(port);
	return srv;
}

static int pkt_append(nsupdate_params_t *p, int sect)
{
	/* Check packet state first. */
	int ret = KNOT_EOK;
	knot_dname_t * qname = NULL;
	scanner_t *s = p->rrp;
	if (!p->pkt) {
		p->pkt = create_empty_packet(MAX_PACKET_SIZE);
		qname = knot_dname_from_str(p->zone);
		ret = knot_query_set_question(p->pkt, qname, p->class_num, p->type_num);
		knot_dname_free(&qname);
		if (ret != KNOT_EOK)
			return ret;

		knot_query_set_opcode(p->pkt, KNOT_OPCODE_UPDATE);
	}

	/* Form a rrset. */
	knot_dname_t *o = knot_dname_copy(s->r_owner);
	if (!o) {
		DBG("%s: failed to create dname - %s\n",
		    __func__, knot_strerror(ret));
		return KNOT_ENOMEM;
	}
	knot_rrset_t *rr = knot_rrset_new(o, s->r_type, s->r_class, s->r_ttl);
	if (!rr) {
		DBG("%s: failed to create rrset - %s\n",
		    __func__, knot_strerror(ret));
		knot_dname_free(&o);
		return KNOT_ENOMEM;
	}

	/* Create RDATA (not for NXRRSET prereq). */
	if (s->r_data_length > 0 && sect != PQ_NXRRSET) {
		size_t pos = 0;
		ret = knot_rrset_rdata_from_wire_one(rr, s->r_data, &pos,
		                                     s->r_data_length,
		                                     s->r_data_length);
		if (ret != KNOT_EOK) {
			DBG("%s: failed to set rrset from wire - %s\n",
			    __func__, knot_strerror(ret));
			knot_rrset_free(&rr);
			return ret;
		}
	}

	/* Add to correct section.
	 * ZONES  ... QD section.
	 * UPDATE ... NS section.
	 * PREREQ ... AN section.
	 * ADDIT. ... same.
	 */
	switch(sect) {
	case UP_ADD:
	case UP_DEL:
		ret = knot_response_add_rrset_authority(p->pkt, rr, KNOT_PF_NOTRUNC);
		break;
	case PQ_NXDOMAIN:
	case PQ_NXRRSET:
	case PQ_YXDOMAIN:
	case PQ_YXRRSET:
		ret = knot_response_add_rrset_answer(p->pkt, rr, KNOT_PF_NOTRUNC);
		break;
	default:
		assert(0); /* Should never happen. */
		break;
	}

	if (ret != KNOT_EOK) {
		DBG("%s: failed to append rdata to appropriate section - %s\n",
		    __func__, knot_strerror(ret));
		if (ret == KNOT_ESPACE) {
			ERR("exceeded UPDATE message maximum size %zu\n",
			    knot_packet_max_size(p->pkt));
		}
	}

	return ret;
}

static int pkt_sendrecv(nsupdate_params_t *params,
                        uint8_t *qwire, size_t qlen,
                        uint8_t *rwire, size_t rlen)
{
	net_t net;
	int   ret;

	ret = net_init(params->srcif,
	               params->server,
	               get_iptype(params->ip),
	               get_socktype(params->protocol, KNOT_RRTYPE_SOA),
	               params->wait,
	               &net);

	ret = net_connect(&net);
	DBG("%s: send_msg = %d\n", __func__, net.sockfd);
	if (ret != KNOT_EOK) return -1;

	ret = net_send(&net, qwire, qlen);
	if (ret != KNOT_EOK) {
		net_close(&net);
		net_clean(&net);
		return -1;
	}

	/* Wait for reception. */
	int rb = net_receive(&net, rwire, rlen);
	DBG("%s: receive_msg = %d\n", __func__, rb);
	if (rb <= 0) {
		net_close(&net);
		net_clean(&net);
		return -1;
	}

	net_close(&net);
	net_clean(&net);

	return rb;
}

static int nsupdate_process_line(char *lp, int len, void *arg)
{
	nsupdate_params_t *params = (nsupdate_params_t *)arg;

	/* Remove trailing white space chars. */
	for (int i = len - 1; i >= 0; i--) {
		if (isspace((unsigned char)lp[i]) == 0) {
			break;
		}
		lp[i] = '\0';
	}

	/* Check for empty line or comment. */
	if (lp[0] == '\0' || lp[0] == ';') {
		return KNOT_EOK;
	}

	int ret = tok_find(lp, cmd_array);
	if (ret < 0) {
		return KNOT_EOK; /* Syntax error - do nothing. */
	}

	const char *cmd = cmd_array[ret];
	const char *val = tok_skipspace(lp + TOK_L(cmd));
	ret = cmd_handle[ret](val, params);
	if (ret != KNOT_EOK) {
		DBG("operation '%s' failed (%s)\n",
		    TOK_S(cmd), knot_strerror(ret));
	}

	return KNOT_EOK;
}

static int nsupdate_process(nsupdate_params_t *params, FILE *fp)
{
	/* Process lines. */
	int ret = tok_process_lines(fp, nsupdate_process_line, params);

	/* Check for longing query. */
	if (params->pkt && ret == KNOT_EOK) {
		cmd_send("", params);
	}

	/* Free last answer. */
	if (params->resp) {
		knot_packet_free(&params->resp);
	}

	return ret;
}

int nsupdate_exec(nsupdate_params_t *params)
{
	if (!params) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	/* If not file specified, use stdin. */
	if (EMPTY_LIST(params->qfiles)) {
		return nsupdate_process(params, stdin);
	}

	/* Read from each specified file. */
	strnode_t *n = NULL;
	WALK_LIST(n, params->qfiles) {
		if (strcmp(n->str, "-") == 0) {
			ret = nsupdate_process(params, stdin);
			continue;
		}
		FILE *fp = fopen(n->str, "r");
		if (!fp) {
			ERR("could not open '%s': %s\n",
			    n->str, strerror(errno));
			return KNOT_ERROR;
		}
		ret = nsupdate_process(params, fp);
		fclose(fp);
	}

	return ret;
}

int cmd_update(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	/* update is optional token, next add|del|delete */
	int bp = tok_find(lp, cmd_array);
	if (bp < 0) return bp; /* Syntax error. */

	/* allow only specific tokens */
	cmd_handle_f *h = cmd_handle;
	if (h[bp] != cmd_add && h[bp] != cmd_del) {
		ERR("unexpected token '%s' after 'update', allowed: '%s'\n",
		    lp, "{add|del|delete}");
		return KNOT_EPARSEFAIL;
	}

	return h[bp](tok_skipspace(lp + TOK_L(cmd_array[bp])), params);
}


int cmd_add(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	scanner_t *rrp = params->rrp;
	if (parse_full_rr(rrp, lp) != KNOT_EOK) {
		return KNOT_EPARSEFAIL;
	}

	/* Parsed RR */
	DBG("%s: parsed rr cls=%u, ttl=%u, type=%u (rdata len=%u)\n",
	    __func__, rrp->r_class, rrp->r_ttl,rrp->r_type, rrp->r_data_length);

	return pkt_append(params, UP_ADD); /* Append to packet. */
}

int cmd_del(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	scanner_t *rrp = params->rrp;
	if (parse_partial_rr(rrp, lp, PARSE_NODEFAULT) != KNOT_EOK) {
		return KNOT_EPARSEFAIL;
	}

	/* Check owner name. */
	if (rrp->r_owner_length == 0) {
		ERR("failed to parse prereq owner name '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	}

	rrp->r_ttl = 0; /* Set TTL = 0 when deleting. */

	/* When deleting whole RRSet, use ANY class */
	if (rrp->r_data_length == 0) {
		rrp->r_class = KNOT_CLASS_ANY;
	} else {
		rrp->r_class = KNOT_CLASS_NONE;
	}

	/* Parsed RR */
	DBG("%s: parsed rr cls=%u, ttl=%u, type=%u (rdata len=%u)\n",
	    __func__, rrp->r_class, rrp->r_ttl,rrp->r_type, rrp->r_data_length);

	return pkt_append(params, UP_DEL); /* Append to packet. */
}

int cmd_class(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	uint16_t cls;

	if (knot_rrclass_from_string(lp, &cls) != 0) {
		ERR("failed to parse class '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	} else {
		params->class_num = cls;
		scanner_t *s = params->rrp;
		s->default_class = params->class_num;
	}

	return KNOT_EOK;
}

int cmd_ttl(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	uint32_t ttl = 0;

	if (params_parse_num(lp, &ttl) != KNOT_EOK) {
		return KNOT_EPARSEFAIL;
	}

	return nsupdate_set_ttl(params, ttl);
}

int cmd_debug(const char* lp, nsupdate_params_t *params)
{
	UNUSED(params);
	DBG("%s: lp='%s'\n", __func__, lp);

	msg_enable_debug(1);
	return KNOT_EOK;
}

int cmd_prereq_domain(const char *lp, nsupdate_params_t *params, unsigned type)
{
	UNUSED(type);
	DBG("%s: lp='%s'\n", __func__, lp);

	scanner_t *s = params->rrp;
	int ret = parse_partial_rr(s, lp, PARSE_NODEFAULT|PARSE_NAMEONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return ret;
}

int cmd_prereq_rrset(const char *lp, nsupdate_params_t *params, unsigned type)
{
	UNUSED(type);
	DBG("%s: lp='%s'\n", __func__, lp);

	scanner_t *rrp = params->rrp;
	if (parse_partial_rr(rrp, lp, 0) != KNOT_EOK) {
		return KNOT_EPARSEFAIL;
	}

	/* Check owner name. */
	if (rrp->r_owner_length == 0) {
		ERR("failed to parse prereq owner name '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	}

	/* Parsed RR */
	DBG("%s: parsed rr cls=%u, ttl=%u, type=%u (rdata len=%u)\n",
	    __func__, rrp->r_class, rrp->r_ttl,rrp->r_type, rrp->r_data_length);

	return KNOT_EOK;
}

int cmd_prereq(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	/* Scan prereq specifier ([ny]xrrset|[ny]xdomain) */
	int ret = KNOT_EOK;
	int bp = tok_find(lp, pq_array);
	if (bp < 0) return bp; /* Syntax error. */

	const char *tok = pq_array[bp];
	DBG("%s: type %s\n", __func__, TOK_S(tok));
	lp = tok_skipspace(lp + TOK_L(tok));
	switch(bp) {
	case PQ_NXDOMAIN:
	case PQ_YXDOMAIN:
		ret = cmd_prereq_domain(lp, params, bp);
		break;
	case PQ_NXRRSET:
	case PQ_YXRRSET:
		ret = cmd_prereq_rrset(lp, params, bp);
		break;
	default:
		return KNOT_ERROR;
	}

	/* Append to packet. */
	if (ret == KNOT_EOK) {
		scanner_t *s = params->rrp;
		s->r_ttl = 0; /* Set TTL = 0 for prereq. */
		/* YX{RRSET,DOMAIN} - cls ANY */
		if (bp == PQ_YXRRSET || bp == PQ_YXDOMAIN) {
			s->r_class = KNOT_CLASS_ANY;
		} else { /* NX{RRSET,DOMAIN} - cls NONE */
			s->r_class = KNOT_CLASS_NONE;
		}

		ret = pkt_append(params, bp);
	}

	return ret;
}

int cmd_send(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	DBG("sending packet\n");

	/* Create wireformat. */
	int ret = KNOT_EOK;
	uint8_t *wire = NULL;
	size_t len = 0;

	if ((ret = knot_packet_to_wire(params->pkt, &wire, &len))!= KNOT_EOK) {
		ERR("couldn't serialize packet, %s\n", knot_strerror(ret));
		return ret;
	}

	sign_context_t sign_ctx;
	memset(&sign_ctx, '\0', sizeof(sign_context_t));

	/* Sign if key specified. */
	if (params->key_params.name) {
		ret = sign_packet(params->pkt, &sign_ctx, &params->key_params);
		if (ret != KNOT_EOK) {
			ERR("failed to sign UPDATE message - %s\n",
			    knot_strerror(ret));
			return ret;
		}
		len = params->pkt->size;
	}

	int rb = 0;
	/* Send/recv message (1 try + N retries). */
	int tries = 1 + params->retries;
	for (; tries > 0; --tries) {
		memset(params->rwire, 0, sizeof(params->rwire));
		rb = pkt_sendrecv(params, wire, len,
		                  params->rwire, sizeof(params->rwire));
		if (rb > 0) break;
	}

	/* Clear sent packet. */
	knot_packet_free_rrsets(params->pkt);
	knot_packet_free(&params->pkt);

	/* Clear previous response. */
	if (params->resp) {
		knot_packet_free(&params->resp);
	}

	/* Check Send/recv result. */
	if (rb <= 0) {
		free_sign_context(&sign_ctx);
		return KNOT_ECONNREFUSED;
	}

	/* Parse response. */
	params->resp = knot_packet_new();
	if (!params->resp) {
		free_sign_context(&sign_ctx);
		return KNOT_ENOMEM;
	}
	ret = knot_packet_parse_from_wire(params->resp, params->rwire, rb, 0, 0);
	if (ret != KNOT_EOK) {
		ERR("failed to parse response, %s\n", knot_strerror(ret));
		free_sign_context(&sign_ctx);
		return ret;
	}

	/* Check signature if expected. */
	if (params->key_params.name) {
		ret = verify_packet(params->resp, &sign_ctx, &params->key_params);
		free_sign_context(&sign_ctx);
		if (ret != KNOT_EOK) { /* Collect TSIG error. */
			fprintf(stderr, "%s: %s\n", "; TSIG error with server",
				knot_strerror(ret));
			return ret;
		}
	}

	/* Check return code. */
	knot_lookup_table_t *rcode;
	int rc = knot_packet_rcode(params->resp);
	DBG("%s: received rcode=%d\n", __func__, rc);
	rcode = knot_lookup_by_id(knot_rcode_names, rc);
	if (rcode && rcode->id > KNOT_RCODE_NOERROR) {
		ERR("update failed: %s\n", rcode->name);
	}

	/*! \todo Should we check TC bit? */

	return KNOT_EOK;
}

int cmd_zone(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	/* Check zone name. */
	size_t len = strcspn(lp, SEP_CHARS);
	if (!dname_isvalid(lp, len)) {
		ERR("failed to parse zone '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	}

	free(params->zone);
	params->zone = strndup(lp, len);

	return KNOT_EOK;
}

int cmd_server(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	/* Parse host. */
	srv_info_t *srv = parse_host(lp, params->server->service);

	/* Enqueue. */
	if (!srv) return KNOT_ENOMEM;

	srv_info_free(params->server);
	params->server = srv;

	return KNOT_EOK;
}

int cmd_local(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	/* Parse host. */
	srv_info_t *srv = parse_host(lp, "0");

	/* Enqueue. */
	if (!srv) return KNOT_ENOMEM;

	srv_info_free(params->srcif);
	params->srcif = srv;

	return KNOT_EOK;
}

int cmd_show(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	/* Show current packet. */
	if (!params->pkt) return KNOT_EOK;
	printf("Outgoing update query:\n");
	size_t len = knot_packet_size(params->pkt);
	print_packet(params->pkt, len, NULL, -1, false, &params->style);
	return KNOT_EOK;
}

int cmd_answer(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	/* Show current answer. */
	if (!params->resp) return KNOT_EOK;
	printf("\nAnswer:\n");
	size_t len = knot_packet_size(params->resp);
	print_packet(params->resp, len, NULL, -1, true, &params->style);
	return KNOT_EOK;
}

int cmd_key(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	char *kstr = strdup(lp); /* Convert to default format. */
	if (!kstr) return KNOT_ENOMEM;

	int ret = KNOT_EOK;
	size_t len = strcspn(lp, SEP_CHARS);
	if(kstr[len] == '\0') {
		ERR("command 'key' without {secret} specified\n");
		ret = KNOT_EINVAL;
	} else {
		// override existing key
		knot_free_key_params(&params->key_params);

		kstr[len] = ':'; /* Replace ' ' with ':' sep */
		ret = params_parse_tsig(kstr, &params->key_params);
	}

	free(kstr);
	return ret;
}

int cmd_origin(const char* lp, nsupdate_params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);

	/* Check zone name. */
	size_t len = strcspn(lp, SEP_CHARS);
	if (!dname_isvalid(lp, len)) {
		ERR("failed to parse zone '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	}

	char *name = strndup(lp, len);

	int ret = nsupdate_set_origin(params, name);

	free(name);

	return ret;
}

/*
 *   Not implemented.
 */

int cmd_gsstsig(const char* lp, nsupdate_params_t *params)
{
	UNUSED(params);
	DBG("%s: lp='%s'\n", __func__, lp);

	return KNOT_ENOTSUP;
}

int cmd_oldgsstsig(const char* lp, nsupdate_params_t *params)
{
	UNUSED(params);
	DBG("%s: lp='%s'\n", __func__, lp);

	return KNOT_ENOTSUP;
}

int cmd_realm(const char* lp, nsupdate_params_t *params)
{
	UNUSED(params);
	DBG("%s: lp='%s'\n", __func__, lp);

	return KNOT_ENOTSUP;
}
