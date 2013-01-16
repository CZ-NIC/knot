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

/* FreeBSD POSIX2008 getline() */
#ifndef _WITH_GETLINE
 #define _WITH_GETLINE
#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>

#include "utils/nsupdate/nsupdate_exec.h"
#include "utils/common/msg.h"
#include "utils/common/resolv.h"
#include "common/errcode.h"
#include "common/mempattern.h"
#include "libknot/dname.h"
#include "libknot/util/descriptor.h"

/* Declarations of cmd parse functions. */
typedef int (*cmd_handle_f)(const char *lp, params_t *params);
int cmd_add(const char* lp, params_t *params);
int cmd_answer(const char* lp, params_t *params);
int cmd_class(const char* lp, params_t *params);
int cmd_debug(const char* lp, params_t *params);
int cmd_del(const char* lp, params_t *params);
int cmd_gsstsig(const char* lp, params_t *params);
int cmd_key(const char* lp, params_t *params);
int cmd_local(const char* lp, params_t *params);
int cmd_oldgsstsig(const char* lp, params_t *params);
int cmd_prereq(const char* lp, params_t *params);
int cmd_realm(const char* lp, params_t *params);
int cmd_send(const char* lp, params_t *params);
int cmd_server(const char* lp, params_t *params);
int cmd_show(const char* lp, params_t *params);
int cmd_ttl(const char* lp, params_t *params);
int cmd_update(const char* lp, params_t *params);
int cmd_zone(const char* lp, params_t *params);

/* Sorted list of commands.
 * This way we could identify command byte-per-byte and
 * cancel early if the next is lexicographically greater.
 */
#define CMD_S(x) ((x)+1)
#define CMD_L(x) ((unsigned char)(x)[0])
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
	"\x6" "prereq",        /* (nx|yx)(domain|rrset) {domain-name} ... */
	"\x5" "realm",         /* {[realm_name]} */
	"\x4" "send",
	"\x6" "server",        /* {servername} [port] */
	"\x4" "show",
	"\x3" "ttl",           /* {seconds} */
	"\x6" "update",        /* (add|delete) {domain-name} ... */
	"\x4" "zone",           /* {zonename} */
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
	PQ_YXRRSET
};

static inline const char* skipspace(const char *lp) {
	while (isspace(*lp)) ++lp; return lp;
}

static int dname_isvalid(const char *lp, size_t len) {
	knot_dname_t *dn = knot_dname_new_from_str(lp, len, NULL);
	if (dn == NULL) {
		return 0;
	}
	knot_dname_free(&dn);
	return 1;
}

static int parse_remainder(scanner_t *s, const char* lp)
{
	if (scanner_process(lp, lp + strlen(lp), 0, s) < 0) {
		return KNOT_EPARSEFAIL;
	}
	char nl = '\n';
	if (scanner_process(&nl, &nl+sizeof(char), 1, s) < 0) { /* Terminate */
		return KNOT_EPARSEFAIL;
	}
	return KNOT_EOK;
}

/*!
 * \brief Scan for matching token described by a match table.
 *
 * Table consists of strings, prefixed with 1B length.
 *
 * \param fp File with contents to be read.
 * \param tbl Match description table.
 * \param lpm Pointer to longest prefix match.
 * \retval index to matching record.
 * \retval -1 if no match is found, lpm may be set to longest prefix match.
 */
static int tok_scan(const char* lp, const char **tbl, int *lpm)
{
	const char *prefix = lp; /* Ptr to line start. */
	int i = 0, pl = 1;       /* Match index, prefix length. */
	unsigned char len = 0;   /* Read length. */
	for(;;) {
		const char *tok = tbl[i];
		if (*lp == '\0' || isspace(*lp)) {
			if (tok && CMD_L(tok) == len) { /* Consumed whole w? */
				return i; /* Identifier */
			} else { /* Word is shorter than cmd? */
				break;
			}
		}

		/* Find next prefix match. */
		++len;
		while (tok) {
			if (CMD_L(tok) >= len) {  /* Is prefix of current token */
				if (*lp < tok[pl]) {  /* Terminate early. */
					tok = NULL;
					break; /* No match could be found. */
				}
				if (*lp == tok[pl]) { /* Match */
					if(lpm) *lpm = i;
					++pl;
					break;
				}
			}

			/* No early cut, no match - seek next. */
			while ((tok = tbl[++i]) != NULL) {
				if (CMD_L(tok) >= len &&
				    memcmp(CMD_S(tok), prefix, len) == 0) {
					break;
				}
			}
		}

		if (tok == NULL) {
			break; /* All tokens exhausted. */
		} else {
			++lp;  /* Next char */
		}
	}

	return -1;
}

static int tok_find(const char *lp, const char **tbl)
{
	int lpm = -1;
	int bp = 0;
	if ((bp = tok_scan(lp, tbl, &lpm)) < 0) {
		if (lpm > -1) {
			ERR("unexpected literal: '%s', did you mean '%s' ?\n",
			    lp, CMD_S(tbl[lpm]));
		} else {
			ERR("unexpected literal: '%s'\n", lp);
		}
		ERR("syntax error\n");
		return KNOT_EPARSEFAIL;
	}
	
	return bp;
}

static int nsupdate_process(params_t *params, FILE *fp)
{
	/* Process lines. */
	int ret = KNOT_EOK;
	char *buf = NULL;
	size_t buflen = 0;
	ssize_t rb = 0;
	while ((rb = getline(&buf, &buflen, fp)) != -1) {
		if (buf[rb - 1] == '\n') buf[rb - 1] = '\0'; /* Discard nline */
		ret = tok_find(buf, cmd_array);
		if (ret < 0) {
			break; /* Syntax error */
		} else {
			const char *cmd = cmd_array[ret];
			const char *lp = skipspace(buf + CMD_L(cmd));
			ret = cmd_handle[ret](lp, params);
			if (ret != KNOT_EOK) {
				ERR("incorrect operation '%s' - %s\n",
				    CMD_S(cmd), knot_strerror(ret));
				break;
			}
		}
	}

	free(buf);
	return ret;
}

int nsupdate_exec(params_t *params)
{
	if (!params) {
		return KNOT_EINVAL;
	}
	
	nsupdate_params_t* npar = NSUP_PARAM(params);

	/* If not file specified, use stdin. */
	if (EMPTY_LIST(npar->qfiles)) {
		return nsupdate_process(params, stdin);
	}

	/* Read from each specified file. */
	strnode_t *n = NULL;
	WALK_LIST(n, npar->qfiles) {
		if (strcmp(n->str, "-") == 0) {
			nsupdate_process(params, stdin);
			continue;
		}
		FILE *fp = fopen(n->str, "r");
		if (!fp) {
			ERR("could not open '%s': %s\n",
			    n->str, strerror(errno));
			return KNOT_ERROR;
		}
		nsupdate_process(params, fp);
		fclose(fp);
	}

	return KNOT_EOK;
}

int cmd_update(const char* lp, params_t *params)
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
	
	return h[bp](skipspace(lp + CMD_L(cmd_array[bp])), params);
}


int cmd_add(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	
	scanner_t *rrp = NSUP_PARAM(params)->rrp;
	if (parse_remainder(rrp, lp) != KNOT_EOK) {
		return KNOT_EPARSEFAIL;
	}
	
	/* Parsed RR */
	DBG("%s: parsed rr cls=%u, ttl=%u, type=%u (rdata len=%u)\n",
	    __func__, rrp->r_class, rrp->r_ttl,rrp->r_type, rrp->r_data_length);
	
	/*! \todo Make a rrset or modify packet API and write wireformat directly. */
	
	return KNOT_EOK;
}

int cmd_class(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	params->class_num = knot_rrclass_from_string(lp);
	if (params->class_num == 0) {
		ERR("failed to parse class '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	}
	
	return KNOT_EOK;
}

int cmd_debug(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	params_flag_verbose(params);
	return KNOT_EOK;
}

int cmd_prereq_domain(const char *lp, params_t *params, unsigned type)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	
	/* Extract dname. */
	size_t len = strcspn(lp, SEP_CHARS);
	if (!dname_isvalid(lp, len)) {
		ERR("failed to parse prereq name '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	}

	DBG("%s: parsed name '%s' len: %zu\n", __func__, lp, len);
	return KNOT_EOK;
}

int cmd_prereq_rrset(const char *lp, params_t *params, unsigned type)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	
	scanner_t *rrp = NSUP_PARAM(params)->rrp;
	if (parse_remainder(rrp, lp) != KNOT_EOK) {
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
	
	return KNOT_ENOTSUP;
}

int cmd_prereq(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	
	/* Scan prereq specifier ([ny]xrrset|[ny]xdomain) */
	int bp = tok_find(lp, pq_array);
	if (bp < 0) return bp; /* Syntax error. */
	
	const char *tok = pq_array[bp];
	DBG("%s: type %s\n", __func__, CMD_S(tok));
	lp = skipspace(lp + CMD_L(tok));
	switch(bp) {
	case PQ_NXDOMAIN:
	case PQ_YXDOMAIN:
		return cmd_prereq_domain(lp, params, bp);
	case PQ_NXRRSET:
	case PQ_YXRRSET:
		return cmd_prereq_rrset(lp, params, bp);
	default:
		return KNOT_ERROR;
	}
	
	
	return KNOT_ENOTSUP;
}

int cmd_send(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	DBG("sending packet\n");
	return KNOT_EOK;
}

int cmd_zone(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	
	nsupdate_params_t *npar = NSUP_PARAM(params);
	
	/* Check zone name. */
	size_t len = strcspn(lp, SEP_CHARS);
	if (!dname_isvalid(lp, len)) {
		ERR("failed to parse zone '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	}
	
	/* Extract name. */
	if(npar->zone) free(npar->zone);
	npar->zone = strndup(lp, len);
	if (!npar->zone) return KNOT_ENOMEM;
	return KNOT_EOK;
}

int cmd_server(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	
	/* Fetch specific params. */
	nsupdate_params_t *npar = NSUP_PARAM(params);
	
	/* Extract server address. */
	size_t len = strcspn(lp, SEP_CHARS);
	if (npar->addr) free(npar->addr);
	npar->addr = strndup(lp, len);
	if (!npar->addr) return KNOT_ENOMEM;
	DBG("%s: parsed addr: %s\n", __func__, npar->addr);
	
	/* Attempt to parse port (optional) */
	lp = skipspace(lp + len);
	if (*lp == '\0') return KNOT_EOK;
	char *np = NULL;
	unsigned long port = strtoul(lp, &np, 10);
	if (!np || (*np != '\0' && !isspace(*np))) {
		ERR("failed to parse port number '%s'\n", lp);
		return KNOT_EPARSEFAIL;
	}
	if (port == 0 || port > 65535) {
		ERR("invalid port number '%lu', valid range: <1-65535>\n",
		    port);
		return KNOT_ERANGE;
	}
	npar->port = port;
	DBG("%s: parsed port: %u\n", __func__, npar->port);
	return KNOT_EOK;
}

/*
 *   Not implemented.
 */

int cmd_gsstsig(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}

int cmd_key(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}

int cmd_local(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}

int cmd_oldgsstsig(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}

int cmd_realm(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}

int cmd_show(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}

int cmd_del(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}

int cmd_answer(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}

int cmd_ttl(const char* lp, params_t *params)
{
	DBG("%s: lp='%s'\n", __func__, lp);
	return KNOT_ENOTSUP;
}
