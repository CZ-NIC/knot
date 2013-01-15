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

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>

#include "utils/nsupdate/nsupdate_exec.h"
#include "utils/common/msg.h"
#include "common/errcode.h"
#include "common/mempattern.h"

/* Declarations of cmd parse functions. */
int cmd_add(const char* lp, const params_t *params);
int cmd_answer(const char* lp, const params_t *params);
int cmd_class(const char* lp, const params_t *params);
int cmd_debug(const char* lp, const params_t *params);
int cmd_del(const char* lp, const params_t *params);
int cmd_gsstsig(const char* lp, const params_t *params);
int cmd_key(const char* lp, const params_t *params);
int cmd_local(const char* lp, const params_t *params);
int cmd_oldgsstsig(const char* lp, const params_t *params);
int cmd_prereq(const char* lp, const params_t *params);
int cmd_realm(const char* lp, const params_t *params);
int cmd_send(const char* lp, const params_t *params);
int cmd_server(const char* lp, const params_t *params);
int cmd_show(const char* lp, const params_t *params);
int cmd_ttl(const char* lp, const params_t *params);
int cmd_update(const char* lp, const params_t *params);
int cmd_zone(const char* lp, const params_t *params);

/* Sorted list of commands.
 * This way we could identify command byte-per-byte and
 * cancel early if the next is lexicographically greater.
 */
const char* cmd_array[] = {
	"\x3" "add",
	"\x6" "answer",
	"\x5" "class",         /* {classname} */
	"\x5" "debug"
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

typedef int (*cmd_handle_f)(const char *lp, const params_t *params);
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
	int bp = 0, pl = 1; /* Match index, prefix length. */
	unsigned char rdlen = 0; /* Read length. */
	for(;;) {
		const char *tok = tbl[bp];
		if (*lp == '\0' || isspace(*lp)) {
			if (tok && tok[0] == rdlen) { /* Consumed whole word? */
				return bp; /* Identifier */
			} else { /* Word is shorter than cmd? */
				break;
			}
		}

		/* Find next prefix match. */
		++rdlen;
		while (tok) {
			if (tok[0] >= rdlen) {  /* Is prefix of current token */
				if (*lp < tok[pl]) {  /* Terminate early. */
					tok = NULL;
					break; /* No match could be found. */
				}
				if (*lp == tok[pl]) { /* Match */
					if(lpm) *lpm = bp;
					++pl;
					break;
				}
			}

			/* No early cut, no match - seek next. */
			while ((tok = tbl[++bp]) != NULL) {
				if (tok[0] >= rdlen &&
				    memcmp(tok+1, prefix, rdlen) == 0) {
					break;
				}
			}
		}

		/* All tokens exhausted. */
		if (tok == NULL) {
			break;
		} else {
			++lp; /* Next char */
		}
	}

	return -1;
}

static int nsupdate_process(const params_t *params, FILE *fp)
{
	/* Process lines. */
	int ret = KNOT_EOK;
	int bp = 0;
	int lpm = -1;
	char *buf = NULL;
	size_t buflen = 0;
	ssize_t rb = 0;
	while ((rb = getline(&buf, &buflen, fp)) != -1) {
		/* Discard newline char */
		if (buf[rb - 1] == '\n') buf[rb - 1] = '\0';
		if ((bp = tok_scan(buf, cmd_array, &lpm)) > -1) {
			const char *cmd = cmd_array[bp];
			ret = cmd_handle[bp](buf + cmd[0] + 1, params);
			if (ret != KNOT_EOK) {
				ERR("incorrect operation '%s' - %s\n",
				    cmd, knot_strerror(ret));
				break;
			}
		} else {
			if (lpm > -1) {
				ERR("incorrect section name: %s, "
				    "did you mean '%s' ?\n",
				    buf, cmd_array[lpm]+1);
			} else {
				ERR("incorrect section name: %s\n", buf);
			}
			ERR("syntax error\n");
			ret = KNOT_EPARSEFAIL;
		}
	}

	free(buf);
	return ret;
}

int nsupdate_exec(const params_t *params)
{
	if (!params) {
		return KNOT_EINVAL;
	}

	/* If not file specified, use stdin. */
	if (EMPTY_LIST(params->qfiles)) {
		return nsupdate_process(params, stdin);
	}

	/* Read from each specified file. */
	strnode_t *n = NULL;
	WALK_LIST(n, params->qfiles) {
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

int cmd_add(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_answer(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_class(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_debug(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_del(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_gsstsig(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_key(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_local(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_oldgsstsig(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_prereq(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_realm(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_send(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_server(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_show(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_ttl(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_update(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}

int cmd_zone(const char* lp, const params_t *params)
{
	return KNOT_ENOTSUP;
}
