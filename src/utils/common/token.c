/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/common/token.h"
#include "utils/common/msg.h"
#include "libknot/libknot.h"
#include "contrib/ctype.h"

int tok_scan(const char* lp, const char **tbl, int *lpm)
{
	if (lp == NULL || tbl == NULL || *tbl == NULL || lpm == NULL) {
		DBG_NULL;
		return -1;
	}

	const char *prefix = lp; /* Ptr to line start. */
	int i = 0, pl = 1;       /* Match index, prefix length. */
	unsigned char len = 0;   /* Read length. */
	for(;;) {
		const char *tok = tbl[i];
		if (*lp == '\0' || is_space(*lp)) {
			if (tok && TOK_L(tok) == len) { /* Consumed whole w? */
				return i; /* Identifier */
			} else { /* Word is shorter than cmd? */
				break;
			}
		}

		/* Find next prefix match. */
		++len;
		while (tok) {
			if (TOK_L(tok) >= len) {  /* Is prefix of current token */
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
				if (TOK_L(tok) >= len &&
				    memcmp(TOK_S(tok), prefix, len) == 0) {
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

int tok_find(const char *lp, const char **tbl)
{
	if (lp == NULL || tbl == NULL || *tbl == NULL) {
		DBG_NULL;
		return KNOT_EINVAL;
	}

	int lpm = -1;
	int bp = 0;
	if ((bp = tok_scan(lp, tbl, &lpm)) < 0) {
		if (lpm > -1) {
			ERR("unexpected literal: '%s', did you mean '%s' ?",
			    lp, TOK_S(tbl[lpm]));
		} else {
			ERR("unexpected literal: '%s'", lp);
		}

		return KNOT_EPARSEFAIL;
	}

	return bp;
}

const char *tok_skipspace(const char *lp)
{
	if (lp == NULL) {
		DBG_NULL;
		return NULL;
	}

	while (is_space(*lp)) {
		lp += 1;
	}

	return lp;
}
