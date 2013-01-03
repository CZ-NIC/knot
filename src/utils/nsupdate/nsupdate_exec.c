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

#include "utils/nsupdate/nsupdate_exec.h"
#include "utils/common/msg.h"
#include "common/errcode.h"

static int nsupdate_process(const params_t *params, FILE *fp)
{
	return 0;
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
