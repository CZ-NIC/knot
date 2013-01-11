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

#include "utils/host/host_exec.h"

#include "common/lists.h"		// list
#include "common/errcode.h"		// KNOT_EOK

#include "utils/common/msg.h"		// WARN
#include "utils/common/params.h"	// params_t
#include "utils/common/exec.h"		// process_query

int host_exec(const params_t *params)
{
	node *query = NULL;
	node *server = NULL;

	if (params == NULL) {
		return KNOT_EINVAL;
	}

	switch (params->operation) {
	case OPERATION_QUERY:
		// Loop over query list.
		WALK_LIST(query, params->queries) {
			// Loop over nameserver list.
			WALK_LIST(server, params->servers) {
				int ret = process_query(params,
				                        (query_t *)query,
				                        (server_t *)server);

				if (ret == KNOT_EOK) {
					break;
				}
			}
		}

		break;
	case OPERATION_LIST_SOA:
		break;
	default:
		ERR("unsupported operation\n");
		break;
	}

	return KNOT_EOK;
}
