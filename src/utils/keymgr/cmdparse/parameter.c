/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "shared/print.h"
#include "utils/keymgr/cmdparse/match.h"
#include "utils/keymgr/cmdparse/parameter.h"

#include <assert.h>

static const parameter_t *param_match(const parameter_t *params, const char *search)
{
	const parameter_t *match = NULL;

	for (const parameter_t *p = params; p->name; p++) {
		cmd_match_t m = cmd_match(p->name, search);
		if (m == CMD_MATCH_NO) {
			continue;
		}

		if (m == CMD_MATCH_EXACT) {
			match = p;
			break;
		}

		assert(m == CMD_MATCH_PREFIX);
		if (p->req_full_match) {
			continue;
		}

		if (match) {
			error("Ambiguous parameter '%s' ('%s' or '%s').",
			      search, match->name, p->name);
			return NULL;
		}

		match = p;
	}

	if (!match) {
		error("Invalid parameter '%s'.", search);
		return NULL;
	}

	return match;
}

int parse_parameters(const parameter_t *params, int argc, char *argv[], void *data)
{
	assert(params);
	assert(argv);

	while (argc > 0) {
		char *search = argv[0];
		const parameter_t *match = param_match(params, search);
		if (!match) {
			// error printed
			return 1;
		}

		assert(match->process);
		int eaten = match->process(argc - 1, argv + 1, match, data);
		if (eaten < 0) {
			return -eaten;
		}

		argc -= (eaten + 1);
		argv += (eaten + 1);
	}

	return 0;
}
