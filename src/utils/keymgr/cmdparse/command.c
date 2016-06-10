/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "utils/keymgr/cmdparse/command.h"
#include "utils/keymgr/cmdparse/match.h"

#include <assert.h>
#include <string.h>

#define HELP_COMMAND "help"

/*!
 * Print list of available commands.
 */
static void command_help(const command_t *commands)
{
	fprintf(stderr, "Available commands:\n");

	for (const command_t *cmd = commands; cmd->name != NULL; cmd++) {
		if (cmd->help) {
			fprintf(stderr, "- %s (%s)\n", cmd->name, cmd->help);
		} else {
			fprintf(stderr, "- %s\n", cmd->name);
		}
	}
}

/*!
 * Execute a subcommand.
 */
int subcommand(const command_t *commands, int argc, char *argv[])
{
	assert(commands);
	assert(argv);

	if (argc <= 0 || argv[0][0] == '\0') {
		error("No command specified.");
		return 1;
	}

	char *search = argv[0];
	const command_t *match = NULL;

	if (strcmp(search, HELP_COMMAND) == 0) {
		command_help(commands);
		return 0;
	}

	for (const command_t *cmd = commands; cmd->name != NULL;  cmd++) {
		cmd_match_t m = cmd_match(cmd->name, search);

		if (m == CMD_MATCH_NO) {
			continue;
		}

		if (m == CMD_MATCH_EXACT) {
			match = cmd;
			break;
		}

		assert(m == CMD_MATCH_PREFIX);
		if (match) {
			error("Ambiguous command ('%s' or '%s').",
			      match->name, cmd->name);
			return 1;
		}

		match = cmd;
	}

	if (!match) {
		error("Unknown command.");
		return 1;
	}

	assert(match->process);

	return match->process(argc - 1, argv + 1);
}
