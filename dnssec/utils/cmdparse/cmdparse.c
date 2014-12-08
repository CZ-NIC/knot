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

#include "cmdparse/cmdparse.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define error(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

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

enum match_type {
	MATCH_NO = 0,
	MATCH_PREFIX,
	MATCH_EXECT,
};

typedef enum match_type match_type_t;

static match_type_t cmd_match(const char *cmd, const char *search)
{
	size_t cmd_len = strlen(cmd);
	size_t search_len = strlen(search);

	if (cmd_len >= search_len && strncmp(search, cmd, search_len) == 0) {
		return cmd_len == search_len ? MATCH_EXECT : MATCH_PREFIX;
	} else {
		return MATCH_NO;
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
		match_type_t m = cmd_match(cmd->name, search);

		if (m == MATCH_NO) {
			continue;
		}

		if (m == MATCH_EXECT) {
			match = cmd;
			break;
		}

		assert(m == MATCH_PREFIX);
		if (match) {
			error("Unambiguous command ('%s' or '%s').",
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
