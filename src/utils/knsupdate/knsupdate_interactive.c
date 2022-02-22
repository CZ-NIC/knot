/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <histedit.h>

#include "contrib/string.h"
#include "utils/common/lookup.h"
#include "utils/common/msg.h"
#include "utils/knsupdate/knsupdate_exec.h"
#include "utils/knsupdate/knsupdate_interactive.h"

#define HISTORY_FILE	".knsupdate_history"

static char *prompt(EditLine *el)
{
	return PROGRAM_NAME"> ";
}

static void print_commands(void)
{
	printf("\n");

	for (const char **cmd = knsupdate_cmd_array; *cmd != NULL; cmd++) {
		printf(" %-18s\n", (*cmd) + 1);
	}
}

static void cmds_lookup(EditLine *el, const char *str, size_t str_len)
{
	lookup_t lookup;
	int ret = lookup_init(&lookup);
	if (ret != KNOT_EOK) {
		return;
	}

	// Fill the lookup with command names.
	for (const char **desc = knsupdate_cmd_array; *desc != NULL; desc++) {
		ret = lookup_insert(&lookup, (*desc) + 1, NULL);
		if (ret != KNOT_EOK) {
			goto cmds_lookup_finish;
		}
	}

	(void)lookup_complete(&lookup, str, str_len, el, true);

cmds_lookup_finish:
	lookup_deinit(&lookup);
}

static unsigned char complete(EditLine *el, int ch)
{
	int argc, token, pos;
	const char **argv;

	const LineInfo *li = el_line(el);
	Tokenizer *tok = tok_init(NULL);

	// Parse the line.
	int ret = tok_line(tok, li, &argc, &argv, &token, &pos);
	if (ret != 0) {
		goto complete_exit;
	}

	// Show possible commands.
	if (argc == 0) {
		print_commands();
		goto complete_exit;
	}

	// Complete the command name.
	if (token == 0) {
		cmds_lookup(el, argv[0], pos);
		goto complete_exit;
	}

	// Find the command descriptor.
	const char **desc = knsupdate_cmd_array;
	while (*desc != NULL && strcmp((*desc) + 1, argv[0]) != 0) {
		desc++;
	}
	if (*desc == NULL) {
		goto complete_exit;
	}

complete_exit:
	tok_reset(tok);
	tok_end(tok);

	return CC_REDISPLAY;
}

int interactive_loop(knsupdate_params_t *params)
{
	char *hist_file = NULL;
	const char *home = getenv("HOME");
	if (home != NULL) {
		hist_file = sprintf_alloc("%s/%s", home, HISTORY_FILE);
	}
	if (hist_file == NULL) {
		INFO("failed to get home directory");
	}

	EditLine *el = el_init(PROGRAM_NAME, stdin, stdout, stderr);
	if (el == NULL) {
		ERR("interactive mode not available");
		free(hist_file);
		return KNOT_ERROR;
	}

	History *hist = history_init();
	if (hist == NULL) {
		ERR("interactive mode not available");
		el_end(el);
		free(hist_file);
		return KNOT_ERROR;
	}

	HistEvent hev = { 0 };
	history(hist, &hev, H_SETSIZE, 1000);
	history(hist, &hev, H_SETUNIQUE, 1);
	el_set(el, EL_HIST, history, hist);
	history(hist, &hev, H_LOAD, hist_file);

	el_set(el, EL_TERMINAL, NULL);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_PROMPT, prompt);
	el_set(el, EL_SIGNAL, 1);
	el_source(el, NULL);

	// Warning: these two el_sets()'s always leak -- in libedit2 library!
	// For more details see this commit's message.
	el_set(el, EL_ADDFN, PROGRAM_NAME"-complete",
	       "Perform "PROGRAM_NAME" completion.", complete);
	el_set(el, EL_BIND, "^I",  PROGRAM_NAME"-complete", NULL);

	int count;
	const char *line;
	while ((line = el_gets(el, &count)) != NULL && count > 0) {
		char command[count + 1];
		memcpy(command, line, count);
		command[count] = '\0';
		// Removes trailing newline
		size_t cmd_len = strcspn(command, "\n");
		command[cmd_len] = '\0';

		if (cmd_len > 0) {
			history(hist, &hev, H_ENTER, command);
			history(hist, &hev, H_SAVE, hist_file);
		}

		// Process the command.
		(void)knsupdate_process_line(command, params);
		if (params->stop) {
			break;
		}
	}

	history_end(hist);
	free(hist_file);

	el_end(el);

	return KNOT_EOK;
}
