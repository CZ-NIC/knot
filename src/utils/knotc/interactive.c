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

#include <stdio.h>
#include <histedit.h>

#include "knot/common/log.h"
#include "utils/common/lookup.h"
#include "utils/knotc/interactive.h"
#include "utils/knotc/commands.h"
#include "contrib/string.h"

#define PROGRAM_NAME	"knotc"
#define HISTORY_FILE	".knotc_history"

extern params_t params;

static void cmds_lookup(EditLine *el, const char *str, size_t str_len)
{
	lookup_t lookup;
	int ret = lookup_init(&lookup);
	if (ret != KNOT_EOK) {
		return;
	}

	// Fill the lookup with command names.
	for (const cmd_desc_t *desc = cmd_table; desc->name != NULL; desc++) {
		ret = lookup_insert(&lookup, desc->name, NULL);
		if (ret != KNOT_EOK) {
			goto cmds_lookup_finish;
		}
	}

	lookup_index(&lookup);
	lookup_complete(&lookup, str, str_len, el, true);

cmds_lookup_finish:
	lookup_deinit(&lookup);
}

static void local_zones_lookup(EditLine *el, const char *str, size_t str_len)
{
	lookup_t lookup;
	int ret = lookup_init(&lookup);
	if (ret != KNOT_EOK) {
		return;
	}

	char buff[KNOT_DNAME_TXT_MAXLEN + 1];

	// Fill the lookup with local zone names.
	for (conf_iter_t iter = conf_iter(conf(), C_ZONE);
	     iter.code == KNOT_EOK; conf_iter_next(conf(), &iter)) {
		conf_val_t val = conf_iter_id(conf(), &iter);
		char *name = knot_dname_to_str(buff, conf_dname(&val), sizeof(buff));

		ret = lookup_insert(&lookup, name, NULL);
		if (ret != KNOT_EOK) {
			goto local_zones_lookup_finish;
		}
	}

	lookup_index(&lookup);
	lookup_complete(&lookup, str, str_len, el, true);

local_zones_lookup_finish:
	lookup_deinit(&lookup);
}

static char *get_id_name(const char *section)
{
	const cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL && desc->cmd != CTL_CONF_LIST) {
		desc++;
	}
	assert(desc->name != NULL);

	knot_ctl_data_t query = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(desc->cmd),
		[KNOT_CTL_IDX_SECTION] = section
	};

	knot_ctl_t *ctl = NULL;
	knot_ctl_type_t type;
	knot_ctl_data_t reply;

	// Try to get the first group item (possible id).
	if (set_ctl(&ctl, desc, &params) != KNOT_EOK ||
	    knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &query) != KNOT_EOK ||
	    knot_ctl_send(ctl, KNOT_CTL_TYPE_BLOCK, NULL) != KNOT_EOK ||
	    knot_ctl_receive(ctl, &type, &reply) != KNOT_EOK ||
	    type != KNOT_CTL_TYPE_DATA || reply[KNOT_CTL_IDX_ERROR] != NULL) {
		unset_ctl(ctl);
		return NULL;
	}

	char *id_name = strdup(reply[KNOT_CTL_IDX_ITEM]);

	unset_ctl(ctl);

	return id_name;
}

static void id_lookup(EditLine *el, const char *str, size_t str_len,
                      const cmd_desc_t *cmd_desc, const char *section, bool add_space)
{
	// Decide which confdb transaction to ask.
	unsigned ctl_code = (cmd_desc->flags & CMD_CONF_FREQ_TXN) ?
	                    CTL_CONF_GET : CTL_CONF_READ;

	const cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL && desc->cmd != ctl_code) {
		desc++;
	}
	assert(desc->name != NULL);

	char *id_name = get_id_name(section);
	if (id_name == NULL) {
		return;
	}

	knot_ctl_data_t query = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(desc->cmd),
		[KNOT_CTL_IDX_SECTION] = section,
		[KNOT_CTL_IDX_ITEM] = id_name
	};

	lookup_t lookup;
	knot_ctl_t *ctl = NULL;

	if (set_ctl(&ctl, desc, &params) != KNOT_EOK ||
	    knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &query) != KNOT_EOK ||
	    knot_ctl_send(ctl, KNOT_CTL_TYPE_BLOCK, NULL) != KNOT_EOK ||
	    lookup_init(&lookup) != KNOT_EOK) {
		unset_ctl(ctl);
		free(id_name);
		return;
	}

	free(id_name);

	while (true) {
		knot_ctl_type_t type;
		knot_ctl_data_t reply;

		// Receive one section id.
		if (knot_ctl_receive(ctl, &type, &reply) != KNOT_EOK) {
			goto id_lookup_finish;
		}

		// Stop if finished transfer.
		if (type != KNOT_CTL_TYPE_DATA) {
			break;
		}

		// Insert the id into the lookup.
		if (reply[KNOT_CTL_IDX_ERROR] != NULL ||
		    lookup_insert(&lookup, reply[KNOT_CTL_IDX_DATA], NULL) != KNOT_EOK) {
			goto id_lookup_finish;
		}
	}

	lookup_index(&lookup);
	lookup_complete(&lookup, str, str_len, el, add_space);

id_lookup_finish:
	lookup_deinit(&lookup);
	unset_ctl(ctl);
}

static void list_lookup(EditLine *el, const char *section, const char *item)
{
	const cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL && desc->cmd != CTL_CONF_LIST) {
		desc++;
	}
	assert(desc->name != NULL);

	knot_ctl_data_t query = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(desc->cmd),
		[KNOT_CTL_IDX_SECTION] = section
	};

	lookup_t lookup;
	knot_ctl_t *ctl = NULL;

	if (set_ctl(&ctl, desc, &params) != KNOT_EOK ||
	    knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &query) != KNOT_EOK ||
	    knot_ctl_send(ctl, KNOT_CTL_TYPE_BLOCK, NULL) != KNOT_EOK ||
	    lookup_init(&lookup) != KNOT_EOK) {
		unset_ctl(ctl);
		return;
	}

	while (true) {
		knot_ctl_type_t type;
		knot_ctl_data_t reply;

		// Receive one section/item name.
		if (knot_ctl_receive(ctl, &type, &reply) != KNOT_EOK) {
			goto list_lookup_finish;
		}

		// Stop if finished transfer.
		if (type != KNOT_CTL_TYPE_DATA) {
			break;
		}

		const char *str = (section == NULL) ? reply[KNOT_CTL_IDX_SECTION] :
		                                      reply[KNOT_CTL_IDX_ITEM];

		// Insert the name into the lookup.
		if (reply[KNOT_CTL_IDX_ERROR] != NULL ||
		    lookup_insert(&lookup, str, NULL) != KNOT_EOK) {
			goto list_lookup_finish;
		}
	}

	lookup_index(&lookup);
	lookup_complete(&lookup, item, strlen(item), el, section != NULL);

list_lookup_finish:
	lookup_deinit(&lookup);
	unset_ctl(ctl);
}

static void item_lookup(EditLine *el, const char *str, const cmd_desc_t *cmd_desc)
{
	// List all sections.
	if (str == NULL) {
		list_lookup(el, NULL, "");
		return;
	}

	// Check for id specification.
	char *id = (strchr(str, '['));
	if (id != NULL) {
		char *section = strndup(str, id - str);

		// Check for completed id specification.
		char *id_stop = (strchr(id, ']'));
		if (id_stop != NULL) {
			// Complete the item name.
			if (*(id_stop + 1) == '.') {
				list_lookup(el, section, id_stop + 2);
			}
		} else {
			// Complete the section id.
			id_lookup(el, id + 1, strlen(id + 1), cmd_desc, section, false);
		}

		free(section);
	} else {
		// Check for item specification.
		char *dot = (strchr(str, '.'));
		if (dot != NULL) {
			// Complete the item name.
			char *section = strndup(str, dot - str);
			list_lookup(el, section, dot + 1);
			free(section);
		} else {
			// Complete the section name.
			list_lookup(el, NULL, str);
		}
	}
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
	const cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL && strcmp(desc->name, argv[0]) != 0) {
		desc++;
	}
	if (desc->name == NULL) {
		goto complete_exit;
	}

	if (token > 1 || desc->flags == CMD_CONF_FNONE ||
	                 desc->flags == CMD_CONF_FREAD ||
	                 desc->flags == CMD_CONF_FWRITE) {
		goto complete_exit;
	}

	ret = set_config(desc, &params);
	if (ret != KNOT_EOK) {
		goto complete_exit;
	}

	// Complete the zone name.
	if (desc->flags & CMD_CONF_FOPT_ZONE) {
		if (desc->flags & CMD_CONF_FREAD) {
			local_zones_lookup(el, argv[1], pos);
		} else {
			id_lookup(el, argv[1], pos, desc, "zone", true);
		}
		goto complete_exit;
	}

	// Complete the section/id/item name.
	if (desc->flags & (CMD_CONF_FOPT_ITEM | CMD_CONF_FREQ_ITEM)) {
		item_lookup(el, argv[1], desc);
		goto complete_exit;
	}
complete_exit:
	conf_update(NULL);
	tok_reset(tok);
	tok_end(tok);

	return CC_REDISPLAY;
}

static char *prompt(EditLine *el)
{
	return PROGRAM_NAME"> ";
}

int interactive_loop(params_t *params)
{
	char *hist_file = NULL;
	const char *home = getenv("HOME");
	if (home != NULL) {
		hist_file = sprintf_alloc("%s/%s", home, HISTORY_FILE);
	}
	if (hist_file == NULL) {
		log_notice("failed to get home directory");
	}

	EditLine *el = el_init(PROGRAM_NAME, stdin, stdout, stderr);
	if (el == NULL) {
		log_error("interactive mode not available");
		free(hist_file);
		return KNOT_ERROR;
	}

	History *hist = history_init();
	if (hist == NULL) {
		log_error("interactive mode not available");
		el_end(el);
		free(hist_file);
		return KNOT_ERROR;
	}

	HistEvent hev = { 0 };
	history(hist, &hev, H_SETSIZE, 100);
	el_set(el, EL_HIST, history, hist);
	history(hist, &hev, H_LOAD, hist_file);

	el_set(el, EL_TERMINAL, NULL);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_PROMPT, prompt);
	el_set(el, EL_SIGNAL, 1);
	el_source(el, NULL);

	el_set(el, EL_ADDFN, PROGRAM_NAME"-complete",
	       "Perform "PROGRAM_NAME" completion.", complete);
	el_set(el, EL_BIND, "^I",  PROGRAM_NAME"-complete", NULL);

	int count;
	const char *line;
	while ((line = el_gets(el, &count)) != NULL && count > 0) {
		history(hist, &hev, H_ENTER, line);

		Tokenizer *tok = tok_init(NULL);

		// Tokenize the current line.
		int argc;
		const char **argv;
		const LineInfo *li = el_line(el);
		int ret = tok_line(tok, li, &argc, &argv, NULL, NULL);
		if (ret != 0) {
			continue;
		}

		// Process the command.
		ret = process_cmd(argc, argv, params);

		tok_reset(tok);
		tok_end(tok);

		// Check for the exit command.
		if (ret == KNOT_CTL_ESTOP) {
			break;
		}
	}

	history(hist, &hev, H_SAVE, hist_file);
	history_end(hist);
	free(hist_file);

	el_end(el);

	return KNOT_EOK;
}
