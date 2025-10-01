/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <dirent.h>
#include <histedit.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>

#include "knot/common/log.h"
#include "utils/common/lookup.h"
#include "utils/knotc/interactive.h"
#include "utils/knotc/commands.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/string.h"

#define PROGRAM_NAME	"knotc"
#define HISTORY_FILE	".knotc_history"

extern params_t params;

typedef struct {
	const char **args;
	int count;
	bool dname;
} dup_check_ctx_t;

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

	(void)lookup_complete(&lookup, str, str_len, el, true);

cmds_lookup_finish:
	lookup_deinit(&lookup);
}

static void remove_duplicates(lookup_t *lookup, dup_check_ctx_t *check_ctx)
{
	if (check_ctx == NULL) {
		return;
	}

	knot_dname_txt_storage_t dname = "";
	for (int i = 0; i < check_ctx->count; i++) {
		const char *arg = (check_ctx->args)[i];
		size_t len = strlen(arg);
		if (check_ctx->dname && len > 1 && arg[len - 1] != '.') {
			strlcat(dname, arg, sizeof(dname));
			strlcat(dname, ".", sizeof(dname));
			arg = dname;
		}
		(void)lookup_remove(lookup, arg);
	}
}

static void local_zones_lookup(EditLine *el, const char *str, size_t str_len,
                               dup_check_ctx_t *check_ctx)
{
	lookup_t lookup;
	int ret = lookup_init(&lookup);
	if (ret != KNOT_EOK) {
		return;
	}

	knot_dname_txt_storage_t buff;

	// Fill the lookup with local zone names.
	for (conf_iter_t iter = conf_iter(conf(), C_ZONE);
	     iter.code == KNOT_EOK; conf_iter_next(conf(), &iter)) {
		conf_val_t val = conf_iter_id(conf(), &iter);
		char *name = knot_dname_to_str(buff, conf_dname(&val), sizeof(buff));

		ret = lookup_insert(&lookup, name, NULL);
		if (ret != KNOT_EOK) {
			conf_iter_finish(conf(), &iter);
			goto local_zones_lookup_finish;
		}
	}

	remove_duplicates(&lookup, check_ctx);
	(void)lookup_complete(&lookup, str, str_len, el, true);

local_zones_lookup_finish:
	lookup_deinit(&lookup);
}

static void list_separators(EditLine *el, const char *separators)
{
	lookup_t lookup;
	if (lookup_init(&lookup) != KNOT_EOK) {
		return;
	}

	size_t count = strlen(separators);
	for (int i = 0; i < count; i++) {
		char sep[2] = { separators[i] };
		(void)lookup_insert(&lookup, sep, NULL);
	}
	(void)lookup_complete(&lookup, "", 0, el, false);

	lookup_deinit(&lookup);
}

static bool rmt_lookup(EditLine *el, const char *str, size_t str_len,
                       const char *section, const char *item, const char *id,
                       dup_check_ctx_t *check_ctx, bool add_space, const char *filters,
                       knot_ctl_idx_t idx)
{
	const cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL && desc->cmd != CTL_CONF_LIST) {
		desc++;
	}
	assert(desc->name != NULL);

	knot_ctl_data_t query = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(desc->cmd),
		[KNOT_CTL_IDX_SECTION] = section,
		[KNOT_CTL_IDX_ITEM] = item,
		[KNOT_CTL_IDX_ID] = id,
		[KNOT_CTL_IDX_FILTERS] = filters,
	};

	lookup_t lookup;
	knot_ctl_t *ctl = NULL;
	bool found = false;

	if (set_ctl(&ctl, params.socket, DEFAULT_CTL_TIMEOUT_MS, desc) != KNOT_EOK ||
	    knot_ctl_send(ctl, KNOT_CTL_TYPE_DATA, &query) != KNOT_EOK ||
	    knot_ctl_send(ctl, KNOT_CTL_TYPE_BLOCK, NULL) != KNOT_EOK ||
	    lookup_init(&lookup) != KNOT_EOK) {
		unset_ctl(ctl);
		return found;
	}

	while (true) {
		knot_ctl_type_t type;
		knot_ctl_data_t reply;

		if (knot_ctl_receive(ctl, &type, &reply) != KNOT_EOK) {
			goto rmt_lookup_finish;
		}

		if (type != KNOT_CTL_TYPE_DATA && type != KNOT_CTL_TYPE_EXTRA) {
			break;
		}

		const char *error = reply[KNOT_CTL_IDX_ERROR];
		if (error != NULL) {
			printf("\nnotice: (%s)\n", error);
			goto rmt_lookup_finish;
		}

		// Insert the received name into the lookup.
		if (lookup_insert(&lookup, reply[idx], NULL) != KNOT_EOK) {
			goto rmt_lookup_finish;
		}
	}

	remove_duplicates(&lookup, check_ctx);
	if (lookup_complete(&lookup, str, str_len, el, add_space) == KNOT_EOK &&
	    str != NULL && strcmp(lookup.found.key, str) == 0) {
		found = true;
	}

rmt_lookup_finish:
	lookup_deinit(&lookup);
	unset_ctl(ctl);

	return found;
}

static bool id_lookup(EditLine *el, const char *str, size_t str_len,
                      const char *section, const cmd_desc_t *cmd_desc,
                      dup_check_ctx_t *ctx, bool add_space, bool zones)
{
	char filters[4] = "";
	if (zones) {
		strlcat(filters, CTL_FILTER_LIST_ZONES, sizeof(filters));
	} else if (cmd_desc->flags & CMD_FREQ_TXN) {
		strlcat(filters, CTL_FILTER_LIST_TXN, sizeof(filters));
	}

	return rmt_lookup(el, str, str_len, section, NULL, NULL, ctx, add_space,
	                  filters, KNOT_CTL_IDX_ID);
}

static void val_lookup(EditLine *el, const char *str, size_t str_len,
                       const char *section, const char *item, const char *id,
                       dup_check_ctx_t *ctx, bool list_schema)
{
	char filters[4] = CTL_FILTER_LIST_TXN;
	if (list_schema) {
		strlcat(filters, CTL_FILTER_LIST_SCHEMA, sizeof(filters));
	}

	(void)rmt_lookup(el, str, str_len, section, item, id, ctx, true,
	                 filters, KNOT_CTL_IDX_DATA);
}

static bool list_lookup(EditLine *el, const char *str, const char *section)
{
	const char *filters = CTL_FILTER_LIST_SCHEMA;
	knot_ctl_idx_t idx = (section == NULL) ? KNOT_CTL_IDX_SECTION : KNOT_CTL_IDX_ITEM;

	return rmt_lookup(el, str, strlen(str), section, NULL, NULL, NULL,
	                  section != NULL, filters, idx);
}

static void item_lookup(EditLine *el, const char *str, const cmd_desc_t *cmd_desc)
{
	// List all sections.
	if (str == NULL) {
		(void)list_lookup(el, "", NULL);
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
				(void)list_lookup(el, id_stop + 2, section);
			} else {
				list_separators(el, ".");
			}
		} else {
			// Complete the section id.
			if (id_lookup(el, id + 1, strlen(id + 1), section, cmd_desc,
			              NULL, false, false)) {
				list_separators(el, "]");
			}
		}

		free(section);
	} else {
		// Check for item specification.
		char *dot = (strchr(str, '.'));
		if (dot != NULL) {
			// Complete the item name.
			char *section = strndup(str, dot - str);
			(void)list_lookup(el, dot + 1, section);
			free(section);
		} else {
			// Complete the section name.
			if (list_lookup(el, str, NULL)) {
				list_separators(el, "[.");
			}
		}
	}
}

static void filter_lookup(EditLine *el, const char *str, const cmd_desc_t *cmd,
			  dup_check_ctx_t *dup_ctx)
{
	lookup_t lookup;
	int ret = lookup_init(&lookup);
	if (ret != KNOT_EOK) {
		return;
	}

	if (lookup_insert(&lookup, CMD_ZONE_STATUS, (void *)zone_status_filters) != KNOT_EOK ||
	    lookup_insert(&lookup, CMD_ZONE_BACKUP, (void *)zone_backup_filters) != KNOT_EOK ||
	    lookup_insert(&lookup, CMD_ZONE_RESTORE, (void *)zone_backup_filters) != KNOT_EOK ||
	    lookup_insert(&lookup, CMD_ZONE_PURGE, (void *)zone_purge_filters) != KNOT_EOK ||
	    lookup_insert(&lookup, CMD_ZONE_BEGIN, (void *)zone_begin_filters) != KNOT_EOK ||
	    lookup_insert(&lookup, CMD_ZONE_FLUSH, (void *)zone_flush_filters) != KNOT_EOK ||
	    lookup_insert(&lookup, CMD_CONF_IMPORT, (void *)conf_import_filters) != KNOT_EOK ||
	    lookup_insert(&lookup, CMD_CONF_EXPORT, (void *)conf_export_filters) != KNOT_EOK) {
		goto cmds_lookup_finish;
	}

	ret = lookup_search(&lookup, cmd->name, strlen(cmd->name));
	if (ret == KNOT_EOK) {
		lookup_t flookup;
		ret = lookup_init(&flookup);
		if (ret != KNOT_EOK) {
			goto cmds_lookup_finish;
		}

		for (const filter_desc_t *it = lookup.found.data; it->name != NULL; ++it) {
			ret = lookup_insert(&flookup, it->name, NULL);
			if (ret != KNOT_EOK) {
				goto cmds_lookup_finish_both;
			}
		}

		remove_duplicates(&flookup, dup_ctx);
		(void)lookup_complete(&flookup, str, strlen(str), el, true);
cmds_lookup_finish_both:
		lookup_deinit(&flookup);
	}

cmds_lookup_finish:
	lookup_deinit(&lookup);
}

static void path_lookup(EditLine *el, const char *str, bool dirsonly)
{
	if (str == NULL || *str == '\0') {
		str = "./";
	}

#ifndef PATH_MAX        // GNU Hurd needs this.
	long PATH_MAX = MAX(pathconf(str, _PC_PATH_MAX), 1024);
#endif

	char path[PATH_MAX]; // avoid editing argument directly
	strlcpy(path, str, PATH_MAX);
	char *sep = strrchr(path, '/');
	char *dir, *base;
	if (sep == NULL) {
		dir = "./";
		base = path;
	} else {
		dir = (sep == path) ? "/" : path;
		base = sep + 1;
		*sep = '\0';
	}

	struct dirent **namelist;
	int nnames = scandir(dir, &namelist, NULL, alphasort);
	if (nnames == -1) {
		return;
	}

	lookup_t lookup;
	int ret = lookup_init(&lookup);
	if (ret != KNOT_EOK) {
		goto finish2;
	}

	if (sep != NULL) {
		*sep = '/';
	}
	char obase[NAME_MAX + 1];  // Max. name length + terminator.
	strlcpy(obase, base, NAME_MAX + 1);

	struct stat sb;
	for (int i = 0; i < nnames; ++i) {
		const struct dirent *it = namelist[i];
		bool is_dir = (it->d_type == DT_DIR);
		if (it->d_type == DT_LNK) {
			strlcpy(base, it->d_name, PATH_MAX - (size_t)(base - path));
			is_dir = !stat(path, &sb) && S_ISDIR(sb.st_mode);
		}
		if ((!dirsonly || is_dir) &&
		    (strcmp(it->d_name, ".") && strcmp(it->d_name, ".."))) {
			char buf[NAME_MAX + 2];  // Max. name length + slash + terminator.
			(void)snprintf(buf, NAME_MAX + 2, is_dir ? "%s/" : "%s", it->d_name);
			ret = lookup_insert(&lookup, buf, NULL);
			if (ret != KNOT_EOK) {
				goto finish1;
			}
		}
	}

	ret = lookup_complete(&lookup, obase, strlen(obase), el, false);
	if (ret == KNOT_EOK) {
		strlcpy(base, lookup.found.key, PATH_MAX - (size_t)(base - path));
		if (!stat(path, &sb) && !S_ISDIR(sb.st_mode)) {
			el_insertstr(el, " ");
		}
	}

finish1:
	lookup_deinit(&lookup);
finish2:
	for (int i = 0; i < nnames; ++i) {
		free(namelist[i]);
	}
	free(namelist);
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

	// Finish if a command with no or unsupported arguments.
	if (desc->flags == CMD_FNONE || desc->flags == CMD_FREAD ||
	    desc->flags == CMD_FWRITE) {
		goto complete_exit;
	}

	ret = set_config(desc, &params, true);
	if (ret != KNOT_EOK) {
		goto complete_exit;
	}

	// Complete filters and path arguments.
	if ((desc->flags & CMD_FOPT_FILTER) && token > 0) {
		if ((argv[token] == NULL || *argv[token] != '+') &&
		    (!strcmp(CMD_CONF_IMPORT, argv[0]) || !strcmp(CMD_CONF_EXPORT, argv[0]))) {
			path_lookup(el, argv[token], false);
			goto complete_exit;
		}

		if (token < argc && *argv[token] == '+') {
			dup_check_ctx_t ctx = { &argv[1], token - 1, false };
			filter_lookup(el, argv[token], desc, &ctx);
			goto complete_exit;
		}

		switch (desc->cmd) {
		case CTL_ZONE_FLUSH:
			if (!strcmp(zone_flush_filters[0].name, argv[token - 1])) {
				path_lookup(el, argv[token], true);
				goto complete_exit;
			}
			break;
		case CTL_ZONE_BACKUP:
		case CTL_ZONE_RESTORE:
			if (!strcmp(zone_backup_filters[0].name, argv[token - 1])) {
				path_lookup(el, argv[token], true);
				goto complete_exit;
			}
			break;
		default:
			break;
		}
	}

	// Complete zone-key-rollover key type.
	if (desc->cmd == CTL_ZONE_KEY_ROLL && token == 2) {
		lookup_t lookup;
		if (lookup_init(&lookup) != KNOT_EOK) {
			goto complete_exit;
		}
		if (lookup_insert(&lookup, CMD_ROLLOVER_ZSK, NULL) == KNOT_EOK &&
		    lookup_insert(&lookup, CMD_ROLLOVER_KSK, NULL) == KNOT_EOK) {
			(void)lookup_complete(&lookup, argv[2], pos, el, true);
		}
		lookup_deinit(&lookup);
		goto complete_exit;
	}

	// Complete the zone name.
	if (desc->flags & (CMD_FREQ_ZONE | CMD_FOPT_ZONE)) {
		if (token > 1 && !(desc->flags & CMD_FOPT_ZONE)) {
			goto complete_exit;
		}

		dup_check_ctx_t ctx = { &argv[1], token - 1, true };
		if (desc->flags & CMD_FREAD) {
			local_zones_lookup(el, argv[token], pos, &ctx);
		} else {
			id_lookup(el, argv[token], pos, "zone", desc, &ctx, true, true);
		}
		goto complete_exit;
	// Complete the section/id/item name or item value.
	} else if (desc->flags & (CMD_FOPT_ITEM | CMD_FREQ_ITEM)) {
		if (token == 1) {
			item_lookup(el, argv[1], desc);
		} else if (desc->flags & CMD_FOPT_DATA) {
			char section[YP_MAX_TXT_KEY_LEN + 1] = "";
			char item[YP_MAX_TXT_KEY_LEN + 1] = "";
			char id[KNOT_DNAME_TXT_MAXLEN + 1] = "";

			assert(YP_MAX_TXT_KEY_LEN == 127);
			assert(KNOT_DNAME_TXT_MAXLEN == 1004);
			if (sscanf(argv[1], "%127[^[][%1004[^]]].%127s", section, id, item) == 3 ||
			    sscanf(argv[1], "%127[^.].%127s", section, item) == 2) {
				dup_check_ctx_t ctx = { &argv[2], token - 2 };
				val_lookup(el, argv[token], pos, section, item, id,
				           &ctx, desc->flags & CMD_FLIST_SCHEMA);
			}
		}
		goto complete_exit;
	// Complete status command detail.
	} else if (desc->cmd == CTL_STATUS && token == 1) {
		lookup_t lookup;
		if (lookup_init(&lookup) != KNOT_EOK) {
			goto complete_exit;
		}
		if (lookup_insert(&lookup, CMD_STATUS_VERSION, NULL) == KNOT_EOK &&
		    lookup_insert(&lookup, CMD_STATUS_WORKERS, NULL) == KNOT_EOK &&
		    lookup_insert(&lookup, CMD_STATUS_CONFIG, NULL) == KNOT_EOK &&
		    lookup_insert(&lookup, CMD_STATUS_CERT, NULL) == KNOT_EOK) {
			(void)lookup_complete(&lookup, argv[1], pos, el, true);
		}
		lookup_deinit(&lookup);
		goto complete_exit;
	}

complete_exit:
	conf_update(NULL, CONF_UPD_FNONE);
	tok_reset(tok);
	tok_end(tok);

	return CC_REDISPLAY;
}

static char *prompt(EditLine *el)
{
	return PROGRAM_NAME"> ";
}

int interactive_loop(params_t *process_params)
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
		Tokenizer *tok = tok_init(NULL);

		// Tokenize the current line.
		int argc;
		const char **argv;
		const LineInfo *li = el_line(el);
		int ret = tok_line(tok, li, &argc, &argv, NULL, NULL);
		if (ret == 0 && argc != 0) {
			history(hist, &hev, H_ENTER, line);
			history(hist, &hev, H_SAVE, hist_file);

			// Process the command.
			ret = process_cmd(argc, argv, process_params);
		}

		tok_reset(tok);
		tok_end(tok);

		// Check for the exit command.
		if (ret == KNOT_CTL_ESTOP) {
			break;
		}
	}

	history_end(hist);
	free(hist_file);

	el_end(el);

	return KNOT_EOK;
}
