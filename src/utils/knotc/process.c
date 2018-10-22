/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/stat.h>

#include "knot/conf/conf.h"
#include "knot/common/log.h"
#include "utils/knotc/commands.h"
#include "utils/knotc/process.h"

static const cmd_desc_t *get_cmd_desc(const char *command)
{
	/* Find requested command. */
	const cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL) {
		if (strcmp(desc->name, command) == 0) {
			break;
		}
		desc++;
	}
	if (desc->name == NULL) {
		log_error("invalid command '%s'", command);
		return NULL;
	}

	return desc;
}

static bool get_cmd_force_flag(const char *arg)
{
	if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
		return true;
	}
	return false;
}

int set_config(const cmd_desc_t *desc, params_t *params)
{
	if (params->config != NULL && params->confdb != NULL) {
		log_error("ambiguous configuration source");
		return KNOT_EINVAL;
	}

	/* Mask relevant flags. */
	cmd_flag_t flags = desc->flags & (CMD_FREAD | CMD_FWRITE);
	cmd_flag_t mod_flags = desc->flags & (CMD_FOPT_MOD | CMD_FREQ_MOD);

	/* Choose the optimal config source. */
	struct stat st;
	bool import = false;
	if (flags == CMD_FNONE && params->socket != NULL) {
		/* Control operation, known socket, skip configuration. */
		return KNOT_EOK;
	} else if (params->confdb != NULL) {
		import = false;
	} else if (flags == CMD_FWRITE) {
		import = false;
		params->confdb = CONF_DEFAULT_DBDIR;
	} else if (params->config != NULL){
		import = true;
	} else if (stat(CONF_DEFAULT_DBDIR, &st) == 0) {
		import = false;
		params->confdb = CONF_DEFAULT_DBDIR;
	} else if (stat(CONF_DEFAULT_FILE, &st) == 0) {
		import = true;
		params->config = CONF_DEFAULT_FILE;
	} else if (flags != CMD_FNONE) {
		log_error("no configuration source available");
		return KNOT_EINVAL;
	}

	const char *src = import ? params->config : params->confdb;
	log_debug("%s '%s'", import ? "config" : "confdb",
	          (src != NULL) ? src : "empty");

	/* Prepare config flags. */
	conf_flag_t conf_flags = CONF_FNOHOSTNAME;
	if (params->confdb != NULL && !(flags & CMD_FWRITE)) {
		conf_flags |= CONF_FREADONLY;
	}
	if (import || mod_flags & CMD_FOPT_MOD) {
		conf_flags |= CONF_FOPTMODULES;
	} else if (mod_flags & CMD_FREQ_MOD) {
		conf_flags |= CONF_FREQMODULES;
	}

	/* Open confdb. */
	conf_t *new_conf = NULL;
	int ret = conf_new(&new_conf, conf_schema, params->confdb,
	                   params->max_conf_size, conf_flags);
	if (ret != KNOT_EOK) {
		log_error("failed to open configuration database '%s' (%s)",
		          (params->confdb != NULL) ? params->confdb : "",
		          knot_strerror(ret));
		return ret;
	}

	/* Import the config file. */
	if (import) {
		ret = conf_import(new_conf, params->config, true);
		if (ret != KNOT_EOK) {
			log_error("failed to load configuration file '%s' (%s)",
			          params->config, knot_strerror(ret));
			conf_free(new_conf);
			return ret;
		}
	}

	/* Update to the new config. */
	conf_update(new_conf, CONF_UPD_FNONE);

	return KNOT_EOK;
}

int set_ctl(knot_ctl_t **ctl, const cmd_desc_t *desc, params_t *params)
{
	if (desc == NULL) {
		*ctl = NULL;
		return KNOT_EINVAL;
	}

	/* Mask relevant flags. */
	cmd_flag_t flags = desc->flags & (CMD_FREAD | CMD_FWRITE);

	/* Check if control socket is required. */
	if (flags != CMD_FNONE) {
		*ctl = NULL;
		return KNOT_EOK;
	}

	/* Get control socket path. */
	char *path = NULL;
	if (params->socket != NULL) {
		path = strdup(params->socket);
	} else {
		conf_val_t listen_val = conf_get(conf(), C_CTL, C_LISTEN);
		conf_val_t rundir_val = conf_get(conf(), C_SRV, C_RUNDIR);
		char *rundir = conf_abs_path(&rundir_val, NULL);
		path = conf_abs_path(&listen_val, rundir);
		free(rundir);
	}
	if (path == NULL) {
		log_error("empty control socket path");
		return KNOT_EINVAL;
	}

	log_debug("socket '%s'", path);

	*ctl = knot_ctl_alloc();
	if (*ctl == NULL) {
		free(path);
		return KNOT_ENOMEM;
	}

	knot_ctl_set_timeout(*ctl, params->timeout);

	int ret = knot_ctl_connect(*ctl, path);
	if (ret != KNOT_EOK) {
		knot_ctl_free(*ctl);
		*ctl = NULL;
		log_error("failed to connect to socket '%s' (%s)", path,
		          knot_strerror(ret));
		free(path);
		return ret;
	}

	free(path);

	return KNOT_EOK;
}

void unset_ctl(knot_ctl_t *ctl)
{
	if (ctl == NULL) {
		return;
	}

	int ret = knot_ctl_send(ctl, KNOT_CTL_TYPE_END, NULL);
	if (ret != KNOT_EOK && ret != KNOT_ECONN) {
		log_error("failed to finish control (%s)", knot_strerror(ret));
	}

	knot_ctl_close(ctl);
	knot_ctl_free(ctl);
}

int process_cmd(int argc, const char **argv, params_t *params)
{
	if (argc == 0) {
		return KNOT_ENOTSUP;
	}

	/* Check the command name. */
	const cmd_desc_t *desc = get_cmd_desc(argv[0]);
	if (desc == NULL) {
		return KNOT_ENOENT;
	}

	/* Check for exit. */
	if (desc->fcn == NULL) {
		return KNOT_CTL_ESTOP;
	}

	/* Set up the configuration. */
	int ret = set_config(desc, params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Prepare command parameters. */
	cmd_args_t args = {
		.desc = desc,
		.argc = argc - 1,
		.argv = argv + 1,
		.force = params->force
	};

	/* Check for --force flag after command. */
	if (args.argc > 0 && get_cmd_force_flag(args.argv[0])) {
		args.force = true;
		args.argc--;
		args.argv++;
	}

	/* Set control interface if necessary. */
	ret = set_ctl(&args.ctl, desc, params);
	if (ret != KNOT_EOK) {
		conf_update(NULL, CONF_UPD_FNONE);
		return ret;
	}

	/* Execute the command. */
	ret = desc->fcn(&args);

	/* Cleanup */
	unset_ctl(args.ctl);
	conf_update(NULL, CONF_UPD_FNONE);

	return ret;
}
