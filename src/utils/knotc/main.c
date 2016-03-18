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

#include <getopt.h>
#include <stdio.h>
#include <sys/stat.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "libknot/libknot.h"
#include "utils/knotc/commands.h"
#include "utils/common/params.h"
#include "utils/common/strtonum.h"

#define PROGRAM_NAME "knotc"

#define DEFAULT_CTL_TIMEOUT	5

static void print_help(void)
{
	printf("Usage: %s [parameters] <action> [action_args]\n"
	       "\n"
	       "Parameters:\n"
	       " -c, --config <file>                  Use a textual configuration file.\n"
	       "                                       (default %s)\n"
	       " -C, --confdb <dir>                   Use a binary configuration database directory.\n"
	       "                                       (default %s)\n"
	       " -s, --socket <path>                  Use a control UNIX socket path.\n"
	       "                                       (default %s)\n"
	       " -t, --timeout <sec>                  Use a control socket timeout in seconds.\n"
	       "                                       (default %u seconds)\n"
	       " -f, --force                          Forced operation. Overrides some checks.\n"
	       " -v, --verbose                        Enable debug output.\n"
	       " -h, --help                           Print the program help.\n"
	       " -V, --version                        Print the program version.\n"
	       "\n"
	       "Actions:\n",
	       PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR,
	       RUN_DIR "/knot.sock", DEFAULT_CTL_TIMEOUT);

	for (const cmd_help_t *cmd = cmd_help_table; cmd->name != NULL; cmd++) {
		printf(" %-15s %-20s %s\n", cmd->name, cmd->params, cmd->desc);
	}

	printf("\n"
	       "Note:\n"
	       " Empty <zone> parameter means all zones.\n"
	       " Type <item> parameter in the form of <section>[<identifier>].<name>.\n"
	       " (*) indicates a local operation which requires a configuration.\n");
}

static const cmd_desc_t* get_cmd_desc(const char *command)
{
	/* Translate old command name. */
	for (const cmd_desc_old_t *desc = cmd_table_old; desc->old_name != NULL; desc++) {
		if (strcmp(desc->old_name, command) == 0) {
			log_notice("obsolete command '%s', using '%s' instead",
			           desc->old_name, desc->new_name);
			command = desc->new_name;
			break;
		}
	}

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

static int set_config(const cmd_desc_t *desc, const char *confdb,
                      const char *config, char *socket)
{
	if (config != NULL && confdb != NULL) {
		log_error("ambiguous configuration source");
		return KNOT_EINVAL;
	}

	/* Mask relevant flags. */
	cmd_conf_flag_t flags = desc->flags & (CMD_CONF_FREAD | CMD_CONF_FWRITE);

	/* Choose the optimal config source. */
	struct stat st;
	bool import = false;
	if (flags == CMD_CONF_FNONE && socket != NULL) {
		import = false;
		confdb = NULL;
	} else if (confdb != NULL) {
		import = false;
	} else if (flags == CMD_CONF_FWRITE) {
		import = false;
		confdb = CONF_DEFAULT_DBDIR;
	} else if (config != NULL){
		import = true;
	} else if (stat(CONF_DEFAULT_DBDIR, &st) == 0) {
		import = false;
		confdb = CONF_DEFAULT_DBDIR;
	} else if (stat(CONF_DEFAULT_FILE, &st) == 0) {
		import = true;
		config = CONF_DEFAULT_FILE;
	} else if (flags != CMD_CONF_FNONE) {
		log_error("no configuration source available");
		return KNOT_EINVAL;
	}

	const char *src = import ? config : confdb;
	log_debug("%s '%s'", import ? "config" : "confdb",
	          (src != NULL) ? src : "empty");

	/* Prepare config flags. */
	conf_flag_t conf_flags = CONF_FNOHOSTNAME;
	if (confdb != NULL && !(flags & CMD_CONF_FWRITE)) {
		conf_flags |= CONF_FREADONLY;
	}

	/* Open confdb. */
	conf_t *new_conf = NULL;
	int ret = conf_new(&new_conf, conf_scheme, confdb, conf_flags);
	if (ret != KNOT_EOK) {
		log_error("failed to open configuration database '%s' (%s)",
		          (confdb != NULL) ? confdb : "", knot_strerror(ret));
		return ret;
	}

	/* Import the config file. */
	if (import) {
		ret = conf_import(new_conf, config, true);
		if (ret != KNOT_EOK) {
			log_error("failed to load configuration file '%s' (%s)",
			          config, knot_strerror(ret));
			conf_free(new_conf);
			return ret;
		}
	}

	/* Update to the new config. */
	conf_update(new_conf);

	return KNOT_EOK;
}

static int set_args_ctl(knot_ctl_t **ctl, const cmd_desc_t *desc,
                        const char *socket, int timeout)
{
	if (desc == NULL) {
		*ctl = NULL;
		return KNOT_EINVAL;
	}

	/* Mask relevant flags. */
	cmd_conf_flag_t flags = desc->flags & (CMD_CONF_FREAD | CMD_CONF_FWRITE);

	/* Check if control socket is required. */
	if (flags != CMD_CONF_FNONE) {
		*ctl = NULL;
		return KNOT_EOK;
	}

	/* Get control socket path. */
	char *path = NULL;
	if (socket != NULL) {
		path = strdup(socket);
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

	knot_ctl_set_timeout(*ctl, timeout);

	int ret = knot_ctl_connect(*ctl, path);
	if (ret != KNOT_EOK) {
		knot_ctl_free(*ctl);
		log_error("failed to connect to socket '%s' (%s)", path,
		          knot_strerror(ret));
		free(path);
		return ret;
	}

	free(path);

	return KNOT_EOK;
}

static void unset_args_ctl(knot_ctl_t *ctl)
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

int main(int argc, char **argv)
{
	cmd_flag_t flags = CMD_FNONE;
	const char *config = NULL;
	const char *confdb = NULL;
	char *socket = NULL;
	int timeout = DEFAULT_CTL_TIMEOUT * 1000;
	bool verbose = false;

	/* Long options. */
	struct option opts[] = {
		{ "config",  required_argument, NULL, 'c' },
		{ "confdb",  required_argument, NULL, 'C' },
		{ "socket",  required_argument, NULL, 's' },
		{ "timeout", required_argument, NULL, 't' },
		{ "force",   no_argument,       NULL, 'f' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	/* Parse command line arguments */
	int opt = 0, li = 0;
	while ((opt = getopt_long(argc, argv, "c:C:s:t:fvhV", opts, &li)) != -1) {
		switch (opt) {
		case 'c':
			config = optarg;
			break;
		case 'C':
			confdb = optarg;
			break;
		case 's':
			socket = optarg;
			break;
		case 't':
			if (knot_str2int(optarg, &timeout) != KNOT_EOK) {
				print_help();
				return EXIT_FAILURE;
			}
			// Convert to milliseconds.
			timeout = (timeout > 0) ? timeout * 1000 : 0;
			break;
		case 'f':
			flags |= CMD_FFORCE;
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			print_help();
			return EXIT_SUCCESS;
		case 'V':
			print_version(PROGRAM_NAME);
			return EXIT_SUCCESS;
		default:
			print_help();
			return EXIT_FAILURE;
		}
	}

	/* Check if there's at least one remaining non-option. */
	if (argc - optind < 1) {
		print_help();
		return EXIT_FAILURE;
	}

	/* Set up simplified logging just to stdout/stderr. */
	log_init();
	log_levels_set(LOGT_STDOUT, LOG_ANY, LOG_MASK(LOG_INFO) | LOG_MASK(LOG_NOTICE));
	log_levels_set(LOGT_STDERR, LOG_ANY, LOG_UPTO(LOG_WARNING));
	log_levels_set(LOGT_SYSLOG, LOG_ANY, 0);
	log_flag_set(LOG_FNO_TIMESTAMP | LOG_FNO_INFO);
	if (verbose) {
		log_levels_add(LOGT_STDOUT, LOG_ANY, LOG_MASK(LOG_DEBUG));
	}

	/* Check the command name. */
	const cmd_desc_t *desc = get_cmd_desc(argv[optind]);
	if (desc == NULL) {
		log_close();
		return EXIT_FAILURE;
	}

	/* Set up the configuration. */
	int ret = set_config(desc, confdb, config, socket);
	if (ret != KNOT_EOK) {
		log_close();
		return EXIT_FAILURE;
	}

	/* Prepare command parameters. */
	cmd_args_t args = {
		.desc = desc,
		.argc = argc - optind - 1,
		.argv = argv + optind + 1,
		.flags = flags
	};

	/* Set control interface if necessary. */
	ret = set_args_ctl(&args.ctl, desc, socket, timeout);
	if (ret != KNOT_EOK) {
		conf_free(conf());
		log_close();
		return EXIT_FAILURE;
	}

	/* Execute the command. */
	ret = desc->fcn(&args);

	/* Cleanup */
	unset_args_ctl(args.ctl);
	conf_free(conf());
	log_close();

	return ret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE;
}
