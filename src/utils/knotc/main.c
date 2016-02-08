/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/crypto.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "libknot/libknot.h"
#include "utils/knotc/commands.h"
#include "utils/common/params.h"

#define PROGRAM_NAME "knotc"

static void print_help(void)
{
	printf("Usage: %s [parameters] <action> [action_args]\n"
	       "\n"
	       "Parameters:\n"
	       " -c, --config <file>                  Use a textual configuration file.\n"
	       "                                       (default %s)\n"
	       " -C, --confdb <dir>                   Use a binary configuration database directory.\n"
	       "                                       (default %s)\n"
	       " -s, --socket <path>                  Use a remote control UNIX socket path.\n"
	       "                                       (default %s)\n"
	       " -f, --force                          Forced operation. Overrides some checks.\n"
	       " -v, --verbose                        Enable debug output.\n"
	       " -h, --help                           Print the program help.\n"
	       " -V, --version                        Print the program version.\n"
	       "\n"
	       "Actions:\n",
	       PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR, RUN_DIR "/knot.sock");

	for (const cmd_help_t *cmd = cmd_help_table; cmd->name != NULL; cmd++) {
		printf(" %-15s %-20s %s\n", cmd->name, cmd->params, cmd->desc);
	}

	printf("\n"
	       "Note:\n"
	       " Empty <zone> parameter means all zones.\n"
	       " Type <item> parameter in the form of <section>[<identifier>].<name>.\n"
	       " (*) indicates a local operation which requires a configuration.\n");
}

static int set_config(const cmd_desc_t *desc, const char *confdb,
                      const char *config, char *socket)
{
	if (config != NULL && confdb != NULL) {
		log_error("ambiguous configuration source");
		return KNOT_EINVAL;
	}

	/* Choose the optimal config source. */
	struct stat st;
	bool import = false;
	if (desc->flags == CMD_CONF_FNONE && socket != NULL) {
		import = false;
		confdb = NULL;
	} else if (confdb != NULL) {
		import = false;
	} else if (desc->flags == CMD_CONF_FWRITE) {
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
	} else if (desc->flags != CMD_CONF_FNONE) {
		log_error("no configuration source available");
		return KNOT_EINVAL;
	}

	const char *src = import ? config : confdb;
	log_debug("%s '%s'", import ? "config" : "confdb",
	          (src != NULL) ? src : "empty");

	/* Prepare config flags. */
	conf_flag_t conf_flags = CONF_FNONE;
	if (confdb != NULL && !(desc->flags & CMD_CONF_FWRITE)) {
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

int main(int argc, char **argv)
{
	cmd_flag_t flags = CMD_FNONE;
	const char *config = NULL;
	const char *confdb = NULL;
	char *socket = NULL;
	bool verbose = false;

	/* Long options. */
	struct option opts[] = {
		{ "config",  required_argument, NULL, 'c' },
		{ "confdb",  required_argument, NULL, 'C' },
		{ "socket",  required_argument, NULL, 's' },
		{ "force",   no_argument,       NULL, 'f' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	/* Parse command line arguments */
	int opt = 0, li = 0;
	while ((opt = getopt_long(argc, argv, "c:C:s:fvhV", opts, &li)) != -1) {
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

	/* Translate old command name. */
	const char *command = argv[optind];
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
		log_close();
		return EXIT_FAILURE;
	}

	/* Set up the configuration */
	int ret = set_config(desc, confdb, config, socket);
	if (ret != KNOT_EOK) {
		log_close();
		return EXIT_FAILURE;
	}

	/* Prepare command parameters. */
	cmd_args_t args = {
		socket,
		argc - optind - 1,
		argv + optind + 1,
		flags
	};

	/* Get the control socket from confdb if not specified. */
	if (socket == NULL) {
		conf_val_t listen_val = conf_get(conf(), C_CTL, C_LISTEN);
		conf_val_t rundir_val = conf_get(conf(), C_SRV, C_RUNDIR);
		char *rundir = conf_abs_path(&rundir_val, NULL);
		args.socket = conf_abs_path(&listen_val, rundir);
		free(rundir);
	}

	log_debug("socket '%s'", (args.socket != NULL) ? args.socket : "");

	/* Execute the command. */
	dnssec_crypto_init();
	ret = desc->cmd(&args);
	dnssec_crypto_cleanup();

	/* Cleanup */
	if (socket == NULL) {
		free(args.socket);
	}
	conf_free(conf());
	log_close();

	return ret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE;
}
