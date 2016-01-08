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

#include "contrib/sockaddr.h"
#include "dnssec/crypto.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "libknot/libknot.h"
#include "utils/knotc/commands.h"

/*! \brief Print help. */
static void help(void)
{
	printf("Usage: knotc [parameters] <action> [action_args]\n"
	       "\n"
	       "Parameters:\n"
	       " -c, --config <file>                Select configuration file.\n"
	       "                                     (default %s)\n"
	       " -C, --confdb <dir>                 Select configuration database directory.\n"
	       " -s, --socket <path>                Remote control UNIX socket.\n"
	       "                                     (default %s)\n"
	       " -f, --force                        Force operation - override some checks.\n"
	       " -v, --verbose                      Verbose mode - additional runtime information.\n"
	       " -V, --version                      Print %s server version.\n"
	       " -h, --help                         Print help and usage.\n"
	       "\n"
	       "Actions:\n",
	       CONF_DEFAULT_FILE, RUN_DIR "/knot.sock", PACKAGE_NAME);
	cmd_help_t *c = cmd_help_table;
	while (c->name != NULL) {
		printf(" %-13s %-20s %s\n", c->name, c->params, c->desc);
		++c;
	}
	printf("\nThe item argument must be in the section[identifier].item format.\n");
	printf("\nIf optional <zone> parameter is not specified, command is applied to all zones.\n\n");
}

int main(int argc, char **argv)
{
	/* Parse command line arguments */
	int c = 0, li = 0, rc = 0;
	unsigned flags = CMD_NONE;
	const char *config_fn = CONF_DEFAULT_FILE;
	const char *config_db = NULL;
	char *socket = NULL;

	/* Initialize. */
	log_init();
	log_levels_set(LOG_SYSLOG, LOG_ANY, 0);

	/* Long options. */
	struct option opts[] = {
		{ "config",  required_argument, 0, 'c' },
		{ "confdb",  required_argument, 0, 'C' },
		{ "socket",  required_argument, 0, 's' },
		{ "force",   no_argument,       0, 'f' },
		{ "verbose", no_argument,       0, 'v' },
		{ "help",    no_argument,       0, 'h' },
		{ "version", no_argument,       0, 'V' },
		{ NULL }
	};

	while ((c = getopt_long(argc, argv, "s:fc:C:vVh", opts, &li)) != -1) {
		switch (c) {
		case 'c':
			config_fn = optarg;
			break;
		case 'C':
			config_db = optarg;
			break;
		case 's':
			socket = strdup(optarg);
			break;
		case 'f':
			flags |= CMD_FORCE;
			break;
		case 'v':
			log_levels_add(LOGT_STDOUT, LOG_ANY,
			               LOG_MASK(LOG_INFO) | LOG_MASK(LOG_DEBUG));
			break;
		case 'V':
			rc = 0;
			printf("%s, version %s\n", "Knot DNS", PACKAGE_VERSION);
			goto exit;
		case 'h':
		case '?':
			rc = 0;
			help();
			goto exit;
		default:
			rc = 1;
			help();
			goto exit;
		}
	}

	/* Check if there's at least one remaining non-option. */
	if (argc - optind < 1) {
		rc = 1;
		help();
		goto exit;
	}

	/* Check for existing config DB destination. */
	struct stat st;
	if (config_db != NULL && stat(config_db, &st) != 0) {
		flags |= CMD_NOCONFDB;
	}

	const char *command = argv[optind];
	for (cmd_desc_old_t *desc = cmd_table_old; desc->old_name != NULL; desc++) {
		if (strcmp(desc->old_name, command) == 0) {
			log_notice("obsolete command '%s', using '%s' instead",
			           desc->old_name, desc->new_name);
			command = desc->new_name;
			break;
		}
	}

	/* Find requested command. */
	cmd_desc_t *desc = cmd_table;
	while (desc->name != NULL) {
		if (strcmp(desc->name, command) == 0) {
			break;
		}
		++desc;
	}

	/* Command not found. */
	if (desc->name == NULL) {
		log_fatal("invalid command: '%s'", argv[optind]);
		rc = 1;
		goto exit;
	}

	/* Open configuration. */
	conf_t *new_conf = NULL;
	if (config_db == NULL) {
		int ret = conf_new(&new_conf, conf_scheme, NULL, false);
		if (ret != KNOT_EOK) {
			log_fatal("failed to initialize configuration database "
			          "(%s)", knot_strerror(ret));
			rc = 1;
			goto exit;
		}

		/* Import the configuration file. */
		ret = conf_import(new_conf, config_fn, true);
		if (ret != KNOT_EOK) {
			log_fatal("failed to load configuration file (%s)",
			          knot_strerror(ret));
			conf_free(new_conf, false);
			rc = 1;
			goto exit;
		}

		new_conf->filename = strdup(config_fn);
	} else {
		/* Open configuration database. */
		bool ronly = !(desc->flags & CMD_CONF_WRITE);
		int ret = conf_new(&new_conf, conf_scheme, config_db, ronly);
		if (ret != KNOT_EOK) {
			log_fatal("failed to open configuration database '%s' "
			          "(%s)", config_db, knot_strerror(ret));
			rc = 1;
			goto exit;
		}
	}

	/* Run post-open config operations. */
	int ret = conf_post_open(new_conf);
	if (ret != KNOT_EOK) {
		log_fatal("failed to use configuration (%s)", knot_strerror(ret));
		conf_free(new_conf, false);
		rc = 1;
		goto exit;
	}

	/* Update to the new config. */
	conf_update(new_conf);

	/* Get control socket path. */
	if (socket == NULL) {
		conf_val_t listen_val = conf_get(conf(), C_CTL, C_LISTEN);
		conf_val_t rundir_val = conf_get(conf(), C_SRV, C_RUNDIR);
		char *rundir = conf_abs_path(&rundir_val, NULL);
		socket = conf_abs_path(&listen_val, rundir);
		free(rundir);
	}

	cmd_args_t args = {
		socket,
		argc - optind - 1,
		argv + optind + 1,
		flags,
		config_db
	};

	/* Execute command. */
	dnssec_crypto_init();
	rc = desc->cmd(&args);
	dnssec_crypto_cleanup();

exit:
	/* Finish */
	conf_free(conf(), false);
	log_close();
	free(socket);

	return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
