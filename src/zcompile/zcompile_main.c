/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <unistd.h>
#include <stdlib.h>

#include "zcompile/zcompile.h"
#include "common/log.h"
#include <config.h>

static void help(int argc, char **argv)
{
	printf("Usage: %s [parameters] origin zonefile\n",
	       argv[0]);
	printf("Parameters:\n"
	       " -o <outfile> Override output file.\n"
	       " -v           Verbose mode - additional runtime information.\n"
	       " -s           Enable semantic checks.\n"
	       " -V           Print version of the server.\n"
	       " -h           Print help and usage.\n");
}

int main(int argc, char **argv)
{
	// Parse command line arguments
	int c = 0;
	int verbose = 0;
	int semantic_checks = 0;
	const char* origin = 0;
	const char* zonefile = 0;
	const char* outfile = 0;
	while ((c = getopt (argc, argv, "o:vVsh")) != -1) {
		switch (c)
		{
		case 'o':
			outfile = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'V':
			printf("%s, version %s\n", "Knot DNS", PACKAGE_VERSION);
			return 0;
		case 's':
			semantic_checks = 1;
			break;
		case 'h':
		case '?':
		default:
			if (optopt == 'o') {
				fprintf (stderr,
					 "Option -%c requires an argument.\n",
					 optopt);
			}
			help(argc, argv);
			return 1;
		}
	}

	UNUSED(verbose);

	// Check if there's at least two remaining non-option
	if (argc - optind < 2) {
		help(argc, argv);
		return 1;
	}

	origin = argv[optind];
	zonefile = argv[optind + 1];

	// Initialize log (no syslog)
	log_init();
	log_levels_set(LOGT_SYSLOG, LOG_ANY, 0);
	log_zone_info("Parsing file '%s', origin '%s' ...\n",
	              zonefile, origin);

	parser = zparser_create();
	if (!parser) {
		log_server_error("Failed to create parser.\n");
		//log_close();
		return 1;
	}

	int error = zone_read(origin, zonefile, outfile, semantic_checks);
	zparser_free();

	if (error != 0) {
	  /* FIXME! */
//		if (error < 0) {
//			fprintf(stderr, "Finished with error: %s.\n",
//			       error_to_str(knot_zcompile_error_msgs, error));
//		} else {
//			fprintf(stderr, "Finished with %u errors.\n");
//		}
		return 1;
	} else {
		log_zone_info("Compilation of '%s' successful.\n", origin);
	}
	//log_close();
	
	return 0;
}
