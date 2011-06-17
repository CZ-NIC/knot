#include <config.h>
#include <unistd.h>
#include <stdlib.h>

#include "zcompile/zcompile.h"
#include "zcompile/zcompile-error.h"
#include "common/errors.h"
#include "config.h"

#define PROJECT_NAME PACKAGE // Project name
#define PROJECT_VER  0x000100  // 0xMMIIRR (MAJOR,MINOR,REVISION)

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
			printf("%s, version %d.%d.%d\n", PROJECT_NAME,
			       PROJECT_VER >> 16 & 0x000000ff,
			       PROJECT_VER >> 8 & 0x000000ff,
			       PROJECT_VER >> 0 & 0x000000ff);
			return 1;
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

	// Check if there's at least two remaining non-option
	if (argc - optind < 2) {
		help(argc, argv);
		return 1;
	}

	origin = argv[optind];
	zonefile = argv[optind + 1];

	// Initialize log (no output)
	//log_init(0);
	//log_levels_set(LOGT_STDOUT, LOG_ANY, LOG_MASK(LOG_DEBUG));

	printf("Parsing file '%s', origin '%s' ...\n",
	       zonefile, origin);

	parser = zparser_create();
	if (!parser) {
		fprintf(stderr, "Failed to create parser.\n");
		//log_close();
		return 1;
	}

	int error = zone_read(origin, zonefile, outfile, semantic_checks);

	printf("Finished with error: %s.\n",
	       error_to_str(knot_zcompile_error_msgs, error));
	//log_close();

	return error ? 1 : 0;
}
