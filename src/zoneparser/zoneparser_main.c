#include <config.h>
#include <unistd.h>
#include <stdlib.h>

#include "zoneparser/zoneparser.h"
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
	       " -V           Print version of the server.\n"
	       " -h           Print help and usage.\n");
}

int main(int argc, char **argv)
{
	// Parse command line arguments
	int c = 0;
	int verbose = 0;
	const char* origin = 0;
	const char* zonefile = 0;
	const char* outfile = 0;
	while ((c = getopt (argc, argv, "o:vVh")) != -1) {
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

	int errors = zone_read(origin, zonefile, outfile);

	printf("Finished.\n");
	//log_close();

	return errors ? 1 : 0;
}
