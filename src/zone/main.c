#include <unistd.h>
#include <stdlib.h>
#include "zonec.h"

#include "dnslib/dnslib.h"

/* Total errors counter */
long int totalerrors = 0;

int
main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "zonec: 3 parameters requiered\n");
		return -1;
	}
	char *origin = NULL;
	const char *singlefile = NULL;
	parser = zparser_create();
	if (!parser) {
		fprintf(stderr, "zonec: error creating the parser\n");
		exit(1);
	}
	origin = argv[1];
	singlefile = argv[2];

	zone_read(origin, singlefile);

	return totalerrors ? 1 : 0;
}
