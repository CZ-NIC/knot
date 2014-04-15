#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <error_code>\n", argv[0]);
		return 1;
	}

	char *end = NULL;
	long error = strtol(argv[1], &end, 10);
	if (*end != '\0' || error < INT_MIN || error > INT_MAX) {
		fprintf(stderr, "Invalid error code.\n");
		return 1;
	}

	printf("%s (%ld): %s\n", gnutls_strerror_name(error), error, gnutls_strerror(error));

	return 0;
}
