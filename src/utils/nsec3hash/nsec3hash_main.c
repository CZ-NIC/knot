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
#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "common/base32hex.h"
#include "common/errcode.h"
#include "common/hex.h"
#include "common/strtonum.h"
#include "libknot/dnssec/cleanup.h"
#include "libknot/dnssec/nsec3.h"

#define PROGRAM_NAME "knsec3hash"

/*!
 * \brief Print program usage (and example).
 */
static void usage(FILE *stream)
{
	fprintf(stream, "usage:   " PROGRAM_NAME " "
	                "<salt> <algorithm> <iterations> <domain-name>\n");
	fprintf(stream, "example: " PROGRAM_NAME " "
	                "c01dcafe 1 10 knot-dns.cz\n");
}

/*!
 * \brief Parse NSEC3 parameters and fill structure with NSEC3 parameters.
 */
static bool parse_nsec3_params(knot_nsec3_params_t *params, const char *salt,
			       const char *algorithm, const char *iterations)
{
	int result;

	result = knot_str2uint8t(algorithm, &params->algorithm);
	if (result != KNOT_EOK) {
		fprintf(stderr, "Could not parse algorithm number.\n");
		return false;
	}

	result = knot_str2uint16t(iterations, &params->iterations);
	if (result != KNOT_EOK) {
		fprintf(stderr, "Could not parse iteration count.\n");
		return false;
	}

	size_t salt_length;
	result = hex_decode(salt, &params->salt, &salt_length);
	if (result != KNOT_EOK) {
		fprintf(stderr, "Could not parse hex encoded salt.\n");
		return false;
	}

	if (salt_length > UINT8_MAX) {
		fprintf(stderr, "Decoded salt is longer than %d bytes.\n",
		        UINT8_MAX);
		free(params->salt);
		memset(params, '\0', sizeof(*params));
		return false;
	}

	params->salt_length = (uint8_t)salt_length;

	return true;
}

/*!
 * \brief Entry point of 'knsec3hash'.
 */
int main(int argc, char *argv[])
{
	struct option options[] = {
		{ "version", no_argument, 0, 'V' },
		{ "help",    no_argument, 0, 'h' },
		{ NULL }
	};

	int opt = 0;
	int li = 0;
	while ((opt = getopt_long(argc, argv, "hV", options, &li)) != -1) {
		switch(opt) {
		case 'V':
			printf("%s, version %s\n", PROGRAM_NAME, PACKAGE_VERSION);
			return 0;
		case 'h':
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return 1;
		}
	}

	// knsec3hash <salt> <algorithm> <iterations> <domain>
	if (argc != 5) {
		usage(stderr);
		return 1;
	}

	atexit(knot_dnssec_cleanup);

	int exit_code = 1;
	knot_nsec3_params_t nsec3_params = { 0 };
	knot_dname_t *dname = NULL;
	uint8_t *digest = NULL;
	size_t digest_size = 0;
	uint8_t *b32_digest = NULL;
	int32_t b32_length = 0;
	int result = 0;

	if (!parse_nsec3_params(&nsec3_params, argv[1], argv[2], argv[3])) {
		goto fail;
	}

	dname = knot_dname_from_str(argv[4], strlen(argv[4]));
	if (dname == NULL) {
		fprintf(stderr, "Cannot parse domain name.\n");
		goto fail;
	}

	result = knot_nsec3_hash(&nsec3_params, dname, knot_dname_size(dname),
	                         &digest, &digest_size);
	if (result != KNOT_EOK) {
		fprintf(stderr, "Cannot compute hash: %s\n",
		        knot_strerror(result));
		goto fail;
	}

	b32_length = base32hex_encode_alloc(digest, digest_size, &b32_digest);
	if (b32_length < 0) {
		fprintf(stderr, "Cannot encode computed hash: %s\n",
		        knot_strerror(b32_length));
		goto fail;
	}

	exit_code = 0;

	printf("%.*s (salt=%s, hash=%d, iterations=%d)\n", b32_length,
	       b32_digest, argv[1], nsec3_params.algorithm,
	       nsec3_params.iterations);

fail:

	knot_nsec3_params_free(&nsec3_params);
	knot_dname_free(&dname);
	free(digest);
	free(b32_digest);

	return exit_code;
}
