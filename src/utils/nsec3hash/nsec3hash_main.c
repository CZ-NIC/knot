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

#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <locale.h>

#include "utils/common/params.h"
#include "common/base32hex.h"
#include "libknot/errcode.h"
#include "common-knot/hex.h"
#include "common-knot/strtonum.h"
#include "libknot/dnssec/crypto.h"

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
		fprintf(stderr, "Invalid algorithm number.\n");
		return false;
	}

	result = knot_str2uint16t(iterations, &params->iterations);
	if (result != KNOT_EOK) {
		fprintf(stderr, "Invalid iteration count: %s\n",
		        knot_strerror(result));
		return false;
	}

	size_t salt_length = 0;
	uint8_t *salt_data = NULL;

	if (salt[0] != '\0') {
		result = hex_decode(salt, &salt_data, &salt_length);
		if (result != KNOT_EOK) {
			fprintf(stderr, "Invalid salt: %s\n",
				knot_strerror(result));
			return false;
		}
	}

	if (salt_length > UINT8_MAX) {
		fprintf(stderr, "Invalid salt: Maximal length is %d bytes.\n",
		        UINT8_MAX);
		free(salt_data);
		return false;
	}

	params->salt = salt_data;
	params->salt_length = (uint8_t)salt_length;

	return true;
}

/*!
 * \brief Entry point of 'knsec3hash'.
 */
int main(int argc, char *argv[])
{
	bool enable_idn = true;

	struct option options[] = {
		{ "version", no_argument, 0, 'V' },
		{ "help",    no_argument, 0, 'h' },
		{ NULL }
	};

#ifdef LIBIDN
	// Set up localization.
	if (setlocale(LC_CTYPE, "") == NULL) {
		enable_idn = false;
	}
#endif

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

	atexit(knot_crypto_cleanup);

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

	if (enable_idn) {
		char *ascii_name = name_from_idn(argv[4]);
		if (ascii_name == NULL) {
			fprintf(stderr, "Cannot transform IDN domain name.\n");
			goto fail;
		}
		dname = knot_dname_from_str_alloc(ascii_name);
		free(ascii_name);
	} else {
		dname = knot_dname_from_str_alloc(argv[4]);
	}
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
    printf("Digest size: %zu,  Base32 size: %d\n\n", digest_size,b32_length);
	exit_code = 0;

	printf("%.*s (salt=%s, hash=%d, iterations=%d)\n", b32_length,
	       b32_digest, argv[1], nsec3_params.algorithm,
	       nsec3_params.iterations);

fail:
	knot_nsec3param_free(&nsec3_params);
	knot_dname_free(&dname, NULL);
	free(digest);
	free(b32_digest);

	return exit_code;
}
