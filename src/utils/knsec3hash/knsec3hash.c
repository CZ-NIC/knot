/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "contrib/base32hex.h"
#include "contrib/string.h"
#include "contrib/strtonum.h"
#include "libdnssec/error.h"
#include "libdnssec/nsec.h"
#include "libknot/libknot.h"
#include "utils/common/msg.h"
#include "utils/common/params.h"

#define PROGRAM_NAME	"knsec3hash"

/*!
 * \brief Print program help (and example).
 */
static void print_help(void)
{
	printf("Usage:   " PROGRAM_NAME " <salt> <algorithm> <iterations> <domain-name>\n");
	printf("Example: " PROGRAM_NAME " c01dcafe 1 10 knot-dns.cz\n");
	printf("Alternative usage: "PROGRAM_NAME " <algorithm> <flags> <iterations> <salt> <domain-name>\n");
	printf("Example: " PROGRAM_NAME " 1 0 10 c01dcafe knot-dns.cz\n");
}

/*!
 * \brief Parse NSEC3 salt.
 */
static int str_to_salt(const char *str, dnssec_binary_t *salt)
{
	if (strcmp(str, "-") == 0) {
		salt->size = 0;
		return DNSSEC_EOK;
	} else {
		salt->data = hex_to_bin(str, &salt->size);
		return (salt->data != NULL ? DNSSEC_EOK : DNSSEC_EINVAL);
	}
}

/*!
 * \brief Parse NSEC3 parameters and fill structure with NSEC3 parameters.
 */
static bool parse_nsec3_params(dnssec_nsec3_params_t *params, const char *salt_str,
			       const char *algorithm_str, const char *iterations_str)
{
	uint8_t algorithm = 0;
	int r = str_to_u8(algorithm_str, &algorithm);
	if (r != KNOT_EOK) {
		ERR2("invalid algorithm number");
		return false;
	}

	uint16_t iterations = 0;
	r = str_to_u16(iterations_str, &iterations);
	if (r != KNOT_EOK) {
		ERR2("invalid iteration count");
		return false;
	}

	dnssec_binary_t salt = { 0 };
	r = str_to_salt(salt_str, &salt);
	if (r != DNSSEC_EOK) {
		ERR2("invalid salt (%s)", knot_strerror(r));
		return false;
	}

	if (salt.size > UINT8_MAX) {
		ERR2("invalid salt, maximum length is %d bytes", UINT8_MAX);
		dnssec_binary_free(&salt);
		return false;
	}

	params->algorithm = algorithm;
	params->iterations = iterations;
	params->salt = salt;
	params->flags = 0;

	return true;
}

/*!
 * \brief Entry point of 'knsec3hash'.
 */
int main(int argc, char *argv[])
{
	struct option options[] = {
		{ "help",    no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL }
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "hV", options, NULL)) != -1) {
		switch(opt) {
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

	bool new_params = false;
	if (argc == 6) {
		// knsec3hash <algorithm> <flags> <iterations> <salt> <domain>
		new_params = true;
	} else if (argc != 5) {
		// knsec3hash <salt> <algorithm> <iterations> <domain>
		print_help();
		return EXIT_FAILURE;
	}

	int exit_code = EXIT_FAILURE;
	dnssec_nsec3_params_t nsec3_params = { 0 };

	dnssec_binary_t dname = { 0 };
	dnssec_binary_t digest = { 0 };
	dnssec_binary_t digest_print = { 0 };

	if (new_params) {
		if (!parse_nsec3_params(&nsec3_params, argv[4], argv[1], argv[3])) {
			goto fail;
		}
	} else {
		if (!parse_nsec3_params(&nsec3_params, argv[1], argv[2], argv[3])) {
			goto fail;
		}
	}

	dname.data = knot_dname_from_str_alloc(argv[new_params ? 5 : 4]);
	if (dname.data == NULL) {
		ERR2("cannot parse domain name");
		goto fail;
	}
	knot_dname_to_lower(dname.data);
	dname.size = knot_dname_size(dname.data);

	int r = dnssec_nsec3_hash(&dname, &nsec3_params, &digest);
	if (r != DNSSEC_EOK) {
		ERR2("cannot compute NSEC3 hash (%s)", knot_strerror(r));
		goto fail;
	}

	r = knot_base32hex_encode_alloc(digest.data, digest.size, &digest_print.data);
	if (r < 0) {
		ERR2("cannot encode computed hash (%s)", knot_strerror(r));
		goto fail;
	}
	digest_print.size = r;

	exit_code = EXIT_SUCCESS;

	printf("%.*s (salt=%s, hash=%d, iterations=%d)\n", (int)digest_print.size,
	       digest_print.data, argv[1], nsec3_params.algorithm,
	       nsec3_params.iterations);

fail:
	dnssec_nsec3_params_free(&nsec3_params);
	dnssec_binary_free(&dname);
	dnssec_binary_free(&digest);
	dnssec_binary_free(&digest_print);

	return exit_code;
}
