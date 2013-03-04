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

#include "tests/libknot/sign_tests.h"
#include "libknot/sign/key.h"
#include "libknot/sign/key.c" // testing static functions

static int sign_tests_count(int argc, char *argv[]);
static int sign_tests_run(int argc, char *argv[]);

unit_api sign_tests_api = {
	"libknot/sign",
	&sign_tests_count,
	&sign_tests_run
};

static int sign_tests_count(int argc, char *argv[])
{
	return 31;
}

static int sign_tests_run(int argc, char *argv[])
{
	// 1-3. - strndup_with_suffix()
	{
		char *result;

		result = strndup_with_suffix("begin", 5, "end");
		ok(result && strcmp(result, "beginend") == 0,
		   "strndup_with_suffix(), matching length");
		free(result);

		result = strndup_with_suffix("begin", 3, "end");
		ok(result && strcmp(result, "begend") == 0,
		   "strndup_with_suffix(), shorter length");
		free(result);

		result = strndup_with_suffix("", 0, "end");
		ok(result && strcmp(result, "end") == 0,
		   "strndup_with_suffix(), empty base string");
		free(result);
	}

	// 4-8. - get_key_name_from_public_key()
	{
		char *result;

		result = get_key_name_from_public_key("Kexample.com.+0.+0.public");
		ok(result && strcmp(result, "example.com") == 0,
		   "get_key_name_from_public_key(), name with K");
		free(result);

		result = get_key_name_from_public_key("example.cz.+0.+0.public");
		ok(result && strcmp(result, "example.cz") == 0,
		   "get_key_name_from_public_key(), name without K");
		free(result);

		result = get_key_name_from_public_key("../Knic.cz.+0.+0.public");
		ok(result && strcmp(result, "nic.cz") == 0,
		   "get_key_name_from_public_key(), name with path and K");
		free(result);

		result = get_key_name_from_public_key("../foo.+0.+0.public");
		ok(result && strcmp(result, "foo") == 0,
		   "get_key_name_from_public_key(), name with path, without K");
		free(result);

		result = get_key_name_from_public_key("../invalid.public");
		ok(!result, "get_key_name_from_public_key(), invalid name");
	}

	// 9.-14. - get_key_filenames()
	{
		char *public, *private;
		int result;

		result = get_key_filenames("Kexample.com.+1.+2.private",
		                           &public, &private);
		ok(result == KNOT_EOK &&
		   strcmp(public, "Kexample.com.+1.+2.public") == 0 &&
		   strcmp(private, "Kexample.com.+1.+2.private") == 0,
		   "get_key_filenames(), from private key");
		free(public);
		free(private);

		result = get_key_filenames("Kexample.com.+4.+8.public",
		                           &public, &private);
		ok(result == KNOT_EOK &&
		   strcmp(public, "Kexample.com.+4.+8.public") == 0 &&
		   strcmp(private, "Kexample.com.+4.+8.private") == 0,
		   "get_key_filenames(), from public key");
		free(public);
		free(private);

		result = get_key_filenames("nic.cz.+4.+8",
		                           &public, &private);
		ok(result == KNOT_EOK &&
		   strcmp(public, "nic.cz.+4.+8.public") == 0 &&
		   strcmp(private, "nic.cz.+4.+8.private") == 0,
		   "get_key_filenames(), without extension");
		free(public);
		free(private);

		result = get_key_filenames("nic.cz.+0.+1.",
		                           &public, &private);
		ok(result == KNOT_EOK &&
		   strcmp(public, "nic.cz.+0.+1.public") == 0 &&
		   strcmp(private, "nic.cz.+0.+1.private") == 0,
		   "get_key_filenames(), empty extension");
		free(public);
		free(private);

		result = get_key_filenames("../keys/Kfoo.bar.+5.+10.private",
		                           &public, &private);
		ok(result == KNOT_EOK &&
		   strcmp(public, "../keys/Kfoo.bar.+5.+10.public") == 0 &&
		   strcmp(private, "../keys/Kfoo.bar.+5.+10.private") == 0,
		   "get_key_filenames(), with path");
		free(public);
		free(private);

		result = get_key_filenames("keys/something.txt",
		                           &public, &private);
		ok(result == KNOT_EOK &&
		   strcmp(public, "keys/something.txt.public") == 0 &&
		   strcmp(private, "keys/something.txt.private") == 0,
		   "get_key_filenames(), nonstandard name");
		free(public);
		free(private);
	}

	// 15. - key_param_string()
	{
		char *output = NULL;
		int result;

		result = key_param_string(&output, "ahoj DNS svete");
		ok(result == KNOT_EOK && strcmp(output, "ahoj DNS svete") == 0,
		   "key_param_string(), correct usage");
		free(output);
	}

	// 16-21. - key_param_int()
	{
		int output = 0;
		int result;

		result = key_param_int(&output, "12345");
		ok(result == KNOT_EOK && output == 12345,
		   "key_param_int(), correct number");

		result = key_param_int(&output, "6789 whatever");
		ok(result == KNOT_EOK && output == 6789,
		   "key_param_int(), number, space, and text");

		result = key_param_int(&output, "24680\n");
		ok(result == KNOT_EOK && output == 24680,
		   "key_param_int(), number and new line");

		result = key_param_int(&output, "0");
		ok(result == KNOT_EOK && output == 0,
		   "key_param_int(), zero");

		result = key_param_int(&output, "");
		ok(result == KNOT_EINVAL,
		   "key_param_int(), empty string");

		result = key_param_int(&output, "\t \n");
		ok(result == KNOT_EINVAL,
		   "key_param_int(), only white spaces");

		result = key_param_int(&output, "4444abc");
		ok(result == KNOT_EINVAL,
		   "key_param_int(), number and text");
	}

	// 22-25. - parse_keyfile_line()
	{
		knot_key_params_t key = { 0 };
		int result;
		char *line;

		line = strdup("Algorithm: 123 ABC");
		result = parse_keyfile_line(&key, line, strlen(line));
		ok(result == KNOT_EOK && key.algorithm == 123,
		   "parse_keyfile_line(), simple line with algorithm");
		free(line);

		line = strdup("Key:   secret\n");
		result = parse_keyfile_line(&key, line, strlen(line));
		ok(result == KNOT_EOK && strcmp(key.secret, "secret") == 0,
		   "parse_keyfile_line(), new line terminated line with key");
		free(key.secret);
		free(line);

		line = strdup("Cool: Knot DNS");
		result = parse_keyfile_line(&key, line, strlen(line));
		ok(result == KNOT_EOK,
		   "parse_keyfile_line(), unknown parameter");
		free(line);
	}

	// 26. - knot_load_key_params()
	{
		//! \todo write unit tests for knot_load_key_params()
		ok(1, "knot_load_key_params(), TODO");
	}

	// 27. - knot_free_key_params()
	{
		int result;
		knot_key_params_t params = { 0 };
		knot_key_params_t empty_params = { 0 };

		params.algorithm = 42;
		params.public_exponent = strdup("AQAB");

		result = knot_free_key_params(&params);
		ok(result == KNOT_EOK
		   && memcmp(&params, &empty_params, sizeof(params)) == 0,
		   "knot_free_key_params(), regular free");
	}

	// 28-31. - knot_tsig_key_from_params()
	{
		int result;
		knot_key_params_t params = { 0 };
		knot_tsig_key_t tsig_key;

		result = knot_tsig_key_from_params(&params, &tsig_key);
		ok(result == KNOT_EINVAL,
		   "knot_tsig_key_from_params(), empty parameters");

		params.secret = "Ok6NmA==";
		result = knot_tsig_key_from_params(&params, &tsig_key);
		ok(result == KNOT_EINVAL,
		   "knot_tsig_key_from_params(), no key name");

		params.name = "shared.example.com";
		params.secret = NULL;
		result = knot_tsig_key_from_params(&params, &tsig_key);
		ok(result == KNOT_EINVAL,
		   "knot_tsig_key_from_params(), no shared secret");

		params.name = "shared.example.com";
		params.secret = "Ok6NmA==";
		uint8_t decoded_secret[] = { 0x3a, 0x4e, 0x8d, 0x98 };
		result = knot_tsig_key_from_params(&params, &tsig_key);
		ok(result == KNOT_EOK
		   && tsig_key.secret.size == sizeof(decoded_secret)
		   && memcmp(tsig_key.secret.data, decoded_secret,
		             sizeof(decoded_secret)) == 0,
		   "knot_tsig_key_from_params(), secret set properly");

		knot_tsig_key_free(&tsig_key);
	}

	return 0;
}
