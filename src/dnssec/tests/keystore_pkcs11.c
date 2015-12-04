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

#include <tap/basic.h>
#include <tap/files.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dnssec/crypto.h"
#include "dnssec/error.h"
#include "dnssec/keystore.h"
#include "dnssec/sign.h"

#include "sample_keys.h"

#define ENV_SOFTHSM_DSO  "KNOT_SOFTHSM2_DSO"
#define ENV_SOFTHSM_UTIL "KNOT_SOFTHSM2_UTIL"

#define SOFTHSM_DSO      "libsofthsm2.so"
#define SOFTHSM_CONF     "softhsm2.conf"
#define SOFTHSM_CONF_ENV "SOFTHSM2_CONF"
#define SOFTHSM_UTIL     "softhsm2-util"

#define TOKEN_LABEL "libdnssec-test"
#define TOKEN_PIN   "1234"
#define TOKEN_SOPIN "123456"

#define EXIT_EXEC_FAILED 127

#ifndef LIBDIR
#  include <bits/wordsize.h>
#  if __WORDSIZE == 32
#    define LIBDIR "/usr/lib32"
#  elif __WORDSIZE == 64
#    define LIBDIR "/usr/lib64"
#  endif
#endif

/*!
 * Get SoftHSM DSO path.
 */
static char *libsofthsm_dso(void)
{
	// prefer environment variable

	const char *env = getenv(ENV_SOFTHSM_DSO);
	if (env) {
		return (env[0] != '\0' ? strdup(env) : NULL);
	}

	// autodetection

	static const char *paths[] = {
		LIBDIR "/pkcs11/" SOFTHSM_DSO,
		LIBDIR "/softhsm/" SOFTHSM_DSO,
		LIBDIR "/" SOFTHSM_DSO,
		NULL
	};

	for (const char **path_ptr = paths; *path_ptr; path_ptr += 1) {
		const char *path = *path_ptr;
		if (access(path, R_OK|X_OK) == 0) {
			return strdup(path);
		}
	}

	return NULL;
}

/*!
 * Get SoftHSM utility path.
 */
static char *libsofthsm_util(void)
{
	// prefer environment variable

	const char *env = getenv(ENV_SOFTHSM_UTIL);
	if (env && env[0] != '\0') {
		return strdup(env);
	}

	// fallback, will relay on PATH

	return strdup(SOFTHSM_UTIL);
}

/*!
 * Path to temporary token data.
 */
static char *token_path = NULL;

/*!
 * Cleanup token test data.
 */
static void token_cleanup(void)
{
	if (token_path) {
		test_rm_rf(token_path);
		free(token_path);
	}
}

/*!
 * Initialize token using the support tool.
 */
static bool init_exec(const char *util)
{
	pid_t child = fork();
	if (child == -1) {
		return false;
	}

	// child

	if (child == 0) {
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);

		const char *basename = strrchr(util, '/');
		if (basename) {
			basename += 1;
		} else {
			basename = util;
		}

		execlp(util, basename,
		       "--init-token", "--slot=0", "--label=" TOKEN_LABEL,
		       "--pin=" TOKEN_PIN, "--so-pin=" TOKEN_SOPIN,
		       NULL);

		exit(EXIT_EXEC_FAILED);
	}

	// parent

	int status = 0;
	if (waitpid(child, &status, 0) == -1) {
		return false;
	}

	int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	if (exit_code != 0) {
		diag("%s exit status %d", util, exit_code);
		if (exit_code == EXIT_EXEC_FAILED) {
			diag("set %s environment variable to adjust the path",
			     ENV_SOFTHSM_UTIL);
		}
	}

	return exit_code == 0;
}

/*!
 * Initialize environment and token for testing.
 */
static bool token_init(void)
{
	token_path = test_mkdtemp();
	if (!token_path) {
		return false;
	}

	// generate configuration file for unit test

	char config[4096] = { 0 };
	int r = snprintf(config, sizeof(config), "%s/%s", token_path, SOFTHSM_CONF);
	if (r <= 0 || r >= sizeof(config)) {
		return false;
	}

	FILE *file = fopen(config, "w");
	if (!file) {
		return false;
	}

	fprintf(file, "directories.tokendir = %s\n", token_path);
	fprintf(file, "objectstore.backend = file\n");
	fprintf(file, "log.debug = INFO\n");

	fclose(file);

	// update environment to use the config

	if (setenv(SOFTHSM_CONF_ENV, config, 1) != 0) {
		return false;
	}

	// initialize token

	char *util = libsofthsm_util();
	if (!util) {
		return false;
	}

	bool inited = init_exec(util);
	free(util);

	return inited;
}

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_crypto_init();

	// PKCS #11 initialization

	dnssec_keystore_t *store = NULL;
	int r = dnssec_keystore_init_pkcs11(&store);
	if (r == DNSSEC_NOT_IMPLEMENTED_ERROR) {
		skip_all("not supported");
		goto done;
	}
	ok(r == DNSSEC_EOK && store, "dnssec_keystore_init_pkcs11()");

	char *dso_name = libsofthsm_dso();
	if (!dso_name) {
		skip_all("%s not found, set %s environment variable",
			 SOFTHSM_DSO, ENV_SOFTHSM_DSO);
		goto done;
	}
	ok(dso_name != NULL, "find token DSO");

	bool success = token_init();
	if (!success) {
		skip_all("failed to configure and initialize the token");
		goto done;
	}
	ok(success, "initialize the token");

	char config[4096] = { 0 };
	r = snprintf(config, sizeof(config), "pkcs11:token=%s;pin-value=%s %s",
	                                     TOKEN_LABEL, TOKEN_PIN, dso_name);
	free(dso_name);
	ok(r > 0 && r < sizeof(config), "build configuration");

	// key manipulation

	r = dnssec_keystore_init(store, config);
	ok(r == DNSSEC_NOT_IMPLEMENTED_ERROR, "dnssec_keystore_init(), not implmeneted");

	r = dnssec_keystore_open(store, config);
	ok(r == DNSSEC_EOK, "dnssec_keystore_open()");

	dnssec_list_t *keys = NULL;
	r = dnssec_keystore_list_keys(store, &keys);
	ok(r == DNSSEC_EOK && dnssec_list_size(keys) == 0, "dnssec_keystore_list_keys(), empty");
	dnssec_list_free_full(keys, NULL, NULL);

	char *id_ecc = NULL;
	r = dnssec_keystore_generate_key(store, DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256, 256, &id_ecc);
	ok(r == DNSSEC_EOK && id_ecc, "dnssec_keystore_generate_key(ECDSA)");

	char *id_rsa = NULL;
	r = dnssec_keystore_import(store, &SAMPLE_RSA_KEY.pem, &id_rsa);
	ok(r == DNSSEC_EOK && id_rsa, "dnssec_keystore_import(RSA)");
	ok(id_rsa && strcmp(id_rsa, SAMPLE_RSA_KEY.key_id) == 0, "predictable key ID after import");

	keys = NULL;
	r = dnssec_keystore_list_keys(store, &keys);
	ok(r == DNSSEC_EOK && dnssec_list_size(keys), "dnssec_keystore_list_keys(), two keys");
	bool found_ecc = false, found_rsa = false;
	dnssec_list_foreach(item, keys) {
		char *id = dnssec_item_get(item);
		if (id) {
			if (id_ecc && strcmp(id, id_ecc) == 0) { found_ecc = true; }
			if (id_rsa && strcmp(id, id_rsa) == 0) { found_rsa = true; }
		}
	}
	ok(found_ecc, "list contains ECC key");
	ok(found_rsa, "list contains RSA key");
	dnssec_list_free_full(keys, NULL, NULL);

	r = dnssec_keystore_remove_key(store, id_ecc);
	ok(r == DNSSEC_EOK, "dnssec_keystore_remove_key(ECC)");

	keys = NULL;
	r = dnssec_keystore_list_keys(store, &keys);
	ok(r == DNSSEC_EOK && dnssec_list_size(keys) == 1, "dnssec_keystore_list_keys(), one key");
	dnssec_list_free_full(keys, NULL, NULL);

	// key usage

	dnssec_key_t *key = NULL;
	r = dnssec_key_new(&key);
	ok(r == DNSSEC_EOK && key, "dnssec_key_new()");
	dnssec_key_set_algorithm(key, DNSSEC_KEY_ALGORITHM_RSA_SHA256);

	r = dnssec_key_import_keystore(key, store, "0000000000000000000000000000000000000000");
	ok(r == DNSSEC_NOT_FOUND, "dnssec_key_import_keystore(invalid), not found");

	r = dnssec_key_import_keystore(key, store, id_rsa);
	ok(r == DNSSEC_EOK, "dnssec_key_import_keystore(RSA)");

	ok(dnssec_key_can_sign(key) == true, "dnssec_key_can_sign()");

	const dnssec_binary_t data = {
		.size = 36,
		.data = (uint8_t *)"So Long, and Thanks for All the Fish"
	};

	const dnssec_binary_t expected = {
		.size = 1,
		.data = (uint8_t *){ 0x00 }
	};

	dnssec_sign_ctx_t *sign_ctx = NULL;
	r = dnssec_sign_new(&sign_ctx, key);
	ok(r == DNSSEC_EOK, "dnssec_sign_new()");

	r = dnssec_sign_add(sign_ctx, &data);
	ok(r == DNSSEC_EOK, "dnssec_sign_add()");

	dnssec_binary_t signature = { 0 };
	r = dnssec_sign_write(sign_ctx, &signature);
	ok(r == DNSSEC_EOK, "dnssec_sign_write()");

	ok(dnssec_binary_cmp(&data, &expected) == 0, "expected signature");

	dnssec_binary_free(&signature);
	dnssec_sign_free(sign_ctx);
	dnssec_key_free(key);

	free(id_rsa);
	free(id_ecc);

	r = dnssec_keystore_close(store);
	ok(r == DNSSEC_EOK, "dnssec_keystore_close()");
done:
	dnssec_keystore_deinit(store);
	dnssec_crypto_cleanup();
	token_cleanup();

	return 0;
}
