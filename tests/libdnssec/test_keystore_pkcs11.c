/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>
#include <tap/files.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "libdnssec/crypto.h"
#include "libdnssec/error.h"
#include "libdnssec/keystore.h"
#include "libdnssec/sign.h"

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

#define MSG_SOFTWARE "soft -"
#define MSG_PKCS11   "p11  -"

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

	// fallback, will rely on PATH

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
	test_rm_rf(token_path);
	free(token_path);
}

/*!
 * Initialize token using the support tool.
 */
static bool token_init_exec(const char *util)
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

	bool inited = token_init_exec(util);
	free(util);

	return inited;
}

static void create_dnskeys(dnssec_keystore_t *keystore,
			   dnssec_key_algorithm_t algorithm, const char *id,
			   dnssec_key_t **p11_key_ptr, dnssec_key_t **soft_key_ptr)
{
	int r;

	// construct PKCS #11 privkey-pubkey key pair

	dnssec_key_t *p11_key = NULL;
	r = dnssec_key_new(&p11_key);
	ok(r == DNSSEC_EOK && p11_key != NULL, MSG_PKCS11 " dnssec_key_new()");

	r = dnssec_key_set_algorithm(p11_key, algorithm);
	ok(r == DNSSEC_EOK, MSG_PKCS11 " dnssec_set_key_algorithm()");

	r = dnssec_keystore_export(keystore, id, p11_key);
	ok(r == DNSSEC_EOK, MSG_PKCS11 " dnssec_key_import_keystore()");

	// construct software public key

	dnssec_key_t *soft_key = NULL;
	r = dnssec_key_new(&soft_key);
	ok(r == DNSSEC_EOK && soft_key != NULL, MSG_SOFTWARE " dnssec_key_new()");

	dnssec_binary_t rdata = { 0 };
	dnssec_key_get_rdata(p11_key, &rdata);
	r = dnssec_key_set_rdata(soft_key, &rdata);
	ok(r == DNSSEC_EOK, MSG_SOFTWARE " dnssec_key_set_rdata()");

	*p11_key_ptr = p11_key;
	*soft_key_ptr = soft_key;
}

static void test_sign(dnssec_key_t *p11_key, dnssec_key_t *soft_key)
{
	int r;

	static const dnssec_binary_t input = {
		.data = (uint8_t *)"So Long, and Thanks for All the Fish.",
		.size = 37
	};

	dnssec_binary_t sign = { 0 };

	// usage constraints

	ok(dnssec_key_can_sign(p11_key),   MSG_PKCS11 " dnssec_key_can_sign()");
	ok(dnssec_key_can_verify(p11_key), MSG_PKCS11 " dnssec_key_can_verify()");

	ok(!dnssec_key_can_sign(soft_key),  MSG_SOFTWARE " dnssec_key_can_sign()");
	ok(dnssec_key_can_verify(soft_key), MSG_SOFTWARE " dnssec_key_can_verify()");

	// PKCS #11 key signature

	dnssec_sign_ctx_t *ctx = NULL;
	r = dnssec_sign_new(&ctx, p11_key);
	ok(r == DNSSEC_EOK, MSG_PKCS11 " dnssec_sign_init() ");

	r = dnssec_sign_add(ctx, &input);
	ok(r == DNSSEC_EOK, MSG_PKCS11 " dnssec_sign_add()");

	r = dnssec_sign_write(ctx, &sign);
	ok(r == DNSSEC_EOK, MSG_PKCS11 " dnssec_sign_write()");

	// PKCS #11 key verification

	r = dnssec_sign_init(ctx);
	ok(r == DNSSEC_EOK, MSG_PKCS11 " dnssec_sign_init()");

	r = dnssec_sign_add(ctx, &input);
	ok(r == DNSSEC_EOK, MSG_PKCS11 " dnssec_sign_add()");

	r = dnssec_sign_verify(ctx, &sign);
	ok(r == DNSSEC_EOK, MSG_PKCS11 " dnssec_sign_verify()");

	// software verification

	dnssec_sign_free(ctx);
	ctx = NULL;

	r = dnssec_sign_new(&ctx, soft_key);
	ok(r == DNSSEC_EOK, MSG_SOFTWARE " dnssec_sign_init()");

	r = dnssec_sign_add(ctx, &input);
	ok(r == DNSSEC_EOK, MSG_SOFTWARE " dnssec_sign_add()");

	r = dnssec_sign_verify(ctx, &sign);
	ok(r == DNSSEC_EOK, MSG_SOFTWARE " dnssec_sign_verify()");

	dnssec_binary_free(&sign);
	dnssec_sign_free(ctx);
}

static void test_key_use(dnssec_keystore_t *store,
			 dnssec_key_algorithm_t algorithm,
			 const char *keyid)
{
	dnssec_key_t *p11_key = NULL;
	dnssec_key_t *soft_key = NULL;

	create_dnskeys(store, algorithm, keyid, &p11_key, &soft_key);
	test_sign(p11_key, soft_key);

	dnssec_key_free(p11_key);
	dnssec_key_free(soft_key);
}

static void test_algorithm(dnssec_keystore_t *store,
			   const key_parameters_t *params)
{
	char *id_generate = NULL;
	char *id_import = NULL;

	int r;

	diag("algorithm %d, generated key", params->algorithm);

	r = dnssec_keystore_generate(store, params->algorithm, params->bit_size, &id_generate);
	ok(r == DNSSEC_EOK && id_generate != NULL, "dnssec_keystore_generate()");
	test_key_use(store, params->algorithm, id_generate);

	diag("algorithm %d, imported key", params->algorithm);

	r = dnssec_keystore_import(store, &params->pem, &id_import);
	ok(r == DNSSEC_EOK && id_import != NULL, "dnssec_keystore_import()");
	test_key_use(store, params->algorithm, id_import);

	free(id_generate);
	free(id_import);
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

	// key store access

	r = dnssec_keystore_init(store, config);
	ok(r == DNSSEC_EOK, "dnssec_keystore_init()");

	r = dnssec_keystore_open(store, config);
	ok(r == DNSSEC_EOK, "dnssec_keystore_open()");

	// key manipulation

	static const int KEYS_COUNT = 2;
	static const key_parameters_t *KEYS[] = {
		&SAMPLE_RSA_KEY,
		&SAMPLE_ECDSA_KEY,
	};
	assert(KEYS_COUNT == sizeof(KEYS) / sizeof(*KEYS));

	for (int i = 0; i < KEYS_COUNT; i++) {
		test_algorithm(store, KEYS[i]);
	}

	r = dnssec_keystore_close(store);
	ok(r == DNSSEC_EOK, "dnssec_keystore_close()");
done:
	dnssec_keystore_deinit(store);
	dnssec_crypto_cleanup();
	token_cleanup();

	return 0;
}
