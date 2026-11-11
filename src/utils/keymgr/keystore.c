/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "utils/keymgr/keystore.h"

#include "contrib/color.h"
#include "contrib/string.h"
#include "contrib/time.h"
#include "libknot/libknot.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/server/dthreads.h"
#include "utils/common/msg.h"

#define DFLT_ID "-"

#define TEST_FORMAT  "%-20s %10s %5s %7s %7s %13s %5s %7s %7s\n"
#define BENCH_FORMAT "%-20s %9s %9s\n"
#define BENCH_TIME   3000

const key_parameters_t *KEYS[] = {
	&SAMPLE_RSA1024_SHA256_KEY,
	&SAMPLE_RSA2048_SHA256_KEY,
	&SAMPLE_RSA4096_SHA256_KEY,
	&SAMPLE_RSA1024_SHA512_KEY,
	&SAMPLE_RSA2048_SHA512_KEY,
	&SAMPLE_RSA4096_SHA512_KEY,
	&SAMPLE_ECDSA_P256_SHA256_KEY,
	&SAMPLE_ECDSA_P384_SHA384_KEY,
	&SAMPLE_ED25519_KEY,
	&SAMPLE_ED448_KEY,
#ifdef HAVE_MLDSA44
	&SAMPLE_MLDSA44_KEY,
#endif
	NULL
};

typedef enum {
	TEST_NONE = 0,
	TEST_OK,
	TEST_ERR,
} test_state_t;

typedef struct {
	dnssec_binary_t input;
	dnssec_binary_t signature;
	dnssec_key_t *key;
} test_ctx_t;

static int create_dnskey(dnssec_keystore_t *keystore, const char *id,
                         dnssec_key_algorithm_t algorithm, dnssec_key_t **key_ptr)
{
	dnssec_key_t *key = NULL;
	if (dnssec_key_new(&key) != KNOT_EOK ||
	    dnssec_key_set_algorithm(key, algorithm) != KNOT_EOK ||
	    dnssec_keystore_get_private(keystore, id, key) != KNOT_EOK) {
		dnssec_key_free(key);
		return KNOT_ERROR;
	}

	*key_ptr = key;

	return KNOT_EOK;
}

static int test_ctx_init(test_ctx_t *ctx, dnssec_keystore_t *store,
                         const char *keyid, dnssec_key_algorithm_t algorithm)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->input.data = (uint8_t *)"WuSEFCiFEKDTKuErihBW76q7p70dHuCfS6c1ffCK6ST";
	ctx->input.size = strlen((char *)ctx->input.data);
	assert(ctx->input.size > 0);
	return create_dnskey(store, keyid, algorithm, &ctx->key);
}

static void test_ctx_deinit(test_ctx_t *ctx)
{
	dnssec_key_free(ctx->key);
	dnssec_binary_free(&ctx->signature);
	memset(ctx, 0, sizeof(*ctx));
}

static int test_sign(test_ctx_t *ctx)
{
	dnssec_sign_ctx_t *sign_ctx = NULL;

	if (dnssec_sign_new(&sign_ctx, ctx->key) != KNOT_EOK ||
	    dnssec_sign_add(sign_ctx, &ctx->input) != KNOT_EOK ||
	    dnssec_sign_write(sign_ctx, DNSSEC_SIGN_NORMAL, &ctx->signature) != KNOT_EOK) {
		dnssec_sign_free(sign_ctx);
		return KNOT_ERROR;
	}

	dnssec_sign_free(sign_ctx);

	return KNOT_EOK;
}

static int test_verify(test_ctx_t *ctx)
{
	dnssec_sign_ctx_t *sign_ctx = NULL;

	if (dnssec_sign_new(&sign_ctx, ctx->key) != KNOT_EOK ||
	    dnssec_sign_add(sign_ctx, &ctx->input) != KNOT_EOK ||
	    dnssec_sign_verify(sign_ctx, false, &ctx->signature) != KNOT_EOK) {
		dnssec_sign_free(sign_ctx);
		return KNOT_ERROR;
	}

	dnssec_sign_free(sign_ctx);

	return KNOT_EOK;
}

static void test_key_use(dnssec_keystore_t *store, const char *keyid,
                         dnssec_key_algorithm_t algorithm,
                         test_state_t *sign_ok, test_state_t *verify_ok)
{
	test_ctx_t ctx;
	if (test_ctx_init(&ctx, store, keyid, algorithm) != KNOT_EOK) {
		return;
	}

	*sign_ok = (test_sign(&ctx) == KNOT_EOK) ? TEST_OK : TEST_ERR;
	if (*sign_ok == TEST_OK) {
		*verify_ok = (test_verify(&ctx) == KNOT_EOK) ? TEST_OK : TEST_ERR;
	}

	test_ctx_deinit(&ctx);
}

static void print_result_cell(test_state_t success, int width, bool color)
{
	char buf[32];
	(void)snprintf(buf, sizeof(buf), "%*s", width,
	               (success == TEST_OK) ? "YES" : (success == TEST_ERR ? " no" : " - "));

	if (success == TEST_OK && color) {
		printf("%s%s%s", COL_BOLD(color), buf, COL_RST(color));
	} else {
		printf("%s", buf);
	}
}

static void test_algorithm(dnssec_keystore_t *store, const key_parameters_t *params, bool c)
{
	struct {
		test_state_t generate;
		test_state_t ge_sign;
		test_state_t ge_verify;
		test_state_t ge_remove;
		test_state_t import;
		test_state_t im_sign;
		test_state_t im_verify;
		test_state_t im_remove;
	} res = { 0 };

	char *id = NULL;
	int ret = dnssec_keystore_generate(store, params->algorithm,
	                                   params->bit_size, NULL, &id);
	if (ret == KNOT_EOK) {
		res.generate = TEST_OK;

		test_key_use(store, id, params->algorithm, &res.ge_sign, &res.ge_verify);

		res.ge_remove = (dnssec_keystore_remove(store, id) == KNOT_EOK) ? TEST_OK : TEST_ERR;
		free(id);
	} else {
		res.generate = TEST_ERR;
	}

	ret = dnssec_keystore_import(store, &params->pem, &id);
	if (ret == KNOT_EOK) {
		res.import = TEST_OK;

		test_key_use(store, id, params->algorithm, &res.im_sign, &res.im_verify);

		res.im_remove = (dnssec_keystore_remove(store, id) == KNOT_EOK) ? TEST_OK : TEST_ERR;
		free(id);
	} else {
		res.import = TEST_ERR;
	}

	const knot_lookup_t *alg_info = knot_lookup_by_id(knot_dnssec_alg_names,
	                                                  params->algorithm);
	assert(alg_info);
	char *name_keysz = sprintf_alloc("%s %db", alg_info->name, params->bit_size);
	assert(name_keysz);

	// the alignment of the output was chosen by hand to make it look nice in a terminal
	printf("%-20s ", name_keysz);
	print_result_cell(res.generate,   7, c);
	print_result_cell(res.ge_sign,    8, c);
	print_result_cell(res.ge_verify,  8, c);
	print_result_cell(res.ge_remove,  8, c);
	print_result_cell(res.import,    12, c);
	print_result_cell(res.im_sign,    8, c);
	print_result_cell(res.im_verify,  8, c);
	print_result_cell(res.im_remove,  8, c);
	printf("\n");

	free(name_keysz);
}

static int init_keystore(dnssec_keystore_t **store, const char *keystore_id,
                         unsigned threads, int algorithm)
{
	size_t len = strlen(keystore_id) + 1;
	conf_val_t id = conf_rawid_get(conf(), C_KEYSTORE, C_ID,
	                               (const uint8_t *)keystore_id, len);
	if (id.code != KNOT_EOK && strcmp(keystore_id, DFLT_ID) != 0) {
		ERR2("keystore '%s' not configured", keystore_id);
		return id.code;
	}
	id.blob = (const uint8_t *)keystore_id;
	id.blob_len = len;

	knot_kasp_keystore_t *keystores = NULL;

	int ret = zone_init_keystore(conf(), NULL, &id, &keystores);
	if (ret != KNOT_EOK) {
		ERR2("failed to open '%s' keystore (%s)", keystore_id, knot_strerror(ret));
		return ret;
	}
	assert(keystores[0].count == 1);
	*store = keystores[0].keystore;

	if (strcmp(keystore_id, DFLT_ID) == 0) {
		printf("Keystore default");
	} else {
		printf("Keystore id '%s'", keystore_id);
	}
	printf(", type %s", (keystores[0].backend == KEYSTORE_BACKEND_PEM ? "PEM" : "PKCS #11"));
	if (threads > 0) {
		printf(", threads %u", threads);
	}
	if (algorithm > 0) {
		printf(", algorithm %d", algorithm);
	}
	printf("\n\n");

	free(keystores);
	return KNOT_EOK;
}

int keymgr_keystore_test(const char *keystore_id, keymgr_list_params_t *params)
{
	dnssec_keystore_t *store = NULL;

	int ret = init_keystore(&store, keystore_id, 0, -1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	const bool c = params->color;
	printf("%s" TEST_FORMAT "%s",
	       COL_UNDR(c),
	       "Algorithm", "Generate:", "Sign", "Verify", "Remove",
	                    "Import:",   "Sign", "Verify", "Remove",
	       COL_RST(c));

	for (int i = 0; KEYS[i] != NULL; i++) {
		test_algorithm(store, KEYS[i], c);
	}

	dnssec_keystore_deinit(store);

	return KNOT_EOK;
}

struct result {
	unsigned long ops;
	unsigned long time;
};

typedef struct {
	dnssec_sign_ctx_t **ctxs;
	struct result *results;
} bench_ctx_t;

static int bench_sign(dthread_t *dt)
{
	assert(dt != NULL && dt->data != NULL);

	bench_ctx_t *data = dt->data;
	dnssec_sign_ctx_t *ctx = data->ctxs[dt_get_id(dt)];
	struct result *result = &data->results[dt_get_id(dt)];

	result->time = 0;
	result->ops = 0;

	uint8_t input_data[64];
	dnssec_binary_t input = {
		.data = input_data,
		.size = sizeof(input_data)
	};
	(void)dnssec_random_binary(&input);

	struct timespec start_ts, end_ts;
	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	while (result->time < BENCH_TIME) {
		dnssec_binary_t sign = { 0 };
		if (dnssec_sign_init(ctx) != KNOT_EOK ||
		    dnssec_sign_add(ctx, &input) != KNOT_EOK ||
		    dnssec_sign_write(ctx, DNSSEC_SIGN_NORMAL, &sign) != KNOT_EOK) {
			dnssec_binary_free(&sign);
			result->time = 0;
			break;
		}
		memcpy(input.data, sign.data, MIN(input.size, sign.size));
		dnssec_binary_free(&sign);

		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		result->time = time_diff_ms(&start_ts, &end_ts);
		result->ops++;
	}

	return KNOT_EOK;
}

static int bench_verify(dthread_t *dt)
{
	assert(dt != NULL && dt->data != NULL);

	bench_ctx_t *data = dt->data;
	dnssec_sign_ctx_t *ctx = data->ctxs[dt_get_id(dt)];
	struct result *result = &data->results[dt_get_id(dt)];

	result->time = 0;
	result->ops = 0;

	uint8_t input_data[64];
	dnssec_binary_t input = {
		.data = input_data,
		.size = sizeof(input_data)
	};
	(void)dnssec_random_binary(&input);

	dnssec_binary_t signature = { 0 };
	if (dnssec_sign_init(ctx) != KNOT_EOK ||
	    dnssec_sign_add(ctx, &input) != KNOT_EOK ||
	    dnssec_sign_write(ctx, DNSSEC_SIGN_NORMAL, &signature) != KNOT_EOK) {
		dnssec_binary_free(&signature);
		result->time = 0;
		return KNOT_EOK;
	}

	struct timespec start_ts, end_ts;
	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	while (result->time < BENCH_TIME) {
		if (dnssec_sign_init(ctx) != KNOT_EOK ||
		    dnssec_sign_add(ctx, &input) != KNOT_EOK ||
		    dnssec_sign_verify(ctx, false, &signature) != KNOT_EOK) {
			result->time = 0;
			break;
		}

		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		result->time = time_diff_ms(&start_ts, &end_ts);
		result->ops++;
	}

	dnssec_binary_free(&signature);

	return KNOT_EOK;
}

static int run_pass(int threads, runnable_t fn, void *data)
{
	int ret = KNOT_EOK;
	dt_unit_t *pool = dt_create(threads, fn, NULL, data);
	if (pool == NULL ||
	    dt_start(pool) != KNOT_EOK ||
	    dt_join(pool) != KNOT_EOK) {
		ret = KNOT_ERROR;
	}
	dt_delete(&pool);
	return ret;
}

static unsigned rate(const struct result *results, unsigned threads)
{
	double f = 0.0;
	for (unsigned t = 0; t < threads; t++) {
		if (results[t].time == 0) {
			return 0;
		}
		f += results[t].ops * 1000.0 / results[t].time;
	}
	return (unsigned)(f + 0.5); // round to nearest integer
}

static void fmt_rate(char *buf, size_t len, unsigned rate_val, bool ok)
{
	if (ok && rate_val > 0) {
		(void)snprintf(buf, len, "%u", rate_val);
	} else {
		(void)snprintf(buf, len, "n/a");
	}
}

static int run_bench(uint16_t threads, dnssec_key_t *key, struct result *results,
                     runnable_t bench_fn)
{
	dnssec_key_t *keys[threads];
	dnssec_sign_ctx_t *ctxs[threads];
	memset(keys, 0, sizeof(keys));
	memset(ctxs, 0, sizeof(ctxs));

	int ret = KNOT_ERROR;
	for (unsigned t = 0; t < threads; t++) {
		keys[t] = dnssec_key_dup(key);
		if (!keys[t] || dnssec_sign_new(&ctxs[t], keys[t]) != KNOT_EOK) {
			goto cleanup;
		}
	}

	bench_ctx_t ctx = { .ctxs = ctxs, .results = results };
	ret = run_pass(threads, bench_fn, &ctx);

cleanup:
	for (unsigned t = 0; t < threads; t++) {
		dnssec_sign_free(ctxs[t]);
		dnssec_key_free(keys[t]);
	}
	return ret;
}

int keymgr_keystore_bench(const char *keystore_id, keymgr_list_params_t *params,
                          uint16_t threads, int algorithm)
{
	dnssec_keystore_t *store = NULL;

	int ret = init_keystore(&store, keystore_id, threads, algorithm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	const bool c = params->color;
	printf("%s" BENCH_FORMAT "%s",
	       COL_UNDR(c),
	       "Algorithm", "Sign/s", "Verify/s",
	       COL_RST(c));

	for (int i = 0; KEYS[i] != NULL; i++) {
		if (algorithm > 0 && algorithm != KEYS[i]->algorithm) {
			continue;
		}

		struct result sign_results[threads];
		struct result verify_results[threads];
		memset(sign_results, 0, sizeof(sign_results));
		memset(verify_results, 0, sizeof(verify_results));

		char *id = NULL;
		dnssec_key_t *key = NULL;

		ret = dnssec_keystore_generate(store, KEYS[i]->algorithm,
		                               KEYS[i]->bit_size, NULL, &id);
		if (ret != KNOT_EOK) {
			goto finish;
		}

		ret = create_dnskey(store, id, KEYS[i]->algorithm, &key);
		if (ret != KNOT_EOK) {
			goto finish;
		}

		ret = run_bench(threads, key, sign_results, bench_sign);
		if (ret != KNOT_EOK) {
			goto finish;
		}

		ret = run_bench(threads, key, verify_results, bench_verify);

finish:
		dnssec_key_free(key);
		if (id != NULL) {
			(void)dnssec_keystore_remove(store, id);
			free(id);
		}

		const knot_lookup_t *alg_info = knot_lookup_by_id(knot_dnssec_alg_names,
		                                                  KEYS[i]->algorithm);
		assert(alg_info);
		char *name_keysz = sprintf_alloc("%s %db", alg_info->name, KEYS[i]->bit_size);
		assert(name_keysz);

		char sign_s[16], verify_s[16];
		fmt_rate(sign_s, sizeof(sign_s), rate(sign_results, threads), ret == KNOT_EOK);
		fmt_rate(verify_s, sizeof(verify_s), rate(verify_results, threads), ret == KNOT_EOK);
		printf(BENCH_FORMAT, name_keysz, sign_s, verify_s);
		free(name_keysz);
	}

	dnssec_keystore_deinit(store);

	return KNOT_EOK;
}
