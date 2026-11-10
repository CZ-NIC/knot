/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdio.h>

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

#define TEST_FORMAT  "%-20s %9s %9s %9s %9s %9s\n"
#define BENCH_FORMAT "%-20s %7s %9s\n"
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

static const dnssec_binary_t fixed_input = {
	.data = (uint8_t *)"WuSEFCiFEKDTKuErihBW76q7p70dHuCfS6c1ffCK6ST",
	.size = 43
};

typedef struct {
	dnssec_key_t *test_key;
	dnssec_key_t *ref_key;
	dnssec_binary_t sign;
} test_ctx_t;

static int create_dnskeys(dnssec_keystore_t *keystore, const char *id,
                          dnssec_key_algorithm_t algorithm,
                          dnssec_key_t **test_key_ptr, dnssec_key_t **ref_key_ptr)
{
	dnssec_key_t *test_key = NULL;
	if (dnssec_key_new(&test_key) != KNOT_EOK ||
	    dnssec_key_set_algorithm(test_key, algorithm) != KNOT_EOK ||
	    dnssec_keystore_get_private(keystore, id, test_key) != KNOT_EOK) {
		dnssec_key_free(test_key);
		return KNOT_ERROR;
	}

	dnssec_binary_t rdata;
	dnssec_key_t *ref_key = NULL;
	if (dnssec_key_new(&ref_key) != KNOT_EOK ||
	    dnssec_key_get_rdata(test_key, &rdata) != KNOT_EOK ||
	    dnssec_key_set_rdata(ref_key, &rdata) != KNOT_EOK) {
		dnssec_key_free(test_key);
		dnssec_key_free(ref_key);
		return KNOT_ERROR;
	}

	*test_key_ptr = test_key;
	*ref_key_ptr = ref_key;

	return KNOT_EOK;
}

static void test_ctx_deinit(test_ctx_t *ctx)
{
	dnssec_key_free(ctx->test_key);
	dnssec_key_free(ctx->ref_key);
	dnssec_binary_free(&ctx->sign);
	memset(ctx, 0, sizeof(*ctx));
}

static int test_ctx_init(test_ctx_t *ctx, dnssec_keystore_t *store,
                         const char *keyid, dnssec_key_algorithm_t algorithm)
{
	memset(ctx, 0, sizeof(*ctx));
	return create_dnskeys(store, keyid, algorithm, &ctx->test_key, &ctx->ref_key);
}

static int test_sign(test_ctx_t *ctx)
{
	dnssec_sign_ctx_t *sign_ctx = NULL;
	int ret = KNOT_ERROR;

	if (dnssec_sign_new(&sign_ctx, ctx->test_key) == KNOT_EOK &&
	    dnssec_sign_add(sign_ctx, &fixed_input) == KNOT_EOK &&
	    dnssec_sign_write(sign_ctx, DNSSEC_SIGN_NORMAL, &ctx->sign) == KNOT_EOK) {
		ret = KNOT_EOK;
	}

	dnssec_sign_free(sign_ctx);
	return ret;
}

static int test_verify(test_ctx_t *ctx)
{
	dnssec_key_t *keys[] = { ctx->test_key, ctx->ref_key };

	for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		dnssec_sign_ctx_t *sign_ctx = NULL;
		if (dnssec_sign_new(&sign_ctx, keys[i]) != KNOT_EOK ||
		    dnssec_sign_add(sign_ctx, &fixed_input) != KNOT_EOK ||
		    dnssec_sign_verify(sign_ctx, false, &ctx->sign) != KNOT_EOK) {
			dnssec_sign_free(sign_ctx);
			return KNOT_ERROR;
		}
		dnssec_sign_free(sign_ctx);
	}

	return KNOT_EOK;
}

static void test_key_use(dnssec_keystore_t *store, const char *keyid,
                         dnssec_key_algorithm_t algorithm,
                         bool *sign_ok, bool *verify_ok)
{
	*sign_ok = false;
	*verify_ok = false;

	test_ctx_t ctx;
	if (test_ctx_init(&ctx, store, keyid, algorithm) != KNOT_EOK) {
		return;
	}

	*sign_ok = (test_sign(&ctx) == KNOT_EOK);
	if (*sign_ok) {
		*verify_ok = (test_verify(&ctx) == KNOT_EOK);
	}

	test_ctx_deinit(&ctx);
}

static void test_algorithm(dnssec_keystore_t *store,
                           const key_parameters_t *params)
{
	struct {
		bool generate;
		bool import;
		bool remove;
		bool sign;
		bool verify;
	} res = { 0 };

	char *id = NULL;
	int ret = dnssec_keystore_generate(store, params->algorithm,
	                                   params->bit_size, NULL, &id);
	if (ret == KNOT_EOK) {
		res.generate = true;

		test_key_use(store, id, params->algorithm, &res.sign, &res.verify);

		ret = dnssec_keystore_remove(store, id);
		res.remove = (ret == KNOT_EOK);
		free(id);
	}

	ret = dnssec_keystore_import(store, &params->pem, &id);
	if (ret == KNOT_EOK) {
		res.import = true;

		if (res.generate) {
			bool sign_ok, verify_ok;
			test_key_use(store, id, params->algorithm, &sign_ok, &verify_ok);
			res.sign &= sign_ok;
			res.verify &= verify_ok;
		} else {
			test_key_use(store, id, params->algorithm, &res.sign, &res.verify);
		}

		ret = dnssec_keystore_remove(store, id);
		if (res.generate) {
			res.remove &= (ret == KNOT_EOK);
		} else {
			res.remove = (ret == KNOT_EOK);
		}
		free(id);
	}

	const knot_lookup_t *alg_info = knot_lookup_by_id(knot_dnssec_alg_names,
	                                                  params->algorithm);
	assert(alg_info);
	char *name_keysz = sprintf_alloc("%s %db", alg_info->name, params->bit_size);
	assert(name_keysz);

	printf(TEST_FORMAT,
	       name_keysz,
	       res.generate ? "yes" : "no",
	       res.import   ? "yes" : "no",
	       res.remove   ? "yes" : "no",
	       res.sign     ? "yes" : "no",
	       res.verify   ? "yes" : "no");

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
	};
	printf(", type %s", (keystores[0].backend == KEYSTORE_BACKEND_PEM ? "PEM" : "PKCS #11"));
	if (threads > 0) {
		printf(", threads %u", threads);
	}
	if (algorithm > 0) {
		printf(", algorithm %u", algorithm);
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
		goto done;
	}

	const bool c = params->color;
	printf("%s" TEST_FORMAT "%s",
	       COL_UNDR(c),
	       "Algorithm", "Generate", "Import", "Remove", "Sign", "Verify",
	       COL_RST(c));
	for (int i = 0; KEYS[i] != NULL; i++) {
		test_algorithm(store, KEYS[i]);
	}
done:
	dnssec_keystore_deinit(store);

	return ret;
}

struct result {
	unsigned long signs;
	unsigned long time;
};

typedef struct {
	dnssec_sign_ctx_t **ctxs;
	struct result *results;
	const dnssec_binary_t *input;
	const dnssec_binary_t *sig;
} bench_ctx_t;

static int bench(dthread_t *dt)
{
	assert(dt != NULL && dt->data != NULL);

	bench_ctx_t *data = dt->data;
	dnssec_sign_ctx_t *ctx = data->ctxs[dt_get_id(dt)];
	struct result *result = &data->results[dt_get_id(dt)];

	result->time = 0;
	result->signs = 0;

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
		result->signs++;
	}

	return KNOT_EOK;
}

static int bench_verify(dthread_t *dt)
{
	assert(dt != NULL && dt->data != NULL);

	bench_ctx_t *data = dt->data;
	dnssec_sign_ctx_t *ctx = data->ctxs[dt_get_id(dt)];
	struct result *result = &data->results[dt_get_id(dt)];
	dnssec_binary_t input = *data->input;
	dnssec_binary_t sig = *data->sig;

	result->time = 0;
	result->signs = 0;

	struct timespec start_ts, end_ts;
	clock_gettime(CLOCK_MONOTONIC, &start_ts);

	while (result->time < BENCH_TIME) {
		if (dnssec_sign_init(ctx) != KNOT_EOK ||
		    dnssec_sign_add(ctx, &input) != KNOT_EOK ||
		    dnssec_sign_verify(ctx, false, &sig) != KNOT_EOK) {
			result->time = 0;
			break;
		}

		clock_gettime(CLOCK_MONOTONIC, &end_ts);
		result->time = time_diff_ms(&start_ts, &end_ts);
		result->signs++;
	}

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

static unsigned rate(const struct result *res, unsigned threads)
{
	double f = 0.0;
	for (unsigned t = 0; t < threads; t++) {
		if (res[t].time == 0) {
			return 0;
		}
		f += res[t].signs * 1000.0 / res[t].time;
	}
	return (unsigned)(f + 0.5); // round to nearest integer
}

static void fmt_rate(char *buf, size_t len, unsigned rate, bool ok)
{
	if (ok && rate > 0) {
		snprintf(buf, len, "%u", rate);
	} else {
		snprintf(buf, len, "n/a");
	}
}

static int run_sign_pass(uint16_t threads, dnssec_key_t *test_key,
                         const dnssec_binary_t *input, dnssec_binary_t *out_sig,
                         struct result *out_results)
{
	dnssec_key_t **keys = calloc(threads, sizeof(*keys));
	dnssec_sign_ctx_t **ctxs = calloc(threads, sizeof(*ctxs));
	int ret = KNOT_ERROR;

	if (!keys || !ctxs) goto cleanup;

	for (unsigned t = 0; t < threads; t++) {
		keys[t] = dnssec_key_dup(test_key);
		if (!keys[t] || dnssec_sign_new(&ctxs[t], keys[t]) != KNOT_EOK) {
			goto cleanup;
		}
	}

	if (dnssec_sign_add(ctxs[0], input) != KNOT_EOK ||
	    dnssec_sign_write(ctxs[0], DNSSEC_SIGN_NORMAL, out_sig) != KNOT_EOK) {
		goto cleanup;
	}

	bench_ctx_t ds = { .ctxs = ctxs, .results = out_results };
	ret = run_pass(threads, bench, &ds);

cleanup:
	for (unsigned t = 0; t < threads; t++) {
		if (keys) dnssec_key_free(keys[t]);
		if (ctxs) dnssec_sign_free(ctxs[t]);
	}
	free(keys);
	free(ctxs);
	return ret;
}

static int run_verify_pass(uint16_t threads, dnssec_key_t *ref_key,
                          const dnssec_binary_t *input, const dnssec_binary_t *sig,
                          struct result *out_results)
{
	dnssec_key_t **keys = calloc(threads, sizeof(*keys));
	dnssec_sign_ctx_t **ctxs = calloc(threads, sizeof(*ctxs));
	int ret = KNOT_ERROR;

	if (!keys || !ctxs) goto cleanup;

	for (unsigned t = 0; t < threads; t++) {
		keys[t] = dnssec_key_dup(ref_key);
		if (!keys[t] || dnssec_sign_new(&ctxs[t], keys[t]) != KNOT_EOK) {
			goto cleanup;
		}
	}

	bench_ctx_t dv = { .ctxs = ctxs, .results = out_results, .input = input, .sig = sig };
	ret = run_pass(threads, bench_verify, &dv);

cleanup:
	for (unsigned t = 0; t < threads; t++) {
		if (keys) dnssec_key_free(keys[t]);
		if (ctxs) dnssec_sign_free(ctxs[t]);
	}
	free(keys);
	free(ctxs);
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
	       COL_UNDR(c),	       "Algorithm", "Sign/s", "Verify/s",
	       COL_RST(c));

	for (int i = 0; KEYS[i] != NULL; i++) {
		if (algorithm > 0 && algorithm != KEYS[i]->algorithm) {
			continue;
		}

		dnssec_binary_t sig = { 0 };
		struct result sign_results[threads];
		struct result verify_results[threads];
		memset(sign_results, 0, sizeof(sign_results));
		memset(verify_results, 0, sizeof(verify_results));

		char *id = NULL;
		dnssec_key_t *test_key = NULL;
		dnssec_key_t *ref_key = NULL;
		ret = dnssec_keystore_generate(store, KEYS[i]->algorithm,
		                               KEYS[i]->bit_size, NULL, &id);
		if (ret != KNOT_EOK ||
		    create_dnskeys(store, id, KEYS[i]->algorithm,
		                   &test_key, &ref_key) != KNOT_EOK) {
			ret = KNOT_ERROR;
			goto finish;
		}

		ret = run_sign_pass(threads, test_key, &fixed_input, &sig, sign_results);
		if (ret != KNOT_EOK) {
			goto finish;
		}

		ret = run_verify_pass(threads, ref_key, &fixed_input, &sig, verify_results);

finish:
		dnssec_key_free(test_key);
		dnssec_key_free(ref_key);
		dnssec_binary_free(&sig);
		if (id != NULL) {
			(void)dnssec_keystore_remove(store, id);
			free(id);
		}

		const knot_lookup_t *alg_info = knot_lookup_by_id(
			knot_dnssec_alg_names, KEYS[i]->algorithm);
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
