/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include "knot/include/module.h"
#include "libknot/libknot.h"
#include "contrib/atomic.h"
#include "contrib/threads.h"
#include "contrib/string.h"
#include "libknot/dnssec/random.h"

#define BADCOOKIE_CTR_INIT	1

#define MOD_SECRET_LIFETIME "\x0F""secret-lifetime"
#define MOD_BADCOOKIE_SLIP  "\x0E""badcookie-slip"
#define MOD_SECRET          "\x06""secret"

const yp_item_t cookies_conf[] = {
	{ MOD_SECRET_LIFETIME, YP_TINT, YP_VINT = { 1, 36*24*3600, 26*3600, YP_STIME } },
	{ MOD_BADCOOKIE_SLIP,  YP_TINT, YP_VINT = { 1, INT32_MAX, 1 } },
	{ MOD_SECRET,          YP_THEX, YP_VNONE, YP_FMULTI },
	{ NULL }
};

int cookies_conf_check(knotd_conf_check_args_t *args)
{
	knotd_conf_t conf = knotd_conf_check_item(args, MOD_SECRET);
	if (conf.count > 2) {
		args->err_str = "up to two cookie values can be configured";
		knotd_conf_free(&conf);
		return KNOT_EINVAL;
	}
	for (int i = 0; i < conf.count; ++i) {
		if (conf.multi[i].data_len != KNOT_EDNS_COOKIE_SECRET_SIZE) {
			args->err_str = "length of the cookie secret must be "
			                "32 HEX characters (16 bytes)";
			knotd_conf_free(&conf);
			return KNOT_EINVAL;
		}
	}
	knotd_conf_free(&conf);

	return KNOT_EOK;
}

typedef struct {
	struct {
		knot_atomic_uint64_t variable;
		uint64_t constant;
	} secret[2];
	pthread_t update_secret;
	uint32_t secret_lifetime;
	uint32_t badcookie_slip;
	knot_atomic_uint16_t badcookie_ctr; // Counter for BADCOOKIE answers.
	uint8_t secret_cnt;
} cookies_ctx_t;

static void update_ctr(cookies_ctx_t *ctx)
{
	assert(ctx);

	if (ATOMIC_GET(ctx->badcookie_ctr) < ctx->badcookie_slip) {
		ATOMIC_ADD(ctx->badcookie_ctr, 1);
	} else {
		ATOMIC_SET(ctx->badcookie_ctr, BADCOOKIE_CTR_INIT);
	}
}

static int generate_secret(cookies_ctx_t *ctx)
{
	assert(ctx);

	// Generate a new variable part of the server secret.
	uint64_t new_secret;
	int ret = dnssec_random_buffer((uint8_t *)&new_secret, sizeof(new_secret));
	if (ret != KNOT_EOK) {
		return ret;
	}

	ATOMIC_SET(ctx->secret[0].variable, new_secret);

	return KNOT_EOK;
}

static void *update_secret(void *data)
{
	knotd_mod_t *mod = (knotd_mod_t *)data;
	cookies_ctx_t *ctx = knotd_mod_ctx(mod);

	while (true) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		int ret = generate_secret(ctx);
		if (ret != KNOT_EOK) {
			knotd_mod_log(mod, LOG_ERR, "failed to generate a secret (%s)",
			              knot_strerror(ret));
		}
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		sleep(ctx->secret_lifetime);
	}

	return NULL;
}

// Inserts the current cookie option into the answer's OPT RR.
static int put_cookie(knotd_qdata_t *qdata, knot_pkt_t *pkt,
                      const knot_edns_cookie_t *cc, const  knot_edns_cookie_t *sc)
{
	assert(qdata && pkt && cc && sc);

	uint8_t *option = NULL;
	uint16_t option_size = knot_edns_cookie_size(cc, sc);
	int ret = knot_edns_reserve_option(&qdata->opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                                   option_size, &option, qdata->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_edns_cookie_write(option, option_size, cc, sc);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Reserve extra space for the cookie option.
	ret = knot_pkt_reserve(pkt, KNOT_EDNS_OPTION_HDRLEN + option_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

static knotd_state_t cookies_process(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	cookies_ctx_t *ctx = knotd_mod_ctx(mod);

	// Check if the cookie option is present.
	uint8_t *cookie_opt = knot_pkt_edns_option(qdata->query,
	                                           KNOT_EDNS_OPTION_COOKIE);
	if (cookie_opt == NULL) {
		return state;
	}

	// Increment the statistics counter.
	knotd_mod_stats_incr(mod, qdata->params->thread_id, 0, 0, 1);

	knot_edns_cookie_t cc;
	knot_edns_cookie_t sc;

	// Parse the cookie from wireformat.
	const uint8_t *data = knot_edns_opt_get_data(cookie_opt);
	uint16_t data_len = knot_edns_opt_get_length(cookie_opt);
	int ret = knot_edns_cookie_parse(&cc, &sc, data, data_len);
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return KNOTD_STATE_FAIL;
	}

	// Prepare data for server cookie computation.
	knot_edns_cookie_params_t params = {
		.version = KNOT_EDNS_COOKIE_VERSION,
		.timestamp = (uint32_t)time(NULL),
		.lifetime_before = 3600,
		.lifetime_after = 300,
		.client_addr = knotd_qdata_remote_addr(qdata)
	};

	// Try the old secret first to ensure the new secret stays in the params.
	for (int i = ctx->secret_cnt - 1; i >= 0; --i) {
		uint64_t current_secret = ATOMIC_GET(ctx->secret[i].variable);
		memcpy(params.secret, &current_secret, sizeof(current_secret));
		memcpy(params.secret + sizeof(current_secret), &ctx->secret[i].constant,
		       sizeof(ctx->secret[i].constant));

		// Compare server cookie.
		ret = knot_edns_cookie_server_check(&sc, &cc, &params);
		if (ret == KNOT_EOK) {
			break;
		}
	}
	if (ret != KNOT_EOK) {
		// Established connection (TCP or QUIC) is taken into account,
		// so a normal response is provided.
		if (qdata->params->proto != KNOTD_QUERY_PROTO_UDP) {
			if (knot_edns_cookie_server_generate(&sc, &cc, &params) != KNOT_EOK ||
			    put_cookie(qdata, pkt, &cc, &sc) != KNOT_EOK)
			{
				return KNOTD_STATE_FAIL;
			}

			return state;
		} else if (ATOMIC_GET(ctx->badcookie_ctr) > BADCOOKIE_CTR_INIT) {
			// Silently drop the response.
			update_ctr(ctx);
			knotd_mod_stats_incr(mod, qdata->params->thread_id, 1, 0, 1);
			return KNOTD_STATE_NOOP;
		} else {
			if (ctx->badcookie_slip > 1) {
				update_ctr(ctx);
			}

			if (knot_edns_cookie_server_generate(&sc, &cc, &params) != KNOT_EOK ||
			    put_cookie(qdata, pkt, &cc, &sc) != KNOT_EOK)
			{
				return KNOTD_STATE_FAIL;
			}

			qdata->rcode = KNOT_RCODE_BADCOOKIE;
			return KNOTD_STATE_FAIL;
		}
	}

	// Reuse valid server cookie.
	ret = put_cookie(qdata, pkt, &cc, &sc);
	if (ret != KNOT_EOK) {
		return KNOTD_STATE_FAIL;
	}

	// Set the valid cookie flag.
	qdata->params->flags |= KNOTD_QUERY_FLAG_COOKIE;

	return state;
}

int cookies_load(knotd_mod_t *mod)
{
	// Create module context.
	cookies_ctx_t *ctx = calloc(1, sizeof(cookies_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Initialize atomic variables.
	ATOMIC_INIT(ctx->badcookie_ctr, BADCOOKIE_CTR_INIT);
	for (int i = 0; i < 2; ++i) {
		ATOMIC_INIT(ctx->secret[i].variable, 0);
	}

	// Set up configurable items.
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_BADCOOKIE_SLIP);
	ctx->badcookie_slip = conf.single.integer;

	// Set up statistics counters.
	int ret = knotd_mod_stats_add(mod, "presence", 1, NULL);
	if (ret != KNOT_EOK) {
		free(ctx);
		return ret;
	}

	ret = knotd_mod_stats_add(mod, "dropped", 1, NULL);
	if (ret != KNOT_EOK) {
		free(ctx);
		return ret;
	}

	// Store module context before rollover thread is created.
	knotd_mod_ctx_set(mod, ctx);

	// Initialize the server secret.
	conf = knotd_conf_mod(mod, MOD_SECRET);
	ctx->secret_cnt = conf.count;
	for (int i = 0; i < ctx->secret_cnt; ++i) {
		assert(conf.multi[i].data_len == KNOT_EDNS_COOKIE_SECRET_SIZE);
		uint64_t conf_secret[2];
		memcpy(conf_secret, conf.multi[i].data, conf.multi[i].data_len);
		ATOMIC_SET(ctx->secret[i].variable, conf_secret[0]);
		ctx->secret[i].constant = conf_secret[1];
		assert(ctx->secret_lifetime == 0);
	}
	knotd_conf_free(&conf);
	if (ctx->secret_cnt == 0) {
		uint64_t gen_secret[2];
		ret = dnssec_random_buffer((uint8_t *)gen_secret, sizeof(gen_secret));
		if (ret != KNOT_EOK) {
			free(ctx);
			return ret;
		}
		ATOMIC_SET(ctx->secret[0].variable, gen_secret[0]);
		ctx->secret[0].constant = gen_secret[1];
		ctx->secret_cnt = 1;

		conf = knotd_conf_mod(mod, MOD_SECRET_LIFETIME);
		ctx->secret_lifetime = conf.single.integer;

		// Start the secret rollover thread.
		if (thread_create_nosignal(&ctx->update_secret, update_secret, (void *)mod)) {
			knotd_mod_log(mod, LOG_ERR, "failed to create the secret rollover thread");
			free(ctx);
			return KNOT_ERROR;
		}
	}

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, cookies_process);
}

void cookies_unload(knotd_mod_t *mod)
{
	cookies_ctx_t *ctx = knotd_mod_ctx(mod);
	if (ctx->secret_lifetime > 0) {
		(void)pthread_cancel(ctx->update_secret);
		(void)pthread_join(ctx->update_secret, NULL);
	}
	ATOMIC_DEINIT(ctx->badcookie_ctr);
	for (int i = 0; i < 2; ++i) {
		ATOMIC_DEINIT(ctx->secret[i].variable);
	}
	memzero(&ctx->secret, sizeof(ctx->secret));
	free(ctx);
}

KNOTD_MOD_API(cookies, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              cookies_load, cookies_unload, cookies_conf, cookies_conf_check);
