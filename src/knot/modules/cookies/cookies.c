/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <pthread.h>
#include <unistd.h>

#include "knot/include/module.h"
#include "libknot/libknot.h"
#include "contrib/string.h"
#include "dnssec/lib/dnssec/random.h"

#ifdef HAVE_ATOMIC
#define ATOMIC_SET(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELAXED)
#define ATOMIC_GET(src)      __atomic_load_n(&(src), __ATOMIC_RELAXED)
#define ATOMIC_ADD(dst, val) __atomic_add_fetch(&(dst), (val), __ATOMIC_RELAXED)
#else
#define ATOMIC_SET(dst, val) ((dst) = (val))
#define ATOMIC_GET(src)      (src)
#define ATOMIC_ADD(dst, val) ((dst) += (val))
#endif

#define BADCOOKIE_CTR_INIT	1

#define MOD_SECRET_LIFETIME "\x0F""secret-lifetime"
#define MOD_BADCOOKIE_SLIP  "\x0E""badcookie-slip"

const yp_item_t cookies_conf[] = {
	{ MOD_SECRET_LIFETIME, YP_TINT, YP_VINT = { 1, 36*24*3600, 26*3600, YP_STIME } },
	{ MOD_BADCOOKIE_SLIP,  YP_TINT, YP_VINT = { 1, INT32_MAX, 1 } },
	{ NULL }
};

typedef struct {
	struct {
		uint64_t variable;
		uint64_t constant;
	} secret;
	pthread_t update_secret;
	uint32_t secret_lifetime;
	uint32_t badcookie_slip;
	uint16_t badcookie_ctr; // Counter for BADCOOKIE answers.
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

	ATOMIC_SET(ctx->secret.variable, new_secret);

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

	// DNS cookies are ignored in the case of the TCP connection.
	if (!(qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE)) {
		return state;
	}

	// Check if OPT RR is present.
	if (qdata->query->opt_rr == NULL) {
		return state;
	}

	// Check if the cookie option is present.
	uint8_t *cookie_opt = knot_edns_get_option(qdata->query->opt_rr,
	                                           KNOT_EDNS_OPTION_COOKIE);
	if (cookie_opt == NULL) {
		return state;
	}

	// Increment the statistics counter.
	knotd_mod_stats_incr(mod, 0, 0, 1);

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
	knot_edns_cookie_params_t params;
	params.client_addr = (struct sockaddr *)qdata->params->remote;
	uint64_t current_secret = ATOMIC_GET(ctx->secret.variable);
	memcpy(params.secret, &current_secret, sizeof(current_secret));
	memcpy(params.secret + sizeof(current_secret), &ctx->secret.constant,
	       sizeof(ctx->secret.constant));

	// Compare server cookie.
	ret = knot_edns_cookie_server_check(&sc, &cc, &params);
	if (ret != KNOT_EOK) {
		if (ATOMIC_GET(ctx->badcookie_ctr) > BADCOOKIE_CTR_INIT) {
			// Silently drop the response.
			update_ctr(ctx);
			return KNOTD_STATE_NOOP;
		} else {
			if (ctx->badcookie_slip > 1) {
				update_ctr(ctx);
			}

			ret = knot_edns_cookie_server_generate(&sc, &cc, &params);
			if (ret != KNOT_EOK) {
				return KNOTD_STATE_FAIL;
			}

			ret = put_cookie(qdata, pkt, &cc, &sc);
			if (ret != KNOT_EOK) {
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

	// Initialize BADCOOKIE counter.
	ctx->badcookie_ctr = BADCOOKIE_CTR_INIT;

	// Set up configurable items.
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_SECRET_LIFETIME);
	ctx->secret_lifetime = conf.single.integer;

	conf = knotd_conf_mod(mod, MOD_BADCOOKIE_SLIP);
	ctx->badcookie_slip = conf.single.integer;

	// Set up statistics counters.
	int ret = knotd_mod_stats_add(mod, "presence", 1, NULL);
	if (ret != KNOT_EOK) {
		free(ctx);
		return ret;
	}

	// Initialize the server secret.
	ret = dnssec_random_buffer((uint8_t *)&ctx->secret, sizeof(ctx->secret));
	if (ret != KNOT_EOK) {
		free(ctx);
		return ret;
	}

	knotd_mod_ctx_set(mod, ctx);

	// Start the secret rollover thread.
	if (pthread_create(&ctx->update_secret, NULL, update_secret, (void *)mod)) {
		knotd_mod_log(mod, LOG_ERR, "failed to create the secret rollover thread");
	}

#ifndef HAVE_ATOMIC
	knotd_mod_log(mod, LOG_WARNING, "the module might work slightly wrong on this platform");
	ctx->badcookie_slip = 1;
#endif

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, cookies_process);
}

void cookies_unload(knotd_mod_t *mod)
{
	cookies_ctx_t *ctx = knotd_mod_ctx(mod);
	memzero(&ctx->secret, sizeof(ctx->secret));
	(void)pthread_cancel(ctx->update_secret);
	(void)pthread_join(ctx->update_secret, NULL);
	free(ctx);
}

KNOTD_MOD_API(cookies, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              cookies_load, cookies_unload, cookies_conf, NULL);
