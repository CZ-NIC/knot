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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <dnssec/error.h>
#include <dnssec/kasp.h>
#include <dnssec/keystore.h>

#include "libknot/libknot.h"
#include "knot/dnssec/context.h"

static int get_keystore(dnssec_kasp_t *kasp, const char *name,
                        dnssec_keystore_t **keystore)
{
	dnssec_kasp_keystore_t *info = NULL;
	int r = dnssec_kasp_keystore_load(kasp, name, &info);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_kasp_keystore_open(kasp, info->backend, info->config, keystore);

	dnssec_kasp_keystore_free(info);

	return r;
}

/*!
 * \brief Initialize DNSSEC parameters of the DNSSEC context.
 *
 * No cleanup is performed on failure.
 */
static int ctx_init_dnssec(kdnssec_ctx_t *ctx, const char *kasp_path,
                           const char *zone_name)
{
	assert(ctx);
	assert(kasp_path);
	assert(zone_name);

	dnssec_kasp_init_dir(&ctx->kasp);
	int r = dnssec_kasp_open(ctx->kasp, kasp_path);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_kasp_zone_load(ctx->kasp, zone_name, &ctx->zone);
	if (r != DNSSEC_EOK) {
		return r;
	}

	const char *policy_name = dnssec_kasp_zone_get_policy(ctx->zone);
	r = dnssec_kasp_policy_load(ctx->kasp, policy_name, &ctx->policy);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return get_keystore(ctx->kasp, ctx->policy->keystore, &ctx->keystore);
}

void kdnssec_ctx_deinit(kdnssec_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	dnssec_keystore_deinit(ctx->keystore);
	dnssec_kasp_policy_free(ctx->policy);
	dnssec_kasp_zone_free(ctx->zone);
	dnssec_kasp_deinit(ctx->kasp);

	memset(ctx, 0, sizeof(*ctx));
}

int kdnssec_ctx_init(kdnssec_ctx_t *ctx_ptr, const char *kasp, const char *zone)
{
	if (ctx_ptr == NULL || kasp == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	kdnssec_ctx_t ctx = { 0 };

	int r = ctx_init_dnssec(&ctx, kasp, zone);
	if (r != KNOT_EOK) {
		kdnssec_ctx_deinit(&ctx);
		return r;
	}

	ctx.now = time(NULL);

	*ctx_ptr = ctx;
	return KNOT_EOK;
}
