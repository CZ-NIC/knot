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

#include <assert.h>
#include <stddef.h>
#include <gnutls/crypto.h>

#include "libdnssec/error.h"
#include "libdnssec/random.h"

#include "libknot/errcode.h"
#include "utils/common/quic.h"

int quic_params_copy(quic_params_t *dst, const quic_params_t *src)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	dst->enable = src->enable;

	return KNOT_EOK;
}

void quic_params_clean(quic_params_t *params)
{
	if (params == NULL) {
		return;
	}

	params->enable = false;
}

#ifdef LIBNGTCP2

const gnutls_datum_t quic_alpn[] = {
	{
		.data = (unsigned char *)"doq",
		.size = 3
	},{
		.data = (unsigned char *)"doq-i12",
		.size = 7
	},{
		.data = (unsigned char *)"doq-i11",
		.size = 7
	},{
		.data = (unsigned char *)"doq-i03",
		.size = 7
	}
};

uint64_t quic_timestamp(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}

	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

int quic_generate_secret(uint8_t *buf, size_t buflen)
{
	assert(buf != NULL && buflen > 0 && buflen <= 32);
	uint8_t rand[16], hash[32];
	int ret = dnssec_random_buffer(rand, sizeof(rand));
	if (ret != DNSSEC_EOK) {
		return ret;
	}
	ret = gnutls_hash_fast(GNUTLS_DIG_SHA256, rand, sizeof(rand), hash);
	if (ret != 0) {
		return ret;
	}
	memcpy(buf, hash, buflen);
	return KNOT_EOK;
}


static int verify_certificate(gnutls_session_t session)
{
	quic_ctx_t *ctx = gnutls_session_get_ptr(session);
	return tls_certificate_verification(ctx->tls);
}

int quic_ctx_init(quic_ctx_t *ctx, tls_ctx_t *tls_ctx, const quic_params_t *params)
{
	if (ctx == NULL || tls_ctx == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	ctx->params = *params;
	ctx->tls = tls_ctx;
	ctx->state = OPENING;
	ctx->stream.id = -1;
	ctx->timestamp = quic_timestamp();
	if (quic_generate_secret(ctx->secret, sizeof(ctx->secret)) != KNOT_EOK) {
		tls_ctx_deinit(ctx->tls);
		return KNOT_ENOMEM;
	}

	gnutls_certificate_set_verify_function(tls_ctx->credentials,
	        verify_certificate);

	return KNOT_EOK;
}


#endif
