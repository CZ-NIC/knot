/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "libknot/dnssec/shared/bignum.c"
#include "libknot/dnssec/binary.h"
#include "libknot/dnssec/error.h"
#include "libknot/dnssec/sign/der.c"

static int binary_eq(const dnssec_binary_t *a, const dnssec_binary_t *b)
{
	return a && b &&
	       a->size == b->size &&
	       memcmp(a->data, b->data, a->size) == 0;
}

#define DECODE_OK(der, r, s, message) \
	dnssec_binary_t __der = { .data = der, .size = sizeof(der) }; \
	dnssec_binary_t __r = { .data = r, .size = sizeof(r) }; \
	dnssec_binary_t __s = { .data = s, .size = sizeof(s) }; \
	dnssec_binary_t __out_s = { 0 }; \
	dnssec_binary_t __out_r = { 0 }; \
	int _result = dss_sig_value_decode(&__der, &__out_r, &__out_s); \
	ok(_result == KNOT_EOK && \
	   binary_eq(&__r, &__out_r) && \
	   binary_eq(&__s, &__out_s), \
	   "decode ok, " message)

#define DECODE_FAIL(der, message) \
	dnssec_binary_t __der = { .data = der, .size = sizeof(der) }; \
	dnssec_binary_t __out_r = { 0 }; \
	dnssec_binary_t __out_s = { 0 }; \
	int _result = dss_sig_value_decode(&__der, &__out_r, &__out_s); \
	ok(_result != KNOT_EOK, \
	   "decode fail, " message)

#define ENCODE_OK(r, s, der, message) \
	dnssec_binary_t __r = { .data = r, .size = sizeof(r) }; \
	dnssec_binary_t __s = { .data = s, .size = sizeof(s) }; \
	dnssec_binary_t __der = { .data = der, .size = sizeof(der) }; \
	dnssec_binary_t __out_der = { 0 }; \
	int _result = dss_sig_value_encode(&__r, &__s, &__out_der); \
	ok(_result == KNOT_EOK && \
	   binary_eq(&__der, &__out_der), \
	   "encode ok, " message); \
	dnssec_binary_free(&__out_der)

#define ENCODE_FAIL(r, s, message) \
	dnssec_binary_t __r = { .data = r, .size = sizeof(r) }; \
	dnssec_binary_t __s = { .data = s, .size = sizeof(s) }; \
	dnssec_binary_t __out_der = { 0 }; \
	int _result = dss_sig_value_encode(&__r, &__s, &__out_der); \
	ok(_result != KNOT_EOK, \
	   "encode fail, " message); \
	dnssec_binary_free(&__out_der)

#define ONE_64_TIMES \
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01, \
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01, \
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01, \
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01, \
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01, \
	0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01, \
	0x01,0x01,0x01,0x01

#define ONE_128_TIMES \
	ONE_64_TIMES, ONE_64_TIMES

int main(void)
{
	plan_lazy();

	{
	uint8_t der[] = { 0x30,0x08, 0x02,0x02,0x1a,0x2b, 0x02,0x02,0x3c,0x4d };
	uint8_t r[]   = { 0x1a, 0x2b };
	uint8_t s[]   = { 0x3c, 0x4d };
	DECODE_OK(der, r, s, "simple without MSB");
	}

	{
	uint8_t der[] = { 0x30,0x08, 0x02,0x02,0xff,0xff, 0x02,0x02,0x80,0x00 };
	uint8_t r[]   = { 0xff, 0xff };
	uint8_t s[]   = { 0x80, 0x00 };
	DECODE_OK(der, r, s, "simple with MSB");
	}

	{
	uint8_t der[] = { 0x30,0x09, 0x02,0x04,0x00,0x00,0x00,0xfa, 0x02,0x01,0x07 };
	uint8_t r[]   = { 0xfa };
	uint8_t s[]   = { 0x07 };
	DECODE_OK(der, r, s, "leading zeros");
	}

	{
	uint8_t der[] = { 0x30,0x07, 0x02,0x01,0x00, 0x02,0x02,0x00,0x00 };
	uint8_t r[]   = { 0x00 };
	uint8_t s[]   = { 0x00 };
	DECODE_OK(der, r, s, "zero values" );
	}

	{
	uint8_t der[] = { };
	DECODE_FAIL(der, "empty input");
	}

	{
	uint8_t der[] = { 0x30,0x04, 0x02,0x01,0x01 };
	DECODE_FAIL(der, "partial sequence");
	}

	{
	uint8_t der[] = { 0x30,0x06, 0x02,0x01,0x01, 0x02,0x02,0x01 };
	DECODE_FAIL(der, "partial integer");
	}

	{
	uint8_t der[] = { 0x30,0x00 };
	DECODE_FAIL(der, "zero-length sequence");
	}

	{
	uint8_t der[] = { 0x30,0x05, 0x02,0x01,0xff, 0x02,0x00 };
	DECODE_FAIL(der, "zero-length integer");
	}

	{
	uint8_t der[] = { 0x30,0x84, 0x02,0x40,ONE_64_TIMES, 0x02,0x40,ONE_64_TIMES };
	DECODE_FAIL(der, "unsupported size");
	}

	{
	uint8_t r[]   = { 0x01, };
	uint8_t s[]   = { 0x02,0x03 };
	uint8_t der[] = { 0x30,0x07, 0x02,0x01,0x01, 0x02,0x02,0x02,0x03 };
	ENCODE_OK(r, s, der, "simple");
	}

	{
	uint8_t r[]   = { 0x00,0x01, };
	uint8_t s[]   = { 0x00,0x00,0x02,0x03 };
	uint8_t der[] = { 0x30,0x07, 0x02,0x01,0x01, 0x02,0x02,0x02,0x03 };
	ENCODE_OK(r, s, der, "unnecessary leading zeros");
	}

	{
	uint8_t r[]   = { 0x00,0x8f };
	uint8_t s[]   = { 0x00,0x00,0xff };
	uint8_t der[] = { 0x30,0x08, 0x02,0x02,0x00,0x8f, 0x02,0x02,0x00,0xff };
	ENCODE_OK(r, s, der, "required zero not removed");
	}

	{
	uint8_t r[]   = { 0x8c };
	uint8_t s[]   = { 0xff,0xee };
	uint8_t der[] = { 0x30,0x09, 0x02,0x02,0x00,0x8c, 0x02,0x03,0x00,0xff,0xee };
	ENCODE_OK(r, s, der, "implicitly added zero");
	}

	{
	uint8_t r[]   = { 0x00 };
	uint8_t s[]   = { 0x00,0x00 };
	uint8_t der[] = { 0x30,0x06, 0x02,0x01,0x00, 0x02,0x01,0x00 };
	ENCODE_OK(r, s, der, "zero");
	}

	{
	uint8_t r[]   = { 0x01 };
	uint8_t s[]   = { };
	uint8_t der[] = { 0x30,0x06, 0x02,0x01,0x01, 0x02,0x01,0x00 };
	ENCODE_OK(r, s, der, "zero-length input");
	}

	{
	uint8_t r[] = { ONE_128_TIMES };
	uint8_t s[] = { 0x01 };
	ENCODE_FAIL(r, s, "input too long");
	}

	{
	uint8_t r[]   = { ONE_64_TIMES };
	uint8_t s[]   = { ONE_64_TIMES };
	ENCODE_FAIL(r, s, "result too long");
	}

	return 0;
}
