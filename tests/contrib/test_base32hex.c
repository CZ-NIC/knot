/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/libknot.h"
#include "contrib/base32hex.h"
#include "contrib/openbsd/strlcpy.h"

#define BUF_LEN			256
#define MAX_BIN_DATA_LEN	((INT32_MAX / 8) * 5)

int main(int argc, char *argv[])
{
	plan(67);

	int32_t  ret;
	uint8_t  in[BUF_LEN], ref[BUF_LEN], out[BUF_LEN], out2[BUF_LEN], *out3;
	uint32_t in_len, ref_len;

	// 0. test invalid input
	ret = knot_base32hex_encode(NULL, 0, out, BUF_LEN);
	is_int(KNOT_EINVAL, ret, "knot_base32hex_encode: NULL input buffer");
	ret = knot_base32hex_encode(in, BUF_LEN, NULL, 0);
	is_int(KNOT_EINVAL, ret, "knot_base32hex_encode: NULL output buffer");
	ret = knot_base32hex_encode(in, MAX_BIN_DATA_LEN + 1, out, BUF_LEN);
	is_int(KNOT_ERANGE, ret, "knot_base32hex_encode: input buffer too large");
	ret = knot_base32hex_encode(in, BUF_LEN, out, BUF_LEN);
	is_int(KNOT_ESPACE, ret, "knot_base32hex_encode: output buffer too small");

	ret = knot_base32hex_encode_alloc(NULL, 0, &out3);
	is_int(KNOT_EINVAL, ret, "knot_base32hex_encode_alloc: NULL input buffer");
	ret = knot_base32hex_encode_alloc(in, MAX_BIN_DATA_LEN + 1, &out3);
	is_int(KNOT_ERANGE, ret, "knot_base32hex_encode_alloc: input buffer too large");
	ret = knot_base32hex_encode_alloc(in, BUF_LEN, NULL);
	is_int(KNOT_EINVAL, ret, "knot_base32hex_encode_alloc: NULL output buffer");

	ret = knot_base32hex_decode(NULL, 0, out, BUF_LEN);
	is_int(KNOT_EINVAL, ret, "knot_base32hex_decode: NULL input buffer");
	ret = knot_base32hex_decode(in, BUF_LEN, NULL, 0);
	is_int(KNOT_EINVAL, ret, "knot_base32hex_decode: NULL output buffer");
	ret = knot_base32hex_decode(in, UINT32_MAX, out, BUF_LEN);
	is_int(KNOT_ERANGE, ret, "knot_base32hex_decode: input buffer too large");
	ret = knot_base32hex_decode(in, BUF_LEN, out, 0);
	is_int(KNOT_ESPACE, ret, "knot_base32hex_decode: output buffer too small");

	ret = knot_base32hex_decode_alloc(NULL, 0, &out3);
	is_int(KNOT_EINVAL, ret, "knot_base32hex_decode_alloc: NULL input buffer");
	ret = knot_base32hex_decode_alloc(in, UINT32_MAX, &out3);
	is_int(KNOT_ERANGE, ret, "knot_base32hex_decode_aloc: input buffer too large");
	ret = knot_base32hex_decode_alloc(in, BUF_LEN, NULL);
	is_int(KNOT_EINVAL, ret, "knot_base32hex_decode_alloc: NULL output buffer");

	// 1. test vector -> ENC -> DEC
	strlcpy((char *)in, "", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "1. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "1. test vector - ENC output content");
	}
	ret = knot_base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "1. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "1. test vector - DEC output content");
	}

	// 2. test vector -> ENC -> DEC
	strlcpy((char *)in, "f", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "co======", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "2. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "2. test vector - ENC output content");
	}
	ret = knot_base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "2. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "2. test vector - DEC output content");
	}

	// 3. test vector -> ENC -> DEC
	strlcpy((char *)in, "fo", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "cpng====", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "3. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "3. test vector - ENC output content");
	}
	ret = knot_base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "3. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "3. test vector - DEC output content");
	}

	// 4. test vector -> ENC -> DEC
	strlcpy((char *)in, "foo", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "cpnmu===", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "4. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "4. test vector - ENC output content");
	}
	ret = knot_base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "4. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "4. test vector - DEC output content");
	}

	// 5. test vector -> ENC -> DEC
	strlcpy((char *)in, "foob", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "cpnmuog=", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "5. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "5. test vector - ENC output content");
	}
	ret = knot_base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "5. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "5. test vector - DEC output content");
	}

	// 6. test vector -> ENC -> DEC
	strlcpy((char *)in, "fooba", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "cpnmuoj1", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "6. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "6. test vector - ENC output content");
	}
	ret = knot_base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "6. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "6. test vector - DEC output content");
	}

	// 7. test vector -> ENC -> DEC
	strlcpy((char *)in, "foobar", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "cpnmuoj1e8======", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "7. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "7. test vector - ENC output content");
	}
	ret = knot_base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "7. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "7. test vector - DEC output content");
	}

	// Bad paddings
	ret = knot_base32hex_decode((uint8_t *)"AAAAAA==", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 2");
	ret = knot_base32hex_decode((uint8_t *)"AAA=====", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 5");
	ret = knot_base32hex_decode((uint8_t *)"A=======", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 7");
	ret = knot_base32hex_decode((uint8_t *)"========", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 8");
	ret = knot_base32hex_decode((uint8_t *)"AAAAA=A=", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding character on position 2");
	ret = knot_base32hex_decode((uint8_t *)"AA=A====", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding character on position 5");
	ret = knot_base32hex_decode((uint8_t *)"=A======", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding character on position 7");
	ret = knot_base32hex_decode((uint8_t *)"CO======CO======", 16, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Two octects with padding");

	// Bad data length
	ret = knot_base32hex_decode((uint8_t *)"A", 1, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 1");
	ret = knot_base32hex_decode((uint8_t *)"AA", 2, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 2");
	ret = knot_base32hex_decode((uint8_t *)"AAA", 3, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 3");
	ret = knot_base32hex_decode((uint8_t *)"AAAA", 4, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 4");
	ret = knot_base32hex_decode((uint8_t *)"AAAAA", 5, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 5");
	ret = knot_base32hex_decode((uint8_t *)"AAAAAA", 6, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 6");
	ret = knot_base32hex_decode((uint8_t *)"AAAAAAA", 7, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 7");
	ret = knot_base32hex_decode((uint8_t *)"AAAAAAAAA", 9, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 9");

	// Bad data character
	ret = knot_base32hex_decode((uint8_t *)"AAAAAAA$", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar");
	ret = knot_base32hex_decode((uint8_t *)"AAAAAAA ", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character space");
	ret = knot_base32hex_decode((uint8_t *)"AAAAAA$A", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 7");
	ret = knot_base32hex_decode((uint8_t *)"AAAAA$AA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 6");
	ret = knot_base32hex_decode((uint8_t *)"AAAA$AAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 5");
	ret = knot_base32hex_decode((uint8_t *)"AAA$AAAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 4");
	ret = knot_base32hex_decode((uint8_t *)"AA$AAAAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 3");
	ret = knot_base32hex_decode((uint8_t *)"A$AAAAAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 2");
	ret = knot_base32hex_decode((uint8_t *)"$AAAAAAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 1");

	return 0;
}
