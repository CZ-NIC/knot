/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "common/errcode.h"
#include "common/base32hex.h"

#define BUF_LEN 256

int main(int argc, char *argv[])
{
	plan(56);

	int32_t  ret;
	uint8_t  in[BUF_LEN], ref[BUF_LEN], out[BUF_LEN], out2[BUF_LEN], *out3, *out4;
	uint32_t in_len, ref_len;

	// 0. test invalid input
	ret = base32hex_encode(NULL, 0, out, BUF_LEN);
	ok(ret == KNOT_EINVAL, "base32hex_encode: NULL input buffer");
	ret = base32hex_encode(in, BUF_LEN, NULL, 0);
	ok(ret == KNOT_EINVAL, "base32hex_encode: NULL output buffer");
	ret = base32hex_encode(in, ((INT32_MAX / 8) * 5) + 1, out, BUF_LEN);
	ok(ret == KNOT_ERANGE, "base32hex_encode: input buffer too large");
	ret = base32hex_encode(in, 160, out, 255);
	ok(ret == KNOT_ERANGE, "base32hex_encode: output buffer too small");
	ret = base32hex_encode_alloc(in, ((INT32_MAX / 8) * 5) + 1, &out3);
	ok(ret == KNOT_ERANGE, "base32hex_encode_alloc: input buffer too large: '%i'", ret);

	ret = base32hex_decode(NULL, 0, out, BUF_LEN);
	ok(ret == KNOT_EINVAL, "base32hex_decode: NULL input buffer");
	ret = base32hex_decode(in, BUF_LEN, NULL, 0);
	ok(ret == KNOT_EINVAL, "base32hex_decode: NULL output buffer");
	ret = base32hex_decode(in, INT32_MAX + 1, out, BUF_LEN);
	ok(ret == KNOT_ERANGE, "base32hex_decode: input buffer too large");
	ret = base32hex_decode(in, 256, out, 159);
	ok(ret == KNOT_ERANGE, "base32hex_decode: output buffer too small");
	ret = base32hex_decode_alloc(in, INT32_MAX + 1, &out3);
	ok(ret == KNOT_ERANGE, "base32hex_decode_alloc: input buffer too large: '%i'", ret);

	// 1. test vector -> ENC -> DEC
	strcpy((char *)in, "");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "");
	ref_len = strlen((char *)ref);
	ret = base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "1. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "1. test vector - ENC output content");
	}
	ret = base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "1. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "1. test vector - DEC output content");
	}

	// 2. test vector -> ENC -> DEC
	strcpy((char *)in, "f");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "CO======");
	ref_len = strlen((char *)ref);
	ret = base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "2. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "2. test vector - ENC output content");
	}
	ret = base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "2. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "2. test vector - DEC output content");
	}

	// 3. test vector -> ENC -> DEC
	strcpy((char *)in, "fo");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "CPNG====");
	ref_len = strlen((char *)ref);
	ret = base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "3. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "3. test vector - ENC output content");
	}
	ret = base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "3. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "3. test vector - DEC output content");
	}

	// 4. test vector -> ENC -> DEC
	strcpy((char *)in, "foo");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "CPNMU===");
	ref_len = strlen((char *)ref);
	ret = base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "4. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "4. test vector - ENC output content");
	}
	ret = base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "4. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "4. test vector - DEC output content");
	}

	// 5. test vector -> ENC -> DEC
	strcpy((char *)in, "foob");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "CPNMUOG=");
	ref_len = strlen((char *)ref);
	ret = base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "5. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "5. test vector - ENC output content");
	}
	ret = base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "5. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "5. test vector - DEC output content");
	}

	// 6. test vector -> ENC -> DEC
	strcpy((char *)in, "fooba");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "CPNMUOJ1");
	ref_len = strlen((char *)ref);
	ret = base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "6. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "6. test vector - ENC output content");
	}
	ret = base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "6. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "6. test vector - DEC output content");
	}

	// 7. test vector -> ENC -> DEC
	strcpy((char *)in, "foobar");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "CPNMUOJ1E8======");
	ref_len = strlen((char *)ref);
	ret = base32hex_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "7. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "7. test vector - ENC output content");
	}
	ret = base32hex_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "7. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "7. test vector - DEC output content");
	}

	// Bad paddings
	ret = base32hex_decode((uint8_t *)"AAAAAA==", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 2");
	ret = base32hex_decode((uint8_t *)"AAA=====", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 5");
	ret = base32hex_decode((uint8_t *)"A======", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 7");
	ret = base32hex_decode((uint8_t *)"=======", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 8");

	// Bad data length
	ret = base32hex_decode((uint8_t *)"A", 1, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 1");
	ret = base32hex_decode((uint8_t *)"AA", 2, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 2");
	ret = base32hex_decode((uint8_t *)"AAA", 3, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 3");
	ret = base32hex_decode((uint8_t *)"AAAA", 4, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 4");
	ret = base32hex_decode((uint8_t *)"AAAAA", 5, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 5");
	ret = base32hex_decode((uint8_t *)"AAAAAA", 6, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 6");
	ret = base32hex_decode((uint8_t *)"AAAAAAA", 7, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 7");
	ret = base32hex_decode((uint8_t *)"AAAAAAAAA", 9, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ESIZE, "Bad data length 9");

	// Bad data character
	ret = base32hex_decode((uint8_t *)"AAAAAAA$", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar");
	ret = base32hex_decode((uint8_t *)"AAAAAAA ", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character space");

	// Alloc function
	strcpy((char *)in, "fo");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "CPNG====");
	ref_len = strlen((char *)ref);

	ret = base32hex_encode_alloc(in, in_len, &out3);
	ok(ret == ref_len, "base32hex_encode_alloc: encode output length");
	if (ret < 0) {
		skip("base32hex_encode_alloc: encode error");
	} else {
		ok(memcmp(out3, ref, ret) == 0, "base32hex_encode_alloc: encode output content");
	}
	ret = base32hex_decode_alloc(out3, ret, &out4);
	ok(ret == in_len, "base32hex_decode_alloc: decode output length");
	if (ret < 0) {
		skip("base32hex_decode_alloc: decode error");
	} else {
		ok(memcmp(out4, in, ret) == 0, "base32hex_decode_alloc: decode output content");
	}

	return 0;
}
