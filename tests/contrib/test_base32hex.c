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
	ret = base32hex_encode(NULL, 0, out, BUF_LEN);
	ok(ret == KNOT_EINVAL, "base32hex_encode: NULL input buffer");
	ret = base32hex_encode(in, BUF_LEN, NULL, 0);
	ok(ret == KNOT_EINVAL, "base32hex_encode: NULL output buffer");
	ret = base32hex_encode(in, MAX_BIN_DATA_LEN + 1, out, BUF_LEN);
	ok(ret == KNOT_ERANGE, "base32hex_encode: input buffer too large");
	ret = base32hex_encode(in, BUF_LEN, out, BUF_LEN);
	ok(ret == KNOT_ERANGE, "base32hex_encode: output buffer too small");

	ret = base32hex_encode_alloc(NULL, 0, &out3);
	ok(ret == KNOT_EINVAL, "base32hex_encode_alloc: NULL input buffer");
	ret = base32hex_encode_alloc(in, MAX_BIN_DATA_LEN + 1, &out3);
	ok(ret == KNOT_ERANGE, "base32hex_encode_alloc: input buffer too large");
	ret = base32hex_encode_alloc(in, BUF_LEN, NULL);
	ok(ret == KNOT_EINVAL, "base32hex_encode_alloc: NULL output buffer");

	ret = base32hex_decode(NULL, 0, out, BUF_LEN);
	ok(ret == KNOT_EINVAL, "base32hex_decode: NULL input buffer");
	ret = base32hex_decode(in, BUF_LEN, NULL, 0);
	ok(ret == KNOT_EINVAL, "base32hex_decode: NULL output buffer");
	ret = base32hex_decode(in, UINT32_MAX, out, BUF_LEN);
	ok(ret == KNOT_ERANGE, "base32hex_decode: input buffer too large");
	ret = base32hex_decode(in, BUF_LEN, out, 0);
	ok(ret == KNOT_ERANGE, "base32hex_decode: output buffer too small");

	ret = base32hex_decode_alloc(NULL, 0, &out3);
	ok(ret == KNOT_EINVAL, "base32hex_decode_alloc: NULL input buffer");
	ret = base32hex_decode_alloc(in, UINT32_MAX, &out3);
	ok(ret == KNOT_ERANGE, "base32hex_decode_aloc: input buffer too large");
	ret = base32hex_decode_alloc(in, BUF_LEN, NULL);
	ok(ret == KNOT_EINVAL, "base32hex_decode_alloc: NULL output buffer");

	// 1. test vector -> ENC -> DEC
	strlcpy((char *)in, "", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "", BUF_LEN);
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
	strlcpy((char *)in, "f", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "CO======", BUF_LEN);
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
	strlcpy((char *)in, "fo", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "CPNG====", BUF_LEN);
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
	strlcpy((char *)in, "foo", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "CPNMU===", BUF_LEN);
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
	strlcpy((char *)in, "foob", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "CPNMUOG=", BUF_LEN);
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
	strlcpy((char *)in, "fooba", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "CPNMUOJ1", BUF_LEN);
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
	strlcpy((char *)in, "foobar", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "CPNMUOJ1E8======", BUF_LEN);
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
	ret = base32hex_decode((uint8_t *)"A=======", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 7");
	ret = base32hex_decode((uint8_t *)"========", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding length 8");
	ret = base32hex_decode((uint8_t *)"AAAAA=A=", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding character on position 2");
	ret = base32hex_decode((uint8_t *)"AA=A====", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding character on position 5");
	ret = base32hex_decode((uint8_t *)"=A======", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad padding character on position 7");
	ret = base32hex_decode((uint8_t *)"CO======CO======", 16, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Two octects with padding");

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
	ret = base32hex_decode((uint8_t *)"AAAAAA$A", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 7");
	ret = base32hex_decode((uint8_t *)"AAAAA$AA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 6");
	ret = base32hex_decode((uint8_t *)"AAAA$AAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 5");
	ret = base32hex_decode((uint8_t *)"AAA$AAAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 4");
	ret = base32hex_decode((uint8_t *)"AA$AAAAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 3");
	ret = base32hex_decode((uint8_t *)"A$AAAAAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 2");
	ret = base32hex_decode((uint8_t *)"$AAAAAAA", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE32HEX_ECHAR, "Bad data character dollar on position 1");

	return 0;
}
