/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "libknot/libknot.h"
#include "contrib/base64url.h"
#include "contrib/openbsd/strlcpy.h"

#define BUF_LEN			256
#define MAX_BIN_DATA_LEN	((INT32_MAX / 4) * 3)

int main(int argc, char *argv[])
{
	plan(50);

	int32_t  ret;
	uint8_t  in[BUF_LEN], ref[BUF_LEN], out[BUF_LEN], out2[BUF_LEN], *out3;
	uint32_t in_len, ref_len;

	// 0. test invalid input
	ret = knot_base64url_encode(NULL, 0, out, BUF_LEN);
	is_int(KNOT_EINVAL, ret, "knot_base64ulr_encode: NULL input buffer");
	ret = knot_base64url_encode(in, BUF_LEN, NULL, 0);
	is_int(KNOT_EINVAL, ret, "knot_base64ulr_encode: NULL output buffer");
	ret = knot_base64url_encode(in, MAX_BIN_DATA_LEN + 1, out, BUF_LEN);
	is_int(KNOT_ERANGE, ret, "knot_base64ulr_encode: input buffer too large");
	ret = knot_base64url_encode(in, BUF_LEN, out, BUF_LEN);
	is_int(KNOT_ERANGE, ret, "knot_base64ulr_encode: output buffer too small");

	ret = knot_base64url_encode_alloc(NULL, 0, &out3);
	is_int(KNOT_EINVAL, ret, "knot_base64ulr_encode_alloc: NULL input buffer");
	ret = knot_base64url_encode_alloc(in, MAX_BIN_DATA_LEN + 1, &out3);
	is_int(KNOT_ERANGE, ret, "knot_base64ulr_encode_alloc: input buffer too large");
	ret = knot_base64url_encode_alloc(in, BUF_LEN, NULL);
	is_int(KNOT_EINVAL, ret, "knot_base64ulr_encode_alloc: NULL output buffer");

	ret = knot_base64url_decode(NULL, 0, out, BUF_LEN);
	is_int(KNOT_EINVAL, ret, "knot_base64ulr_decode: NULL input buffer");
	ret = knot_base64url_decode(in, BUF_LEN, NULL, 0);
	is_int(KNOT_EINVAL, ret, "knot_base64ulr_decode: NULL output buffer");
	ret = knot_base64url_decode(in, BUF_LEN, out, 0);
	is_int(KNOT_ERANGE, ret, "knot_base64ulr_decode: output buffer too small");

	ret = knot_base64url_decode_alloc(NULL, 0, &out3);
	is_int(KNOT_EINVAL, ret, "knot_base64ulr_decode_alloc: NULL input buffer");
	ret = knot_base64url_decode_alloc(in, BUF_LEN, NULL);
	is_int(KNOT_EINVAL, ret, "knot_base64ulr_decode_alloc: NULL output buffer");

	// 1. test vector -> ENC -> DEC
	strlcpy((char *)in, "", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base64url_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "1. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "1. test vector - ENC output content");
	}
	ret = knot_base64url_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "1. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "1. test vector - DEC output content");
	}

	// 2. test vector -> ENC -> DEC
	strlcpy((char *)in, "f", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "Zg", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base64url_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "2. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "2. test vector - ENC output content");
	}
	ret = knot_base64url_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "2. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "2. test vector - DEC output content");
	}

	// 3. test vector -> ENC -> DEC
	strlcpy((char *)in, "fo", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "Zm8", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base64url_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "3. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "3. test vector - ENC output content");
	}
	ret = knot_base64url_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "3. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "3. test vector - DEC output content");
	}

	// 4. test vector -> ENC -> DEC
	strlcpy((char *)in, "foo", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "Zm9v", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base64url_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "4. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "4. test vector - ENC output content");
	}
	ret = knot_base64url_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "4. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "4. test vector - DEC output content");
	}

	// 5. test vector -> ENC -> DEC
	strlcpy((char *)in, "foob", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "Zm9vYg", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base64url_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "5. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "5. test vector - ENC output content");
	}
	ret = knot_base64url_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "5. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "5. test vector - DEC output content");
	}

	// 6. test vector -> ENC -> DEC
	strlcpy((char *)in, "fooba", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "Zm9vYmE", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base64url_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "6. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "6. test vector - ENC output content");
	}
	ret = knot_base64url_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "6. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "6. test vector - DEC output content");
	}

	// 7. test vector -> ENC -> DEC
	strlcpy((char *)in, "foobar", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "Zm9vYmFy", BUF_LEN);
	ref_len = strlen((char *)ref);
	ret = knot_base64url_encode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "7. test vector - ENC output length");
	if (ret < 0) {
		skip("Encode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "7. test vector - ENC output content");
	}
	ret = knot_base64url_decode(out, ret, out2, BUF_LEN);
	ok(ret == in_len, "7. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out2, in, ret) == 0, "7. test vector - DEC output content");
	}

	// 8. ENC (percent-encoded padding) -> DEC
	strlcpy((char *)in, "Zm9vYmE%3D", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "fooba", BUF_LEN);
	ref_len = strlen((char *)ref);
	
	ret = knot_base64url_decode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "8. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "8. test vector - DEC output content");
	}

	strlcpy((char *)in, "Zm9vYmFyCg%3d%3d", BUF_LEN);
	in_len = strlen((char *)in);
	strlcpy((char *)ref, "foobar\n", BUF_LEN);
	ref_len = strlen((char *)ref);

	ret = knot_base64url_decode(in, in_len, out, BUF_LEN);
	ok(ret == ref_len, "9. test vector - DEC output length");
	if (ret < 0) {
		skip("Decode err");
	} else {
		ok(memcmp(out, ref, ret) == 0, "9. test vector - DEC output content");
	}

	// Bad paddings
	ret = knot_base64url_decode((uint8_t *)"A", 1, out, BUF_LEN);
	ok(ret == KNOT_BASE64_ECHAR, "Bad padding length 3");
	ret = knot_base64url_decode((uint8_t *)"%3D", 3, out, BUF_LEN);
	ok(ret == KNOT_BASE64_ECHAR, "Bad padding length 4");

	// Paddings not at the end
	ret = knot_base64url_decode((uint8_t *)"AB%3DCDEFG", 10, out, BUF_LEN);
	ok(ret == KNOT_BASE64_ECHAR, "Bad padding 1");
	ret = knot_base64url_decode((uint8_t *)"AB\0CDEFG", 8, out, BUF_LEN);
	ok(ret == KNOT_BASE64_ECHAR, "Bad padding 2");

	// Bad data character
	ret = knot_base64url_decode((uint8_t *)"AAA$", 4, out, BUF_LEN);
	ok(ret == KNOT_BASE64_ECHAR, "Bad data character dollar");
	ret = knot_base64url_decode((uint8_t *)"AAA ", 4, out, BUF_LEN);
	ok(ret == KNOT_BASE64_ECHAR, "Bad data character space");

	return 0;
}
