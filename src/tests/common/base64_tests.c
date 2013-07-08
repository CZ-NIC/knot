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
#include "tests/common/base64_tests.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "common/errcode.h"
#include "common/base64.h"

#define BUF_LEN 256

static int base64_tests_count(int argc, char *argv[]);
static int base64_tests_run(int argc, char *argv[]);

unit_api base64_tests_api = {
	"Base64 encoding",
	&base64_tests_count,
	&base64_tests_run
};

static int base64_tests_count(int argc, char *argv[])
{
	return 36;
}

static int base64_tests_run(int argc, char *argv[])
{
	int32_t  ret;
	uint8_t  in[BUF_LEN], ref[BUF_LEN], out[BUF_LEN], out2[BUF_LEN];
	uint32_t in_len, ref_len;

	// 1. test vector -> ENC -> DEC
	strcpy((char *)in, "");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "");
	ref_len = strlen((char *)ref);
	ret = base64_encode(in, in_len, out, BUF_LEN);
	cmp_ok(ret, "==", ref_len, "1. test vector - ENC output length");
	skip(ret < 0, 1);
	ok(memcmp(out, ref, ret) == 0, "1. test vector - ENC output content");
	endskip;
	ret = base64_decode(out, ret, out2, BUF_LEN);
	cmp_ok(ret, "==", in_len, "1. test vector - DEC output length");
	skip(ret < 0, 1);
	ok(memcmp(out2, in, ret) == 0, "1. test vector - DEC output content");
	endskip;

	// 2. test vector -> ENC -> DEC
	strcpy((char *)in, "f");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "Zg==");
	ref_len = strlen((char *)ref);
	ret = base64_encode(in, in_len, out, BUF_LEN);
	cmp_ok(ret, "==", ref_len, "2. test vector - ENC output length");
	skip(ret < 0, 1);
	ok(memcmp(out, ref, ret) == 0, "2. test vector - ENC output content");
	endskip;
	ret = base64_decode(out, ret, out2, BUF_LEN);
	cmp_ok(ret, "==", in_len, "2. test vector - DEC output length");
	skip(ret < 0, 1);
	ok(memcmp(out2, in, ret) == 0, "2. test vector - DEC output content");
	endskip;

	// 3. test vector -> ENC -> DEC
	strcpy((char *)in, "fo");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "Zm8=");
	ref_len = strlen((char *)ref);
	ret = base64_encode(in, in_len, out, BUF_LEN);
	cmp_ok(ret, "==", ref_len, "3. test vector - ENC output length");
	skip(ret < 0, 1);
	ok(memcmp(out, ref, ret) == 0, "3. test vector - ENC output content");
	endskip;
	ret = base64_decode(out, ret, out2, BUF_LEN);
	cmp_ok(ret, "==", in_len, "3. test vector - DEC output length");
	skip(ret < 0, 1);
	ok(memcmp(out2, in, ret) == 0, "3. test vector - DEC output content");
	endskip;

	// 4. test vector -> ENC -> DEC
	strcpy((char *)in, "foo");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "Zm9v");
	ref_len = strlen((char *)ref);
	ret = base64_encode(in, in_len, out, BUF_LEN);
	cmp_ok(ret, "==", ref_len, "4. test vector - ENC output length");
	skip(ret < 0, 1);
	ok(memcmp(out, ref, ret) == 0, "4. test vector - ENC output content");
	endskip;
	ret = base64_decode(out, ret, out2, BUF_LEN);
	cmp_ok(ret, "==", in_len, "4. test vector - DEC output length");
	skip(ret < 0, 1);
	ok(memcmp(out2, in, ret) == 0, "4. test vector - DEC output content");
	endskip;

	// 5. test vector -> ENC -> DEC
	strcpy((char *)in, "foob");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "Zm9vYg==");
	ref_len = strlen((char *)ref);
	ret = base64_encode(in, in_len, out, BUF_LEN);
	cmp_ok(ret, "==", ref_len, "5. test vector - ENC output length");
	skip(ret < 0, 1);
	ok(memcmp(out, ref, ret) == 0, "5. test vector - ENC output content");
	endskip;
	ret = base64_decode(out, ret, out2, BUF_LEN);
	cmp_ok(ret, "==", in_len, "5. test vector - DEC output length");
	skip(ret < 0, 1);
	ok(memcmp(out2, in, ret) == 0, "5. test vector - DEC output content");
	endskip;

	// 6. test vector -> ENC -> DEC
	strcpy((char *)in, "fooba");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "Zm9vYmE=");
	ref_len = strlen((char *)ref);
	ret = base64_encode(in, in_len, out, BUF_LEN);
	cmp_ok(ret, "==", ref_len, "6. test vector - ENC output length");
	skip(ret < 0, 1);
	ok(memcmp(out, ref, ret) == 0, "6. test vector - ENC output content");
	endskip;
	ret = base64_decode(out, ret, out2, BUF_LEN);
	cmp_ok(ret, "==", in_len, "6. test vector - DEC output length");
	skip(ret < 0, 1);
	ok(memcmp(out2, in, ret) == 0, "6. test vector - DEC output content");
	endskip;

	// 7. test vector -> ENC -> DEC
	strcpy((char *)in, "foobar");
	in_len = strlen((char *)in);
	strcpy((char *)ref, "Zm9vYmFy");
	ref_len = strlen((char *)ref);
	ret = base64_encode(in, in_len, out, BUF_LEN);
	cmp_ok(ret, "==", ref_len, "7. test vector - ENC output length");
	skip(ret < 0, 1);
	ok(memcmp(out, ref, ret) == 0, "7. test vector - ENC output content");
	endskip;
	ret = base64_decode(out, ret, out2, BUF_LEN);
	cmp_ok(ret, "==", in_len, "7. test vector - DEC output length");
	skip(ret < 0, 1);
	ok(memcmp(out2, in, ret) == 0, "7. test vector - DEC output content");
	endskip;

	// Bad paddings
        ret = base64_decode((uint8_t *)"A===", 4, out, BUF_LEN);
        cmp_ok(ret, "==", KNOT_BASE64_ECHAR, "Bad padding length 3");
        ret = base64_decode((uint8_t *)"====", 4, out, BUF_LEN);
        cmp_ok(ret, "==", KNOT_BASE64_ECHAR, "Bad padding length 4");

	// Bad data length
        ret = base64_decode((uint8_t *)"A", 1, out, BUF_LEN);
        cmp_ok(ret, "==", KNOT_BASE64_ESIZE, "Bad data length 1");
        ret = base64_decode((uint8_t *)"AA", 2, out, BUF_LEN);
        cmp_ok(ret, "==", KNOT_BASE64_ESIZE, "Bad data length 2");
        ret = base64_decode((uint8_t *)"AAA", 3, out, BUF_LEN);
        cmp_ok(ret, "==", KNOT_BASE64_ESIZE, "Bad data length 3");
        ret = base64_decode((uint8_t *)"AAAAA", 5, out, BUF_LEN);
        cmp_ok(ret, "==", KNOT_BASE64_ESIZE, "Bad data length 5");

	// Bad data character
        ret = base64_decode((uint8_t *)"AAA$", 4, out, BUF_LEN);
        cmp_ok(ret, "==", KNOT_BASE64_ECHAR, "Bad data character dollar");
        ret = base64_decode((uint8_t *)"AAA ", 4, out, BUF_LEN);
        cmp_ok(ret, "==", KNOT_BASE64_ECHAR, "Bad data character space");

	return 0;
}
