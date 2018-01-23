/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <string.h>
#include <tap/basic.h>

#include "libknot/consts.h"
#include "libknot/dname.h"

/* Test dname_parse_from_wire */
static int test_fw(size_t l, const char *w) {
	const uint8_t *np = (const uint8_t *)w + l;
	return knot_dname_wire_check((const uint8_t *)w, np, NULL) > 0;
}

/* Test dname to/from string operations */
static void test_str(const char *in_str, const char *in_bin, size_t bin_len) {
	uint8_t      d1[KNOT_DNAME_MAXLEN] = "";
	char         s1[4 * KNOT_DNAME_MAXLEN] = "";
	knot_dname_t *d2 = NULL, *aux_d = NULL;
	char         *s2 = NULL, *aux_s = NULL;
	int          ret = 0;

	/* dname_from_str */
	aux_d = knot_dname_from_str(d1, in_str, sizeof(d1));
	ok(aux_d != NULL, "dname_from_str: %s", in_str);
	if (aux_d == NULL) {
		skip_block(10, "dname_from_str: %s", in_str);
		return;
	}

	/* dname_wire_check */
	ret = knot_dname_wire_check(d1, d1 + sizeof(d1), NULL);
	ok(ret == bin_len, "dname_wire_check: %s", in_str);

	/* dname compare */
	ok(memcmp(d1, in_bin, bin_len) == 0, "dname compare: %s", in_str);

	/* dname_to_str */
	aux_s = knot_dname_to_str(s1, d1, sizeof(s1));
	ok(aux_s != NULL, "dname_to_str: %s", in_str);
	if (aux_s == NULL) {
		skip_block(7, "dname_to_str: %s", in_str);
		return;
	}

	/* dname_from_str_alloc */
	d2 = knot_dname_from_str_alloc(s1);
	ok(d2 != NULL, "dname_from_str_alloc: %s", s1);
	if (d2 == NULL) {
		skip_block(6, "dname_from_str_alloc: %s", s1);
		return;
	}

	/* dname_wire_check */
	ret = knot_dname_wire_check(d2, d2 + bin_len, NULL);
	ok(ret == bin_len, "dname_wire_check: %s", s1);

	/* dname compare */
	ok(d2 && memcmp(d2, in_bin, bin_len) == 0, "dname compare: %s", s1);

	/* dname_to_str_alloc */
	s2 = knot_dname_to_str_alloc(d2);
	knot_dname_free(&d2, NULL);
	ok(s2 != NULL, "dname_to_str_alloc: %s", s1);
	if (s2 == NULL) {
		skip_block(3, "dname_to_str_alloc: %s", s1);
		return;
	}

	/* As the string representation is ambiguous, the following steps
	 * are just for comparison in wire form.
	 */
	d2 = knot_dname_from_str_alloc(s2);
	ok(d2 != NULL, "dname_from_str_alloc: %s", s2);
	if (aux_d == NULL) {
		skip_block(2, "dname_from_str_alloc: %s", s2);
		free(s2);
		return;
	}

	/* dname_wire_check */
	ret = knot_dname_wire_check(d2, d2 + bin_len, NULL);
	ok(ret == bin_len, "dname_wire_check: %s", s2);

	/* dname compare */
	ok(d2 && memcmp(d2, in_bin, bin_len) == 0, "dname compare: %s", s2);

	knot_dname_free(&d2, NULL);
	free(s2);
}

static void test_dname_lf(void)
{
	knot_dname_storage_t storage;

	/* Maximal DNAME length */
	const knot_dname_t *in = (uint8_t *)
		"\x3f""iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
		"\x3f""hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
		"\x3f""ggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
		"\x1f""fffffffffffffffffffffffffffffff"
		"\x0f""eeeeeeeeeeeeeee"
		"\x07""ddddddd"
		"\x03""ccc"
		"\x01""b"
		"\x00";
	const uint8_t *ref = (uint8_t *)
		"\xFE"
		"b""\x00"
		"ccc""\00"
		"ddddddd""\x00"
		"eeeeeeeeeeeeeee""\x00"
		"fffffffffffffffffffffffffffffff""\x00"
		"ggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg""\x00"
		"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh""\x00"
		"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii""\x00";
	uint8_t *out = knot_dname_lf(in, &storage);
	ok(out != NULL, "knot_dname_lf: max-length DNAME success on return");
	ok(memcmp(ref, out, KNOT_DNAME_MAXLEN) == 0, "knot_dname_lf: max-length DNAME converted");

	/* Zero label DNAME*/
	in = (uint8_t *) "\x00";
	out = knot_dname_lf(in, &storage);
	ok(out != NULL, "knot_dname_lf: zero-label DNAME success on return");
	ok(out[0] == '\x00', "knot_dname_lf: zero-label DNAME converted");
}

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_dname_t *d = NULL, *d2 = NULL;
	const char *w = NULL, *t = NULL;
	unsigned len = 0;
	size_t pos = 0;
	char *s = NULL;

	/* DNAME WIRE CHECKS */

	/* NULL wire */
	ok(!test_fw(0, NULL), "parsing NULL dname");

	/* empty label */
	ok(test_fw(1, ""), "parsing empty dname");

	/* incomplete dname */
	ok(!test_fw(5, "\x08" "dddd"), "parsing incomplete wire");

	/* non-fqdn */
	ok(!test_fw(3, "\x02" "ab"), "parsing non-fqdn name");

	/* label length == 63 */
	w = "\x3f" "123456789012345678901234567890123456789012345678901234567890123";
	ok(test_fw(1 + 63 + 1, w), "parsing label length == 63");

	/* label length > 63 */
	w = "\x40" "1234567890123456789012345678901234567890123456789012345678901234";
	ok(!test_fw(1 + 64 + 1, w), "parsing label length > 63");

	/* label count == 127 (also maximal dname length) */
	w = "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64";
	ok(test_fw(127 * 2 + 1, w), "parsing label count == 127");

	/* label count > 127 */
	w = "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64";
	ok(!test_fw(128 * 2 + 1, w), "parsing label count > 127");

	/* dname length > 255 */
	w = "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x02\x64\x64";
	ok(!test_fw(126 * 2 + 3 + 1, w), "parsing dname len > 255");

	/* DNAME STRING CHECKS */

	/* root dname */
	test_str(".", "\x00", 1);

	/* 1-char dname */
	test_str("a.", "\x01""a", 2 + 1);

	/* 1-char dname - non-fqdn */
	test_str("a", "\x01""a", 2 + 1);

	/* wildcard and asterisks */
	test_str("*.*a.a*a.**.",
	         "\x01" "*" "\x02" "*a" "\x03" "a*a" "\x02" "**",
	         2 + 3 + 4 + 3 + 1);

	/* special label */
	test_str("\\000\\0320\\ \\\\\\\"\\.\\@\\*.",
	         "\x09" "\x00\x20\x30\x20\x5c\x22.@*",
	         10 + 1);

	/* unescaped special characters */
	test_str("_a.b-c./d.",
	         "\x02" "_a" "\x03" "b-c" "\x02" "/d",
	         3 + 4 + 3 + 1);

	/* all possible characters */
	test_str("\\000\\001\\002\\003\\004\\005\\006\\007\\008\\009\\010\\011\\012\\013\\014\\015\\016\\017\\018\\019",
	         "\x14" "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13",
	         22);
	test_str("\\020\\021\\022\\023\\024\\025\\026\\027\\028\\029\\030\\031\\032\\033\\034\\035\\036\\037\\038\\039",
	         "\x14" "\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27",
	         22);
	test_str("\\040\\041\\042\\043\\044\\045\\046\\047\\048\\049\\050\\051\\052\\053\\054\\055\\056\\057\\058\\059",
	         "\x14" "\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b",
	         22);
	test_str("\\060\\061\\062\\063\\064\\065\\066\\067\\068\\069\\070\\071\\072\\073\\074\\075\\076\\077\\078\\079",
	         "\x14" "\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
	         22);
	test_str("\\080\\081\\082\\083\\084\\085\\086\\087\\088\\089\\090\\091\\092\\093\\094\\095\\096\\097\\098\\099",
	         "\x14" "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63",
	         22);
	test_str("\\100\\101\\102\\103\\104\\105\\106\\107\\108\\109\\110\\111\\112\\113\\114\\115\\116\\117\\118\\119",
	         "\x14" "\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77",
	         22);
	test_str("\\120\\121\\122\\123\\124\\125\\126\\127\\128\\129\\130\\131\\132\\133\\134\\135\\136\\137\\138\\139",
	         "\x14" "\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b",
	         22);
	test_str("\\140\\141\\142\\143\\144\\145\\146\\147\\148\\149\\150\\151\\152\\153\\154\\155\\156\\157\\158\\159",
	         "\x14" "\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f",
	         22);
	test_str("\\160\\161\\162\\163\\164\\165\\166\\167\\168\\169\\170\\171\\172\\173\\174\\175\\176\\177\\178\\179",
	         "\x14" "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3",
	         22);
	test_str("\\180\\181\\182\\183\\184\\185\\186\\187\\188\\189\\190\\191\\192\\193\\194\\195\\196\\197\\198\\199",
	         "\x14" "\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7",
	         22);
	test_str("\\200\\201\\202\\203\\204\\205\\206\\207\\208\\209\\210\\211\\212\\213\\214\\215\\216\\217\\218\\219",
	         "\x14" "\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb",
	         22);
	test_str("\\220\\221\\222\\223\\224\\225\\226\\227\\228\\229\\230\\231\\232\\233\\234\\235\\236\\237\\238\\239",
	         "\x14" "\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef",
	         22);
	test_str("\\240\\241\\242\\243\\244\\245\\246\\247\\248\\249\\250\\251\\252\\253\\254\\255",
	         "\x10" "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
	         18);

	/* maximal dname label length */
	test_str("12345678901234567890123456789012345678901234567890123456789012\\063",
		 "\x3f" "12345678901234567890123456789012345678901234567890123456789012?",
		 65);

	/* maximal dname length */
	test_str("1234567890123456789012345678901234567890123456789."
	         "1234567890123456789012345678901234567890123456789."
	         "1234567890123456789012345678901234567890123456789."
	         "1234567890123456789012345678901234567890123456789."
	         "\\#234567890123456789012345678901234567890123456789012\\063",
	         "\x31" "1234567890123456789012345678901234567890123456789"
	         "\x31" "1234567890123456789012345678901234567890123456789"
	         "\x31" "1234567890123456789012345678901234567890123456789"
	         "\x31" "1234567890123456789012345678901234567890123456789"
	         "\x35" "#234567890123456789012345678901234567890123456789012?",
	         255);

	/* NULL output, positive maxlen */
	w = "\x02" "aa";
	s = knot_dname_to_str(NULL, (const uint8_t *)w, 1);
	ok(s != NULL, "dname_to_str: null dname");
	if (s != NULL) {
		ok(memcmp(s, "aa.", 4) == 0, "dname_to_str: null dname compare");
		free(s);
	} else {
		skip("dname_to_str: null dname");
	}

	/* non-NULL output, zero maxlen */
	char s_small[2];
	s = knot_dname_to_str(s_small, (const uint8_t *)w, 0);
	ok(s == NULL, "dname_to_str: non-NULL output, zero maxlen");

	/* small buffer */
	s = knot_dname_to_str(s_small, (const uint8_t *)w, 1);
	ok(s == NULL, "dname_to_str: small buffer");

	/* NULL dname */
	s = knot_dname_to_str_alloc(NULL);
	ok(s == NULL, "dname_to_str: null dname");

	/* empty dname is considered as a root dname */
	w = "";
	s = knot_dname_to_str_alloc((const uint8_t *)w);
	ok(s != NULL, "dname_to_str: empty dname");
	if (s != NULL) {
		ok(memcmp(s, ".", 1) == 0, "dname_to_str: empty dname is root dname");
		free(s);
	} else {
		skip("dname_to_str: empty dname");
	}

	/* incomplete dname */
	/* ASAN: global-buffer-overflow
	w = "\x08" "dddd";
	s = knot_dname_to_str_alloc((const uint8_t *)w);
	ok(s != NULL, "dname_to_str: incomplete dname");
	free(s);
	*/

	/* non-fqdn */
	w = "\x02" "ab";
	s = knot_dname_to_str_alloc((const uint8_t *)w);
	ok(s != NULL, "dname_to_str: non-fqdn");
	free(s);

	/* label length > 63 */
	w = "\x40" "1234567890123456789012345678901234567890123456789012345678901234";
	s = knot_dname_to_str_alloc((const uint8_t *)w);
	ok(s != NULL, "dname_to_str: label length > 63");
	free(s);

	/* label count > 127 */
	w = "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64";
	s = knot_dname_to_str_alloc((const uint8_t *)w);
	ok(s != NULL, "dname_to_str: label count > 127");
	free(s);

	/* dname length > 255 */
	w = "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64"
	    "\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x01\x64\x02\x64\x64";
	s = knot_dname_to_str_alloc((const uint8_t *)w);
	ok(s != NULL, "dname_to_str: dname length > 255");
	free(s);

	/* NULL output, positive maxlen */
	s = "aa.";
	d = knot_dname_from_str(NULL, s, 1);
	ok(s != NULL, "dname_from_str: null name");
	if (s != NULL) {
		ok(memcmp(d, "\x02" "aa", 4) == 0, "dname_from_str: null name compare");
		free(d);
	} else {
		skip("dname_from_str: null name");
	}

	/* non-NULL output, zero maxlen */
	uint8_t d_small[2];
	d = knot_dname_from_str(d_small, s, 0);
	ok(d == NULL, "dname_from_str: non-NULL output, zero maxlen");

	/* small buffer */
	d = knot_dname_from_str(d_small, s, 1);
	ok(d == NULL, "dname_from_str: small buffer");

	/* NULL string */
	d = knot_dname_from_str_alloc(NULL);
	ok(d == NULL, "dname_from_str: null string");

	/* empty string */
	t = "";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: empty string");

	/* empty label */
	t = "..";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: empty label");

	/* leading dot */
	t = ".a";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: leading dot");

	/* incomplete decimal notation I */
	t = "\\1";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: incomplete decimal I");

	/* incomplete decimal notation II */
	t = "\\12";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: incomplete decimal II");

	/* invalid decimal notation I */
	t = "\\256";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: invalid decimal I");

	/* invalid decimal notation II */
	t = "\\2x6";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: invalid decimal II");

	/* invalid escape notation */
	t = "\\2";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: invalid escape");

	/* label length > 63 I */
	t = "1234567890123456789012345678901234567890123456789012345678901234";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: label length > 63 I");

	/* label length > 63 II */
	t = "123456789012345678901234567890123456789012345678901234567890123\\?";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: label length > 63 II");

	/* label length > 63 III */
	t = "123456789012345678901234567890123456789012345678901234567890123\\063";
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: label length > 63 III");

	/* dname length > 255 */
	t = "1234567890123456789012345678901234567890123456789."
	    "1234567890123456789012345678901234567890123456789."
	    "1234567890123456789012345678901234567890123456789."
	    "1234567890123456789012345678901234567890123456789."
	    "123456789012345678901234567890123456789012345678901234.",
	d = knot_dname_from_str_alloc(t);
	ok(d == NULL, "dname_from_str: dname length > 255");

	/* DNAME SUBDOMAIN CHECKS */

	/* equal name is subdomain */
	t = "ab.cd.ef";
	d2 = knot_dname_from_str_alloc(t);
	t = "ab.cd.ef";
	d = knot_dname_from_str_alloc(t);
	ok(!knot_dname_is_sub(d, d2), "dname_subdomain: equal name");
	knot_dname_free(&d, NULL);

	/* true subdomain */
	t = "0.ab.cd.ef";
	d = knot_dname_from_str_alloc(t);
	ok(knot_dname_is_sub(d, d2), "dname_subdomain: true subdomain");
	knot_dname_free(&d, NULL);

	/* not subdomain */
	t = "cd.ef";
	d = knot_dname_from_str_alloc(t);
	ok(!knot_dname_is_sub(d, d2), "dname_subdomain: not subdomain");
	knot_dname_free(&d, NULL);

	/* root subdomain */
	t = ".";
	d = knot_dname_from_str_alloc(t);
	ok(knot_dname_is_sub(d2, d), "dname_subdomain: root subdomain");
	knot_dname_free(&d, NULL);
	knot_dname_free(&d2, NULL);

	/* DNAME CAT CHECKS */

	/* dname cat (valid) */
	w = "\x03""cat";
	d = knot_dname_copy((const uint8_t *)w, NULL);
	t = "*";
	d2 = knot_dname_from_str_alloc(t);
	d2 = knot_dname_cat(d2, d);
	t = "\x01""*""\x03""cat";
	len = 2 + 4 + 1;
	ok(d2 && len == knot_dname_size(d2), "dname_cat: valid concatenation size");
	ok(d2 && memcmp(d2, t, len) == 0, "dname_cat: valid concatenation");
	knot_dname_free(&d, NULL);
	knot_dname_free(&d2, NULL);

	/* DNAME PARSE CHECKS */

	/* parse from wire (valid) */
	t = "\x04""abcd""\x03""efg";
	len = 10;
	pos = 0;
	d = knot_dname_parse((const uint8_t *)t, &pos, len, NULL);
	ok(d != NULL, "dname_parse: valid name");
	ok(pos == len, "dname_parse: valid name (parsed length)");
	knot_dname_free(&d, NULL);

	/* parse from wire (invalid) */
	t = "\x08""dddd";
	len = 5;
	pos = 0;
	d = knot_dname_parse((const uint8_t *)t, &pos, len, NULL);
	ok(d == NULL, "dname_parse: bad name");
	ok(pos == 0, "dname_parse: bad name (parsed length)");

	/* DNAME EQUALITY CHECKS */

	t = "ab.cd.ef";
	d = knot_dname_from_str_alloc(t);
	ok(knot_dname_is_equal(d, d), "dname_is_equal: equal names");

	t = "ab.cd.fe";
	d2 = knot_dname_from_str_alloc(t);
	ok(!knot_dname_is_equal(d, d2), "dname_is_equal: same label count");
	knot_dname_free(&d2, NULL);

	t = "ab.cd";
	d2 = knot_dname_from_str_alloc(t);
	ok(!knot_dname_is_equal(d, d2), "dname_is_equal: len(d1) < len(d2)");
	knot_dname_free(&d2, NULL);

	t = "ab.cd.ef.gh";
	d2 = knot_dname_from_str_alloc(t);
	ok(!knot_dname_is_equal(d, d2), "dname_is_equal: len(d1) > len(d2)");
	knot_dname_free(&d2, NULL);

	t = "ab.cd.efe";
	d2 = knot_dname_from_str_alloc(t);
	ok(!knot_dname_is_equal(d, d2), "dname_is_equal: last label longer");
	knot_dname_free(&d2, NULL);

	t = "ab.cd.e";
	d2 = knot_dname_from_str_alloc(t);
	ok(!knot_dname_is_equal(d, d2), "dname_is_equal: last label shorter");
	knot_dname_free(&d2, NULL);

	knot_dname_free(&d, NULL);

	/* DNAME CONVERSION TO LOOK-UP FORMAT CHECK */

	test_dname_lf();

	return 0;
}
