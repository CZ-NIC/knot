/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#define dnserr_conf test_dnserr_conf
#define dnserr_conf_check test_dnserr_conf_check
#define dnserr_load test_dnserr_load
#define dnserr_unload test_dnserr_unload
#include "knot/modules/dnserr/dnserr.c"
#include "libknot/errcode.h"

#define test_pass_parse_report_query(x) _test_parse_report_query((x), KNOT_EOK)
#define test_fail_parse_report_query(x) _test_parse_report_query((x), KNOT_EMALF)
#define test_skip_parse_report_query(x) _test_parse_report_query((x), KNOT_ENOENT)

static void _test_parse_report_query(const char *dname_txt, int expected)
{
	knot_dname_storage_t dname;
	if (knot_dname_from_str(dname, dname_txt, KNOT_DNAME_MAXLEN) == NULL) {
		skip("parse_report_query: '%s' is not valid dname", dname_txt);
	}
	dnserr_parsed_t parsed;
	int ret = report_query(&parsed, 0, dname);
	ok(ret == expected, "parse_report_query, %s", dname_txt);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// Must start (and not end) with _er label
	test_skip_parse_report_query(".");
	test_skip_parse_report_query("a");
	test_skip_parse_report_query("a._er");
	test_fail_parse_report_query("_er");
	test_skip_parse_report_query("1.a.1._er");
	test_skip_parse_report_query("a.1.a.1._er");
	test_skip_parse_report_query("a._er.1.a.1._er");

	// After _er label there is a list of decadic rrtypes joined with hyphen
	test_fail_parse_report_query("_er.a");
	test_fail_parse_report_query("_er.-");
	test_fail_parse_report_query("_er.-1");
	test_fail_parse_report_query("_er.1-");
	test_fail_parse_report_query("_er.1");
	test_fail_parse_report_query("_er.1-2");
	test_fail_parse_report_query("_er.-1-2");
	test_fail_parse_report_query("_er.1-2-");
	test_fail_parse_report_query("_er.1a-2");
	test_fail_parse_report_query("_er.1-a2");
	test_fail_parse_report_query("_er.a.a.2._er");
	test_fail_parse_report_query("_er.-.a.2._er");
	test_fail_parse_report_query("_er.-1.a.2._er");
	test_fail_parse_report_query("_er.1-.a.2._er");
	test_fail_parse_report_query("_er.-1-2.a.2._er");
	test_fail_parse_report_query("_er.1-2-.a.2._er");
	test_fail_parse_report_query("_er.1a-2.a.2._er");
	test_fail_parse_report_query("_er.1-a2.a.2._er");

	// After rrcode list label there is a dname
	test_fail_parse_report_query("_er.1");
	test_fail_parse_report_query("_er.1.a");
	test_fail_parse_report_query("_er.1.a.a.a.a");
	test_fail_parse_report_query("_er.1.1._er");

	// After dname is errcode
	test_fail_parse_report_query("_er.1.a.a");
	test_fail_parse_report_query("_er.1.a.1a");
	test_fail_parse_report_query("_er.1.a.a1");
	test_fail_parse_report_query("_er.1.a.1-1");
	test_fail_parse_report_query("_er.1.a.a._er");
	test_fail_parse_report_query("_er.1.a.1a._er");
	test_fail_parse_report_query("_er.1.a.a1._er");
	test_fail_parse_report_query("_er.1.a.1-1._er");

	// Allowed names
	test_pass_parse_report_query("_er.1.a.1._er");
	test_pass_parse_report_query("_er.1-28.a.2._er");
	test_pass_parse_report_query("_er.1-2-28.a.3._er");
	test_pass_parse_report_query("_er.1.a.a.1._er");
	test_pass_parse_report_query("_er.1-28.a.a.2._er");
	test_pass_parse_report_query("_er.1-2-28.a.a.3._er");

	return 0;
}
