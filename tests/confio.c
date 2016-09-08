/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include "test_conf.h"
#include "knot/conf/confio.h"
#include "knot/conf/tools.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/string.h"
#include "contrib/openbsd/strlcat.h"

#define SKIP_OPENBSD	skip("Nested transactions are not supported on OpenBSD");
#define OUT_LEN		1024
#define ZONE1		"zone1"
#define ZONE2		"zone2"
#define ZONE3		"zone3"

char *format_key(conf_io_t *io)
{
	char id[KNOT_DNAME_TXT_MAXLEN + 1] = "\0";
	size_t id_len = sizeof(id);

	// Get the textual item id.
	if (io->id_len > 0 && !io->id_as_data) {
		if (yp_item_to_txt(io->key0->var.g.id, io->id, io->id_len, id,
		                   &id_len, YP_SNOQUOTE) != KNOT_EOK) {
			return NULL;
		}
	}

	// Get the item prefix.
	const char *prefix = "";
	switch (io->type) {
	case NEW: prefix = "+"; break;
	case OLD: prefix = "-"; break;
	default: break;
	}

	// Format the item key.
	return sprintf_alloc(
		"%s%.*s%s%.*s%s%s%.*s",
		prefix, (int)io->key0->name[0], io->key0->name + 1,
		(io->id_len > 0 && !io->id_as_data ? "[" : ""),
		(io->id_len > 0 && !io->id_as_data ? (int)id_len : 0), id,
		(io->id_len > 0 && !io->id_as_data ? "]" : ""),
		(io->key1 != NULL ? "." : ""),
		(io->key1 != NULL ? (int)io->key1->name[0] : 0),
		(io->key1 != NULL ? io->key1->name + 1 : ""));
}

static int append_data(const yp_item_t *item, const uint8_t *bin, size_t bin_len,
                       char *out, size_t out_len)
{
	char buf[YP_MAX_TXT_DATA_LEN + 1] = "\0";
	size_t buf_len = sizeof(buf);

	int ret = yp_item_to_txt(item, bin, bin_len, buf, &buf_len, YP_SNONE);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (strlcat(out, buf, out_len) >= out_len) {
		return KNOT_ESPACE;
	}

	return KNOT_EOK;
}

char *format_data(conf_io_t *io)
{
	char out[YP_MAX_TXT_DATA_LEN + 1] = "\0";

	// Return the item identifier as the item data.
	if (io->id_as_data) {
		if (append_data(io->key0->var.g.id, io->id, io->id_len, out,
		                sizeof(out)) != KNOT_EOK) {
			return NULL;
		}

		return strdup(out);
	}

	// Check for no data.
	if (io->data.val == NULL && io->data.bin == NULL) {
		return NULL;
	}

	const yp_item_t *item = (io->key1 != NULL) ? io->key1 : io->key0;

	// Format explicit binary data value.
	if (io->data.bin != NULL) {
		if (append_data(item, io->data.bin, io->data.bin_len, out,
		                sizeof(out)) != KNOT_EOK) {
			return NULL;
		}
	// Format multivalued item data.
	} else if (item->flags & YP_FMULTI) {
		size_t values = conf_val_count(io->data.val);
		for (size_t i = 0; i < values; i++) {
			// Skip other values if known index (counted from 1).
			if (io->data.index > 0 &&
			    io->data.index != i + 1) {
				conf_val_next(io->data.val);
				continue;
			}

			if (i > 0) {
				if (strlcat(out, " ", sizeof(out)) >= sizeof(out)) {
					return NULL;
				}
			}

			conf_val(io->data.val);
			if (append_data(item, io->data.val->data, io->data.val->len,
			                out, sizeof(out)) != KNOT_EOK) {
				return NULL;
			}

			conf_val_next(io->data.val);
		}
	// Format singlevalued item data.
	} else {
		conf_val(io->data.val);
		if (append_data(item, io->data.val->data, io->data.val->len, out,
		                sizeof(out)) != KNOT_EOK) {
			return NULL;
		}
	}

	return strdup(out);
}

static int format_item(conf_io_t *io)
{
	char *out = (char *)io->misc;

	// Get the item key and data strings.
	char *key = format_key(io);
	char *data = format_data(io);

	// Format the item.
	char *item = sprintf_alloc(
		"%s%s%s%s",
		(*out != '\0' ? "\n" : ""),
		(key != NULL ? key : ""),
		(data != NULL ? " = " : ""),
		(data != NULL ? data : ""));
	free(key);
	free(data);
	if (item == NULL) {
		return KNOT_ENOMEM;
	}

	// Append the item.
	if (strlcat(out, item, OUT_LEN) >= OUT_LEN) {
		return KNOT_ESPACE;
	}

	free(item);

	return KNOT_EOK;
}

static void test_conf_io_begin(void)
{
	ok(conf_io_begin(true) == KNOT_TXN_ENOTEXISTS, "begin child txn with no parent");
	ok(conf()->io.txn == NULL, "check txn depth");

#if defined(__OpenBSD__)
	SKIP_OPENBSD
#else
	ok(conf_io_begin(false) == KNOT_EOK, "begin parent txn");
	ok(conf()->io.txn == &(conf()->io.txn_stack[0]), "check txn depth");

	ok(conf_io_begin(false) == KNOT_TXN_EEXISTS, "begin another parent txn");
	ok(conf()->io.txn == &(conf()->io.txn_stack[0]), "check txn depth");

	for (int i = 1; i < CONF_MAX_TXN_DEPTH; i++) {
		ok(conf_io_begin(true) == KNOT_EOK, "begin child txn");
		ok(conf()->io.txn == &(conf()->io.txn_stack[i]), "check txn depth");
	}
	ok(conf_io_begin(true) == KNOT_TXN_EEXISTS, "begin another child txn");
	ok(conf()->io.txn == &(conf()->io.txn_stack[CONF_MAX_TXN_DEPTH - 1]),
	   "check txn depth");

	conf_io_abort(false);
	ok(conf()->io.txn == NULL, "check txn depth");
#endif
}

static void test_conf_io_abort(void)
{
#if defined(__OpenBSD__)
	SKIP_OPENBSD
#else
	conf_io_t io = { NULL };

	// Test child persistence after subchild abort.

	ok(conf_io_begin(false) == KNOT_EOK, "begin parent txn");
	char idx[2] = { '0' };
	ok(conf_io_set("server", "version", NULL, idx, &io) ==
	   KNOT_EOK, "set single value '%s'", idx);

	for (int i = 1; i < CONF_MAX_TXN_DEPTH; i++) {
		char idx[2] = { '0' + i };
		ok(conf_io_begin(true) == KNOT_EOK, "begin child txn %s", idx);
		ok(conf_io_set("server", "version", NULL, idx, &io) ==
		   KNOT_EOK, "set single value '%s'", idx);
	}

	for (int i = CONF_MAX_TXN_DEPTH - 1; i > 0; i--) {
		char idx[2] = { '0' + i };
		conf_io_abort(true);
		conf_val_t val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
		ok(val.code == KNOT_EOK, "check entry");
		const char *data = conf_str(&val);
		ok(*data == (idx[0] - 1), "compare txn data '%s'", data);
	}

	conf_io_abort(false);
	ok(conf()->io.txn == NULL, "check txn depth");

	// Test child abort with committed subchild.
	ok(conf_io_begin(false) == KNOT_EOK, "begin new parent txn");
	ok(conf_io_begin(true) == KNOT_EOK, "begin child txn");
	ok(conf_io_begin(true) == KNOT_EOK, "begin subchild txn");
	ok(conf_io_set("server", "version", NULL, "text", &io) ==
	   KNOT_EOK, "set single value");
	ok(conf_io_commit(true) == KNOT_EOK, "commit subchild txn");
	conf_val_t val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_EOK, "check entry");
	const char *data = conf_str(&val);
	ok(strcmp(data, "text") == 0, "compare subchild txn data '%s'", data);
	conf_io_abort(true);
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_ENOENT, "check entry");
	conf_io_abort(false);

	// Test unchanged read_txn.
	val = conf_get_txn(conf(), &conf()->read_txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_ENOENT, "check entry");
#endif
}

static void test_conf_io_commit(void)
{
	ok(conf_io_commit(false) == KNOT_TXN_ENOTEXISTS, "commit no txt txn");
	ok(conf_io_commit(true) == KNOT_TXN_ENOTEXISTS, "commit no txt txn");

#if defined(__OpenBSD__)
	SKIP_OPENBSD
#else
	conf_io_t io = { NULL };

	// Test subchild persistence after commit.

	ok(conf_io_begin(false) == KNOT_EOK, "begin parent txn");
	char idx[2] = { '0' };
	ok(conf_io_set("server", "version", NULL, idx, &io) ==
	   KNOT_EOK, "set single value '%s'", idx);

	for (int i = 1; i < CONF_MAX_TXN_DEPTH; i++) {
		char idx[2] = { '0' + i };
		ok(conf_io_begin(true) == KNOT_EOK, "begin child txn %s", idx);
		ok(conf_io_set("server", "version", NULL, idx, &io) ==
		   KNOT_EOK, "set single value '%s'", idx);
	}

	for (int i = CONF_MAX_TXN_DEPTH - 1; i > 0; i--) {
		char idx[2] = { '0' + i };
		ok(conf_io_commit(true) == KNOT_EOK, "commit child txn %s", idx);
		conf_val_t val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
		ok(val.code == KNOT_EOK, "check entry");
		const char *data = conf_str(&val);
		ok(*data == ('0' + CONF_MAX_TXN_DEPTH - 1), "compare txn data '%s'", data);
	}

	ok(conf_io_commit(false) == KNOT_EOK, "commit parent txn");
	ok(conf()->io.txn == NULL, "check txn depth");

	// Test child persistence after parent commit.
	ok(conf_io_begin(false) == KNOT_EOK, "begin new parent txn");
	conf_val_t val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_EOK, "check entry");
	idx[0] = '0' + CONF_MAX_TXN_DEPTH - 1;
	const char *data = conf_str(&val);
	ok(strcmp(data, idx) == 0, "compare final data '%s'", data);
	conf_io_abort(false);

	// Test unchanged read_txn.
	val = conf_get_txn(conf(), &conf()->read_txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_ENOENT, "check entry");
#endif
}

static void test_conf_io_check(void)
{
	conf_io_t io = { NULL };

	// ERR no txn.
	ok(conf_io_check(&io) ==
	   KNOT_TXN_ENOTEXISTS, "check without active txn");

	ok(conf_io_begin(false) == KNOT_EOK, "begin txn");

	// Section check.
	ok(conf_io_set("remote", "id", NULL, "remote1", &io) ==
	   KNOT_EOK, "set remote id");
	ok(conf_io_check(&io) ==
	   KNOT_EINVAL, "check missing remote address");
	ok(io.error.code == KNOT_EINVAL, "compare error code");

	ok(conf_io_set("remote", "address", "remote1", "1.1.1.1", &io) ==
	   KNOT_EOK, "set remote address");
	ok(conf_io_check(&io) ==
	   KNOT_EOK, "check remote address");
	ok(io.error.code == KNOT_EOK, "compare error code");

	// Item check.
	ok(conf_io_set("zone", "domain", NULL, ZONE1, &io) ==
	   KNOT_EOK, "set zone domain "ZONE1);
	ok(conf_io_set("zone", "master", ZONE1, "remote1", &io) ==
	   KNOT_EOK, "set zone master");

	ok(conf_io_check(&io) ==
	   KNOT_EOK, "check all");

	ok(conf_io_unset("remote", NULL, NULL, NULL) ==
	   KNOT_EOK, "unset remotes");

	ok(conf_io_check(&io) ==
	   KNOT_ENOENT, "check missing master remote");
	ok(io.error.code == KNOT_ENOENT, "compare error code");

	conf_io_abort(false);
}

static void test_conf_io_set(void)
{
	conf_io_t io = { NULL };

	// ERR no txn.
	ok(conf_io_set("server", "version", NULL, "text", &io) ==
	   KNOT_TXN_ENOTEXISTS, "set without active txn");

	ok(conf_io_begin(false) == KNOT_EOK, "begin txn");

	// ERR.
	ok(conf_io_set(NULL, NULL, NULL, NULL, &io) ==
	   KNOT_EINVAL, "set NULL key0");
	ok(conf_io_set("", NULL, NULL, NULL, &io) ==
	   KNOT_YP_EINVAL_ITEM, "set empty key0");
	ok(conf_io_set("uknown", NULL, NULL, NULL, &io) ==
	   KNOT_YP_EINVAL_ITEM, "set unknown key0");
	ok(conf_io_set("server", "unknown", NULL, NULL, &io) ==
	   KNOT_YP_EINVAL_ITEM, "set unknown key1");
	ok(conf_io_set("include", NULL, NULL, NULL, &io) ==
	   KNOT_YP_ENODATA, "set non-group without data");
	ok(conf_io_set("server", "rate-limit", NULL, "x", &io) ==
	   KNOT_EINVAL, "set invalid data");

	// ERR callback
	ok(io.error.code == KNOT_EOK, "io error check before");
	ok(conf_io_set("include", NULL, NULL, "invalid", &io) ==
	   KNOT_EFILE, "set invalid callback value");
	ok(io.error.code == KNOT_EFILE, "io error check after");

	// Single group, single value.
	ok(conf_io_set("server", "version", NULL, "text", &io) ==
	   KNOT_EOK, "set single value");
	conf_val_t val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_EOK, "check entry");
	ok(strcmp(conf_str(&val), "text") == 0, "check entry value");

	// Single group, multi value.
	ok(conf_io_set("server", "listen", NULL, "1.1.1.1", &io) ==
	   KNOT_EOK, "set multivalue 1");
	ok(conf_io_set("server", "listen", NULL, "1.1.1.2", &io) ==
	   KNOT_EOK, "set multivalue 2");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_LISTEN);
	ok(val.code == KNOT_EOK, "check entry");
	ok(conf_val_count(&val) == 2, "check entry value count");

	// Prepare dnames.
	knot_dname_t *zone1 = knot_dname_from_str_alloc(ZONE1);
	ok(zone1 != NULL, "create dname "ZONE1);
	knot_dname_t *zone2 = knot_dname_from_str_alloc(ZONE2);
	ok(zone2 != NULL, "create dname "ZONE2);
	knot_dname_t *zone3 = knot_dname_from_str_alloc(ZONE3);
	ok(zone3 != NULL, "create dname "ZONE3);

	// Multi group ids.
	ok(conf_io_set("zone", "domain", NULL, ZONE1, &io) ==
	   KNOT_EOK, "set zone domain "ZONE1);
	ok(conf_io_set("zone", NULL, ZONE2, NULL, &io) ==
	   KNOT_EOK, "set zone domain "ZONE2);

	// Multi group, single value.
	ok(conf_io_set("zone", "file", ZONE1, "name", &io) ==
	   KNOT_EOK, "set zone file");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_FILE, zone1);
	ok(val.code == KNOT_EOK, "check entry");
	ok(strcmp(conf_str(&val), "name") == 0, "check entry value");

	// Multi group, single value, bad id.
	ok(conf_io_set("zone", "file", ZONE3, "name", &io) ==
	   KNOT_YP_EINVAL_ID, "set zone file");

	// Multi group, single value, all ids.
	ok(conf_io_set("zone", "comment", NULL, "abc", &io) ==
	   KNOT_EOK, "set zones comment");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone1);
	ok(val.code == KNOT_EOK, "check entry");
	ok(strcmp(conf_str(&val), "abc") == 0, "check entry value");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone2);
	ok(val.code == KNOT_EOK, "check entry");
	ok(strcmp(conf_str(&val), "abc") == 0, "check entry value");

	// Prepare different comment.
	ok(conf_io_set("zone", "domain", NULL, ZONE3, &io) ==
	   KNOT_EOK, "set zone domain "ZONE3);
	ok(conf_io_set("zone", "comment", ZONE3, "xyz", &io) ==
	   KNOT_EOK, "set zone comment");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone3);
	ok(val.code == KNOT_EOK, "check entry");
	ok(strcmp(conf_str(&val), "xyz") == 0, "check entry value");

	knot_dname_free(&zone1, NULL);
	knot_dname_free(&zone2, NULL);
	knot_dname_free(&zone3, NULL);

	ok(conf_io_commit(false) == KNOT_EOK, "commit txn");

	// Update read-only transaction.
	ok(conf_refresh_txn(conf()) == KNOT_EOK, "update read-only txn");
}

static void test_conf_io_unset(void)
{
	// ERR no txn.
	ok(conf_io_unset("server", "version", NULL, "text") ==
	   KNOT_TXN_ENOTEXISTS, "unset without active txn");

	ok(conf_io_begin(false) == KNOT_EOK, "begin txn");

	// ERR.
	ok(conf_io_unset("", NULL, NULL, NULL) ==
	   KNOT_YP_EINVAL_ITEM, "unset unknown key0");
	ok(conf_io_unset("uknown", NULL, NULL, NULL) ==
	   KNOT_YP_EINVAL_ITEM, "unset unknown key0");
	ok(conf_io_unset("server", "unknown", NULL, NULL) ==
	   KNOT_YP_EINVAL_ITEM, "unset unknown key1");
	ok(conf_io_unset("include", NULL, NULL, "file") ==
	   KNOT_ENOTSUP, "unset non-group item");
	ok(conf_io_unset("server", "rate-limit", NULL, "x") ==
	   KNOT_EINVAL, "unset invalid data");

	// Single group, single value.
	ok(conf_io_unset("server", "version", NULL, "") ==
	   KNOT_ENOENT, "unset zero length text value");
	conf_val_t val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_EOK, "check entry");

	ok(conf_io_unset("server", "version", NULL, "bad text") ==
	   KNOT_ENOENT, "unset bad value");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_EOK, "check entry");

	ok(conf_io_unset("server", "version", NULL, "text") ==
	   KNOT_EOK, "unset explicit value");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_ENOENT, "check entry");

	// Restart transaction.
	conf_io_abort(false);
	ok(conf_io_begin(false) == KNOT_EOK, "restart txn");

	ok(conf_io_unset("server", "version", NULL, NULL) ==
	   KNOT_EOK, "unset value");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_ENOENT, "check entry");

	// Single group, multi value.
	ok(conf_io_unset("server", "listen", NULL, "9.9.9.9") ==
	   KNOT_ENOENT, "unset bad value");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_LISTEN);
	ok(val.code == KNOT_EOK, "check entry");

	ok(conf_io_unset("server", "listen", NULL, "1.1.1.1") ==
	   KNOT_EOK, "unset explicit value");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_LISTEN);
	ok(val.code == KNOT_EOK, "check entry");
	ok(conf_val_count(&val) == 1, "check entry value count");

	ok(conf_io_unset("server", "listen", NULL, NULL) ==
	   KNOT_EOK, "unset value");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_LISTEN);
	ok(val.code == KNOT_ENOENT, "check entry");

	// Restart transaction.
	conf_io_abort(false);
	ok(conf_io_begin(false) == KNOT_EOK, "restart txn");

	// Whole section items.
	ok(conf_io_unset("server", NULL, NULL, NULL) ==
	   KNOT_EOK, "unset section");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_LISTEN);
	ok(val.code == KNOT_ENOENT, "check entry");

	// Restart transaction.
	conf_io_abort(false);
	ok(conf_io_begin(false) == KNOT_EOK, "restart txn");

	// Prepare dnames.
	knot_dname_t *zone1 = knot_dname_from_str_alloc(ZONE1);
	ok(zone1 != NULL, "create dname "ZONE1);
	knot_dname_t *zone2 = knot_dname_from_str_alloc(ZONE2);
	ok(zone2 != NULL, "create dname "ZONE2);
	knot_dname_t *zone3 = knot_dname_from_str_alloc(ZONE3);
	ok(zone3 != NULL, "create dname "ZONE3);

	// Multi group, single value.
	ok(conf_io_unset("zone", "file", ZONE1, "name") ==
	   KNOT_EOK, "unset zone file");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_FILE, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");

	// Multi group, single bad value, all ids.
	ok(conf_io_unset("zone", "comment", NULL, "other") ==
	   KNOT_EOK, "unset zones comment");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone1);
	ok(val.code == KNOT_EOK, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone2);
	ok(val.code == KNOT_EOK, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone3);
	ok(val.code == KNOT_EOK, "check entry");

	// Restart transaction.
	conf_io_abort(false);
	ok(conf_io_begin(false) == KNOT_EOK, "restart txn");

	// Multi group, single value (not all match), all ids.
	ok(conf_io_unset("zone", "comment", NULL, "abc") ==
	   KNOT_EOK, "unset some zones comment");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone2);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone3);
	ok(val.code == KNOT_EOK, "check entry");

	// Restart transaction.
	conf_io_abort(false);
	ok(conf_io_begin(false) == KNOT_EOK, "restart txn");

	// Multi group, single value (all match), all ids.
	ok(conf_io_unset("zone", "comment", NULL, NULL) ==
	   KNOT_EOK, "unset all zones comment");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone2);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone3);
	ok(val.code == KNOT_ENOENT, "check entry");

	// Restart transaction.
	conf_io_abort(false);
	ok(conf_io_begin(false) == KNOT_EOK, "restart txn");

	// Multi group, all items, specific id.
	ok(conf_io_unset("zone", NULL, ZONE1, NULL) ==
	   KNOT_EOK, "unset zone items");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_FILE, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone2);
	ok(val.code == KNOT_EOK, "check entry");

	// Restart transaction.
	conf_io_abort(false);
	ok(conf_io_begin(false) == KNOT_EOK, "restart txn");

	// Multi group, all items, all ids.
	ok(conf_io_unset("zone", NULL, NULL, NULL) ==
	   KNOT_EOK, "unset zone items");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_FILE, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone2);
	ok(val.code == KNOT_ENOENT, "check entry");

	// Restart transaction.
	conf_io_abort(false);
	ok(conf_io_begin(false) == KNOT_EOK, "restart txn");

	// All groups.
	ok(conf_io_unset(NULL, NULL, NULL, NULL) ==
	   KNOT_EOK, "unset all");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_VERSION);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_get_txn(conf(), conf()->io.txn, C_SERVER, C_LISTEN);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_FILE, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone1);
	ok(val.code == KNOT_ENOENT, "check entry");
	val = conf_zone_get_txn(conf(), conf()->io.txn, C_COMMENT, zone2);
	ok(val.code == KNOT_ENOENT, "check entry");

	knot_dname_free(&zone1, NULL);
	knot_dname_free(&zone2, NULL);
	knot_dname_free(&zone3, NULL);

	conf_io_abort(false);
}

static void test_conf_io_get(void)
{
	const char *ref;
	char out[OUT_LEN];

	conf_io_t io = {
		.fcn = format_item,
		.misc = out
	};

	// ERR no txn.
	ok(conf_io_get("server", "version", NULL, false, &io) ==
	   KNOT_TXN_ENOTEXISTS, "get without active txn");

	// Get current, no active txn.
	*out = '\0';
	ok(conf_io_get("server", "version", NULL, true, &io) ==
	   KNOT_EOK, "get current without active txn");
	ref = "server.version = \"text\"";
	ok(strcmp(ref, out) == 0, "compare result");

	ok(conf_io_begin(false) == KNOT_EOK, "begin txn");

	// ERR.
	ok(conf_io_get("", NULL, NULL, true, &io) ==
	   KNOT_YP_EINVAL_ITEM, "get empty key0");
	ok(conf_io_get("uknown", NULL, NULL, true, &io) ==
	   KNOT_YP_EINVAL_ITEM, "get unknown key0");
	ok(conf_io_get("server", "unknown", NULL, true, &io) ==
	   KNOT_YP_EINVAL_ITEM, "get unknown key1");
	ok(conf_io_get("include", NULL, NULL, true, &io) ==
	   KNOT_ENOTSUP, "get non-group item");

	// Update item in the active txn.
	ok(conf_io_set("server", "version", NULL, "new text", &io) ==
	   KNOT_EOK, "set single value");

	// Get new, active txn.
	*out = '\0';
	ok(conf_io_get("server", "version", NULL, false, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "server.version = \"new text\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Get current, active txn.
	*out = '\0';
	ok(conf_io_get("server", "version", NULL, true, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "server.version = \"text\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Multi value.
	*out = '\0';
	ok(conf_io_get("server", "listen", NULL, true, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "server.listen = \"1.1.1.1\" \"1.1.1.2\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Single group.
	*out = '\0';
	ok(conf_io_get("server", NULL, NULL, true, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "server.version = \"text\"\n"
	      "server.listen = \"1.1.1.1\" \"1.1.1.2\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Prepare dnames.
	knot_dname_t *zone1 = knot_dname_from_str_alloc(ZONE1);
	ok(zone1 != NULL, "create dname "ZONE1);

	// Multi group, all values, all ids.
	*out = '\0';
	ok(conf_io_get("zone", NULL, NULL, true, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "zone.domain = \"zone1.\"\n"
	      "zone[zone1.].file = \"name\"\n"
	      "zone[zone1.].comment = \"abc\"\n"
	      "zone.domain = \"zone2.\"\n"
	      "zone[zone2.].comment = \"abc\"\n"
	      "zone.domain = \"zone3.\"\n"
	      "zone[zone3.].comment = \"xyz\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Multi group ids.
	*out = '\0';
	ok(conf_io_get("zone", "domain", NULL, true, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "zone.domain = \"zone1.\"\n"
	      "zone.domain = \"zone2.\"\n"
	      "zone.domain = \"zone3.\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Multi group, all values, single id.
	*out = '\0';
	ok(conf_io_get("zone", NULL, ZONE1, true, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "zone.domain = \"zone1.\"\n"
	      "zone[zone1.].file = \"name\"\n"
	      "zone[zone1.].comment = \"abc\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Multi group, single value, single id.
	*out = '\0';
	ok(conf_io_get("zone", "file", ZONE1, true, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "zone[zone1.].file = \"name\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// All groups.
	*out = '\0';
	ok(conf_io_get(NULL, NULL, NULL, true, &io) ==
	   KNOT_EOK, "get with active txn");
	ref = "server.version = \"text\"\n"
	      "server.listen = \"1.1.1.1\" \"1.1.1.2\"\n"
	      "zone.domain = \"zone1.\"\n"
	      "zone[zone1.].file = \"name\"\n"
	      "zone[zone1.].comment = \"abc\"\n"
	      "zone.domain = \"zone2.\"\n"
	      "zone[zone2.].comment = \"abc\"\n"
	      "zone.domain = \"zone3.\"\n"
	      "zone[zone3.].comment = \"xyz\"";
	ok(strcmp(ref, out) == 0, "compare result");

	knot_dname_free(&zone1, NULL);

	conf_io_abort(false);
}

static void test_conf_io_diff(void)
{
	const char *ref;
	char out[OUT_LEN];

	conf_io_t io = {
		.fcn = format_item,
		.misc = out
	};

	// ERR no txn.
	ok(conf_io_diff("server", "version", NULL, &io) ==
	   KNOT_TXN_ENOTEXISTS, "diff without active txn");

	ok(conf_io_begin(false) == KNOT_EOK, "begin txn");

	// ERR.
	ok(conf_io_diff("", NULL, NULL, &io) ==
	   KNOT_YP_EINVAL_ITEM, "diff empty key0");
	ok(conf_io_diff("uknown", NULL, NULL, &io) ==
	   KNOT_YP_EINVAL_ITEM, "diff unknown key0");
	ok(conf_io_diff("server", "unknown", NULL, &io) ==
	   KNOT_YP_EINVAL_ITEM, "diff unknown key1");
	ok(conf_io_diff("include", NULL, NULL, &io) ==
	   KNOT_ENOTSUP, "diff non-group item");

	*out = '\0';
	ok(conf_io_diff(NULL, NULL, NULL, &io) == KNOT_EOK, "diff no change");
	ref = "";
	ok(strcmp(ref, out) == 0, "compare result");

	// Update singlevalued item.
	ok(conf_io_set("server", "version", NULL, "new text", &io) ==
	   KNOT_EOK, "set single value");

	*out = '\0';
	ok(conf_io_diff("server", "version", NULL, &io) == KNOT_EOK, "diff single item");
	ref = "-server.version = \"text\"\n"
	      "+server.version = \"new text\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Update multivalued item.
	ok(conf_io_unset("server", "listen", NULL, "1.1.1.1") ==
	   KNOT_EOK, "unset multivalue");
	ok(conf_io_set("server", "listen", NULL, "1.1.1.3", &io) ==
	   KNOT_EOK, "set multivalue");

	*out = '\0';
	ok(conf_io_diff("server", "listen", NULL, &io) == KNOT_EOK, "diff multi item");
	ref = "-server.listen = \"1.1.1.1\" \"1.1.1.2\"\n"
	      "+server.listen = \"1.1.1.2\" \"1.1.1.3\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Unset single item.
	ok(conf_io_unset("zone", "comment", ZONE3, NULL) ==
	   KNOT_EOK, "unset multivalue");

	*out = '\0';
	ok(conf_io_diff("zone", NULL, ZONE3, &io) == KNOT_EOK, "diff section");
	ref = "-zone[zone3.].comment = \"xyz\"";
	ok(strcmp(ref, out) == 0, "compare result");

	// Unset id.
	ok(conf_io_unset("zone", NULL, ZONE1, NULL) ==
	   KNOT_EOK, "unset id");
	ok(conf_io_unset("zone", NULL, ZONE2, NULL) ==
	   KNOT_EOK, "unset id");

	*out = '\0';
	ok(conf_io_diff("zone", NULL, ZONE2, &io) == KNOT_EOK, "diff id section");
	ref = "-zone.domain = \"zone2.\"\n"
	      "-zone[zone2.].comment = \"abc\"";
	ok(strcmp(ref, out) == 0, "compare result");

	*out = '\0';
	ok(conf_io_diff("zone", "domain", NULL, &io) == KNOT_EOK, "diff id");
	ref = "-zone.domain = \"zone1.\"\n"
	      "-zone.domain = \"zone2.\"";
	ok(strcmp(ref, out) == 0, "compare result");

	*out = '\0';
	ok(conf_io_diff(NULL, NULL, NULL, &io) == KNOT_EOK, "diff whole change");
	ref = "-server.version = \"text\"\n"
	      "+server.version = \"new text\"\n"
	      "-server.listen = \"1.1.1.1\" \"1.1.1.2\"\n"
	      "+server.listen = \"1.1.1.2\" \"1.1.1.3\"\n"
	      "-zone.domain = \"zone1.\"\n"
	      "-zone[zone1.].file = \"name\"\n"
	      "-zone[zone1.].comment = \"abc\"\n"
	      "-zone.domain = \"zone2.\"\n"
	      "-zone[zone2.].comment = \"abc\"\n"
	      "-zone[zone3.].comment = \"xyz\"";
	ok(strcmp(ref, out) == 0, "compare result");

	conf_io_abort(false);
}

static void test_conf_io_list(void)
{
	const char *ref;
	char out[OUT_LEN];

	conf_io_t io = {
		.fcn = format_item,
		.misc = out
	};

	// ERR.
	ok(conf_io_list("", &io) ==
	   KNOT_YP_EINVAL_ITEM, "list empty key0");
	ok(conf_io_list("uknown", &io) ==
	   KNOT_YP_EINVAL_ITEM, "list unknown key0");
	ok(conf_io_list("include", &io) ==
	   KNOT_ENOTSUP, "list non-group item");

	// Desc schema.
	*out = '\0';
	ok(conf_io_list(NULL, &io) ==
	   KNOT_EOK, "list schema");
	ref = "server\n"
	      "control\n"
	      "remote\n"
	      "template\n"
	      "zone\n"
	      "include";
	ok(strcmp(ref, out) == 0, "compare result");

	// Desc group.
	*out = '\0';
	ok(conf_io_list("server", &io) ==
	   KNOT_EOK, "list group");
	ref = "server.version\n"
	      "server.rate-limit\n"
	      "server.listen\n"
	      "server.tcp-handshake-timeout\n"
	      "server.tcp-idle-timeout\n"
	      "server.tcp-reply-timeout\n"
	      "server.max-tcp-clients\n"
	      "server.max-udp-payload\n"
	      "server.max-ipv4-udp-payload\n"
	      "server.max-ipv6-udp-payload\n"
	      "server.rate-limit-slip";
	ok(strcmp(ref, out) == 0, "compare result");
}

static const yp_item_t desc_server[] = {
	{ C_VERSION,              YP_TSTR,  YP_VNONE },
	{ C_RATE_LIMIT,           YP_TINT,  YP_VNONE },
	{ C_LISTEN,               YP_TADDR, YP_VNONE, YP_FMULTI },
	// Required config cache items - assert fix.
	{ C_TCP_HSHAKE_TIMEOUT,   YP_TINT,  YP_VNONE },
	{ C_TCP_IDLE_TIMEOUT,	  YP_TINT,  YP_VNONE },
	{ C_TCP_REPLY_TIMEOUT,	  YP_TINT,  YP_VNONE },
	{ C_MAX_TCP_CLIENTS,	  YP_TINT,  YP_VNONE },
	{ C_MAX_UDP_PAYLOAD,      YP_TINT,  YP_VNONE },
	{ C_MAX_IPV4_UDP_PAYLOAD, YP_TINT,  YP_VNONE },
	{ C_MAX_IPV6_UDP_PAYLOAD, YP_TINT,  YP_VNONE },
	{ C_RATE_LIMIT_SLIP,	  YP_TINT,  YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_control[] = {
	{ C_TIMEOUT, YP_TINT, YP_VNONE },
	{ NULL }
};

static const yp_item_t desc_remote[] = {
	{ C_ID,   YP_TSTR,  YP_VNONE },
	{ C_ADDR, YP_TADDR, YP_VNONE, YP_FMULTI },
	{ NULL }
};

#define ZONE_ITEMS \
	{ C_FILE,           YP_TSTR,  YP_VNONE }, \
	{ C_MASTER,         YP_TREF,  YP_VREF = { C_RMT }, YP_FMULTI, { check_ref } }, \
	{ C_DNSSEC_SIGNING, YP_TBOOL, YP_VNONE }, \
	{ C_COMMENT,        YP_TSTR,  YP_VNONE },

static const yp_item_t desc_template[] = {
	{ C_ID, YP_TSTR, YP_VNONE },
	ZONE_ITEMS
	{ NULL }
};

static const yp_item_t desc_zone[] = {
	{ C_DOMAIN, YP_TDNAME, YP_VNONE },
	ZONE_ITEMS
	{ NULL }
};

const yp_item_t test_scheme[] = {
	{ C_SRV,  YP_TGRP, YP_VGRP = { desc_server } },
	{ C_CTL,  YP_TGRP, YP_VGRP = { desc_control } },
	{ C_RMT,  YP_TGRP, YP_VGRP = { desc_remote }, YP_FMULTI, { check_remote } },
	{ C_TPL,  YP_TGRP, YP_VGRP = { desc_template }, YP_FMULTI, { check_template } },
	{ C_ZONE, YP_TGRP, YP_VGRP = { desc_zone }, YP_FMULTI, { check_zone } },
	{ C_INCL, YP_TSTR, YP_VNONE, YP_FNONE, { include_file } },
	{ NULL }
};

int main(int argc, char *argv[])
{
	plan_lazy();

	ok(test_conf("", test_scheme) == KNOT_EOK, "Prepare configuration");

	diag("conf_io_begin");
	test_conf_io_begin();

	diag("conf_io_abort");
	test_conf_io_abort();

	diag("conf_io_commit");
	test_conf_io_commit();

	diag("conf_io_check");
	test_conf_io_check();

	diag("conf_io_set");
	test_conf_io_set();

	diag("conf_io_unset");
	test_conf_io_unset();

	diag("conf_io_get");
	test_conf_io_get();

	diag("conf_io_diff");
	test_conf_io_diff();

	diag("conf_io_list");
	test_conf_io_list();

	conf_free(conf());

	return 0;
}
