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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <tap/basic.h>
#include <unistd.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "keystore.h"
#include "keystore/pkcs8_dir.c"

typedef struct test_pem {
	const char *id;
	dnssec_binary_t data;
} test_pem_t;

extern const dnssec_keystore_pkcs8_functions_t PKCS8_DIR_FUNCTIONS;

const test_pem_t TEST_PEM_A = {
	"7b0c9f6a59b1c76b26ed93ea8684f300821eee41",
	{ .size = 5, .data = (uint8_t *)"hello" }
};

const test_pem_t TEST_PEM_B = {
	"f4f3e73cf4ee605993c2ef2d790571ade827244c",
	{ .size = 4, .data = (uint8_t *)"knot" }
};

static void rm(const char *dir, const char *file)
{
	char buffer[4096] = { 0 };
	int r = snprintf(buffer, 4096, "%s/%s", dir, file);
	if (r < 0) {
		ok(0, "rm");
		return;
	}

	r = unlink(buffer);
	ok(r == 0, "rm %s", buffer);
}

int main(void)
{
	plan_lazy();

	int r = 0;
	void *handle = NULL;
	dnssec_binary_t bin = { 0 };

	char *dir = test_tmpdir();
	if (!dir) {
		return 1;
	}

	// create context

	const dnssec_keystore_pkcs8_functions_t *func = &PKCS8_DIR_FUNCTIONS;

	r = func->handle_new(&handle);
	ok(r == DNSSEC_EOK && handle != NULL, "new handle");

	r = func->init(handle, dir);
	ok(r == DNSSEC_EOK, "init");

	r = func->open(handle, dir);
	ok(r == DNSSEC_EOK, "open");

	// non-existent reads

	r = func->read(handle, TEST_PEM_A.id, &bin);
	ok(r == DNSSEC_ENOENT && bin.size == 0, "read non-existent");

	// writing new content

	r = func->write(handle, TEST_PEM_A.id, &TEST_PEM_A.data);
	ok(r == DNSSEC_EOK, "write A");

	r = func->write(handle, TEST_PEM_B.id, &TEST_PEM_B.data);
	ok(r == DNSSEC_EOK, "write B");

	r = func->write(handle, TEST_PEM_A.id, &TEST_PEM_A.data);
	ok(r == DNSSEC_EOK, "write A (duplicate)");

	// content listing

	dnssec_list_t *list = NULL;
	r = func->list(handle, &list);
	ok(r == DNSSEC_EOK, "get list");
	is_int(2, dnssec_list_size(list), "list size");

	bool found_a = false;
	bool found_b = false;
	dnssec_list_foreach(item, list) {
		char *id = dnssec_item_get(item);
		if (id && strcmp(TEST_PEM_A.id, id) == 0) { found_a = true; }
		if (id && strcmp(TEST_PEM_B.id, id) == 0) { found_b = true; }
	}
	ok(found_a && found_b, "list content");

	dnssec_list_free_full(list, NULL, NULL);

	// reading existing content

	r = func->read(handle, TEST_PEM_A.id, &bin);
	ok(r == DNSSEC_EOK && dnssec_binary_cmp(&TEST_PEM_A.data, &bin) == 0,
	   "read A");
	dnssec_binary_free(&bin);

	r = func->read(handle, TEST_PEM_B.id, &bin);
	ok(r == DNSSEC_EOK && dnssec_binary_cmp(&TEST_PEM_B.data, &bin) == 0,
	   "read B");
	dnssec_binary_free(&bin);

	// content removal

	r = func->remove(handle, TEST_PEM_A.id);
	ok(r == DNSSEC_EOK, "remove A");

	r = func->read(handle, TEST_PEM_A.id, &bin);
	ok(r == DNSSEC_ENOENT && bin.size == 0, "read removed");

	// cleanup

	r = func->close(handle);
	ok(r == DNSSEC_EOK, "close");

	r = func->handle_free(handle);
	ok(r == DNSSEC_EOK, "free handle");

	rm(dir, "f4f3e73cf4ee605993c2ef2d790571ade827244c.pem");

	test_tmpdir_free(dir);

	return 0;
}
