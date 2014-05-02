/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <tap/basic.h>
#include <unistd.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "keystore.h"

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
	void *data = NULL;
	dnssec_binary_t bin = { 0 };

	char *dir = test_tmpdir();
	if (!dir) {
		return 1;
	}

	// create context

	const dnssec_keystore_pkcs8_functions_t *func = &PKCS8_DIR_FUNCTIONS;
	r = func->open(&data, dir);
	ok(r == DNSSEC_EOK && data != NULL, "open");

	// read/write tests

	r = func->read(data, TEST_PEM_A.id, &bin);
	ok(r != DNSSEC_EOK && bin.size == 0, "read non-existent");

	r = func->write(data, TEST_PEM_A.id, &TEST_PEM_A.data);
	ok(r == DNSSEC_EOK, "write A");

	r = func->write(data, TEST_PEM_B.id, &TEST_PEM_B.data);
	ok(r == DNSSEC_EOK, "write B");

	r = func->read(data, TEST_PEM_A.id, &bin);
	ok(r == DNSSEC_EOK && dnssec_binary_cmp(&TEST_PEM_A.data, &bin) == 0,
	   "read A");
	dnssec_binary_free(&bin);

	r = func->read(data, TEST_PEM_B.id, &bin);
	ok(r == DNSSEC_EOK && dnssec_binary_cmp(&TEST_PEM_B.data, &bin) == 0,
	   "read B");
	dnssec_binary_free(&bin);

	// cleanup

	r = func->close(data);
	ok(r == DNSSEC_EOK, "close");

	rm(dir, "7b0c9f6a59b1c76b26ed93ea8684f300821eee41.pem");
	rm(dir, "f4f3e73cf4ee605993c2ef2d790571ade827244c.pem");

	test_tmpdir_free(dir);

	return 0;
}
