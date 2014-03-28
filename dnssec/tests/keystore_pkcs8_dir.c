#include <stdio.h>
#include <tap/basic.h>
#include <unistd.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "keystore.h"

typedef struct test_pem {
	dnssec_key_id_t id;
	dnssec_binary_t data;
} test_pem_t;

extern const dnssec_keystore_pkcs8_functions_t PKCS8_DIR_FUNCTIONS;

const test_pem_t TEST_PEM_A = {
	{ 0x7b, 0x0c, 0x9f, 0x6a, 0x59, 0xb1, 0xc7, 0x6b, 0x26, 0xed,
	  0x93, 0xea, 0x86, 0x84, 0xf3, 0x00, 0x82, 0x1e, 0xee, 0x41 },
	{ .size = 5, .data = (uint8_t *)"hello" }
};

const test_pem_t TEST_PEM_B = {
	{ 0xf4, 0xf3, 0xe7, 0x3c, 0xf4, 0xee, 0x60, 0x59, 0x93, 0xc2,
	   0xef, 0x2d, 0x79, 0x05, 0x71, 0xad, 0xe8, 0x27, 0x24, 0x4c },
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

	r = func->read(data, TEST_PEM_B.id, &bin);
	ok(r == DNSSEC_EOK && dnssec_binary_cmp(&TEST_PEM_B.data, &bin) == 0,
	   "read B");

	// cleanup

	r = func->close(data);
	ok(r == DNSSEC_EOK, "close");

	rm(dir, "7b0c9f6a59b1c76b26ed93ea8684f300821eee41.pem");
	rm(dir, "f4f3e73cf4ee605993c2ef2d790571ade827244c.pem");

	test_tmpdir_free(dir);

	return 0;
}
