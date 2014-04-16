#include <assert.h>
#include <stdio.h>

#include "dnssec/error.h"
#include "legacy/legacy.h"
#include "legacy/privkey.h"
#include "legacy/pubkey.h"
#include "shared.h"

static void get_key_names(const char *input, char **public_ptr, char **private_ptr)
{
	assert(input);
	assert(public_ptr);
	assert(private_ptr);

	asprintf(public_ptr, "%s.key", input);
	asprintf(private_ptr, "%s.private", input);
}

int legacy_key_import(const char *filename)
{
	if (!filename) {
		return DNSSEC_EINVAL;
	}

	_cleanup_free_ char *filename_dnskey = NULL;
	_cleanup_free_ char *filename_private = NULL;
	get_key_names(filename, &filename_dnskey, &filename_private);
	if (!filename_dnskey || !filename_private) {
		return DNSSEC_EINVAL;
	}

	legacy_privkey_t params = { 0 };
	int r = legacy_privkey_parse(filename_private, &params);
	if (r != DNSSEC_EOK) {
		return r;
	}

	printf("conversion happens here\n");

	legacy_privkey_free(&params);

	return DNSSEC_EOK;
}
