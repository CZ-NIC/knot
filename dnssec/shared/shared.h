#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>

#include "binary.h"

#define _public_ __attribute__((visibility("default")))
#define _hidden_ __attribute__((visibility("hidden")))

#define _unused_ __attribute__((unused))

/**
 * Macro to clear a structure of known size.
 *
 * \param pointer Pointer to the structure.
 */
#define clear_struct(pointer) memset((pointer), '\0', sizeof(*(pointer)))

/* -- cleanup macros ------------------------------------------------------- */

#define _cleanup_(var) __attribute__((cleanup(var)))

static inline void close_ptr(int *ptr)
{
	if (*ptr != -1) {
		close(*ptr);
	}
}
static inline void fclose_ptr(FILE **ptr)
{
	if (*ptr) {
		fclose(*ptr);
	}
}

static inline void free_ptr(void *ptr)
{
	free(*(void **)ptr);
}

static inline void free_gnutls_datum_ptr(gnutls_datum_t *ptr)
{
	gnutls_free(ptr->data);
}

static inline void free_x509_privkey_ptr(gnutls_x509_privkey_t *ptr)
{
	if (*ptr) {
		gnutls_x509_privkey_deinit(*ptr);
	}
}

static inline void free_gnutls_hash_ptr(gnutls_hash_hd_t *ptr)
{
	if (*ptr) {
		gnutls_hash_deinit(*ptr, NULL);
	}
}

#define _cleanup_free_ _cleanup_(free_ptr)
#define _cleanup_close_ _cleanup_(close_ptr)
#define _cleanup_fclose_ _cleanup_(fclose_ptr)
#define _cleanup_binary_ _cleanup_(dnssec_binary_free)
#define _cleanup_datum_ _cleanup_(free_gnutls_datum_ptr)
#define _cleanup_x509_privkey_ _cleanup_(free_x509_privkey_ptr)
#define _cleanup_hash_ _cleanup_(free_gnutls_hash_ptr)

/* -- crypto helpers ------------------------------------------------------- */

static inline void binary_to_datum(const dnssec_binary_t *binary,
				   gnutls_datum_t *datum)
{
	assert(binary);
	assert(datum);

	datum->data = binary->data;
	datum->size = binary->size;
}

static inline void datum_to_binary(const gnutls_datum_t *datum,
				   dnssec_binary_t *binary)
{
	assert(datum);
	assert(binary);

	binary->data = datum->data;
	binary->size = datum->size;
}
