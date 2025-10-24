/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "libknot/dnssec/binary.h"
#include "libknot/attribute.h"

/*!
 * Macro to clear a structure of known size.
 *
 * \param pointer Pointer to the structure.
 */
#define clear_struct(pointer) memset((pointer), '\0', sizeof(*(pointer)))

/* -- cleanup macros ------------------------------------------------------- */

static inline void free_ptr(void *ptr)
{
	free(*(void **)ptr);
}

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

static inline void closedir_ptr(DIR **ptr)
{
	if (*ptr) {
		closedir(*ptr);
	}
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

static inline void free_pubkey_ptr(gnutls_pubkey_t *ptr)
{
	if (*ptr) {
		gnutls_pubkey_deinit(*ptr);
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
#define _cleanup_closedir_ _cleanup_(closedir_ptr)
#define _cleanup_binary_ _cleanup_(dnssec_binary_free)
#define _cleanup_datum_ _cleanup_(free_gnutls_datum_ptr)
#define _cleanup_x509_privkey_ _cleanup_(free_x509_privkey_ptr)
#define _cleanup_pubkey_ _cleanup_(free_pubkey_ptr)
#define _cleanup_hash_ _cleanup_(free_gnutls_hash_ptr)

/* -- assertions ----------------------------------------------------------- */

#define assert_unreachable() assert(0)

/* -- crypto helpers ------------------------------------------------------- */

static inline gnutls_datum_t binary_to_datum(const dnssec_binary_t *from)
{
	gnutls_datum_t to = { .size = from->size, .data = from->data };
	return to;
}

static inline dnssec_binary_t binary_from_datum(const gnutls_datum_t *from)
{
	dnssec_binary_t to = { .size = from->size, .data = from->data };
	return to;
}
