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

#define streq(one, two) (strcmp((one), (two)) == 0)

/* -- cleanup macros ------------------------------------------------------- */

#define _cleanup_(var) __attribute__((cleanup(var)))

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
