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

#pragma once

#include "list.h"
#include "kasp.h"

/*!
 * KASP store API implementation.
 */
typedef struct dnssec_kasp_store_functions {
	int (*init)(const char *config);
	// internal context initialization
	int (*open)(void **ctx_ptr, const char *config);
	void (*close)(void *ctx);
	// zone serialization/deserialization
	int (*zone_load)(void *ctx, dnssec_kasp_zone_t *zone);
	int (*zone_save)(void *ctx, dnssec_kasp_zone_t *zone);
	int (*zone_remove)(void *ctx, const char *zone_name);
	int (*zone_list)(void *ctx, dnssec_list_t *zone_names);
	int (*zone_exists)(void *ctx, const char *zone_name);
	// policy serialization/deserialization
	int (*policy_load)(void *ctx, dnssec_kasp_policy_t *policy);
	int (*policy_save)(void *ctx, dnssec_kasp_policy_t *policy);
	int (*policy_remove)(void *ctx, const char *name);
	int (*policy_list)(void *ctx, dnssec_list_t *policy_names);
	int (*policy_exists)(void *ctx, const char *name);
	// keystore serialization/deserialization
	int (*keystore_load)(void *ctx, dnssec_kasp_keystore_t *keystore);
	int (*keystore_save)(void *ctx, dnssec_kasp_keystore_t *keystore);
	int (*keystore_remove)(void *ctx, const char *name);
	int (*keystore_list)(void *ctx, dnssec_list_t *names);
	int (*keystore_exists)(void *ctx, const char *name);
} dnssec_kasp_store_functions_t;

/*!
 * DNSSEC KASP reference.
 */
struct dnssec_kasp {
	const dnssec_kasp_store_functions_t *functions;
	void *ctx;
};

/*!
 * Create new KASP handle.
 *
 * \param[out] kasp_ptr   New KASP handle.
 * \param[in]  functions  KASP store implementation.
 *
 * \return Error code, DNSSE_EOK if successful.
 */
int dnssec_kasp_create(dnssec_kasp_t **kasp_ptr,
		       const dnssec_kasp_store_functions_t *functions);

/*!
 * Free content of the keystore structure.
 */
void kasp_keystore_cleanup(dnssec_kasp_keystore_t *keystore);
