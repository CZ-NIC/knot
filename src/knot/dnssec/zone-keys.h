/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/dynarray.h"
#include "libdnssec/keystore.h"
#include "libdnssec/sign.h"
#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/dnssec/kasp/policy.h"
#include "knot/dnssec/context.h"

/*!
 * \brief Zone key context used during signing.
 */
typedef struct {
	const char *id;
	dnssec_key_t *key;
	dnssec_sign_ctx_t *ctx;

	dnssec_binary_t precomputed_ds;

	knot_time_t next_event;

	bool is_ksk;
	bool is_zsk;
	bool is_active;
	bool is_public;
	int cds_priority;
} zone_key_t;

dynarray_declare(keyptr, zone_key_t *, DYNARRAY_VISIBILITY_PUBLIC, 1)

typedef struct {
	size_t count;
	zone_key_t *keys;
} zone_keyset_t;

/*!
 * \brief Flags determining key type
 */
extern const uint16_t DNSKEY_FLAGS_KSK;
extern const uint16_t DNSKEY_FLAGS_ZSK;
uint16_t dnskey_flags(bool is_ksk);

typedef enum {
        DNSKEY_GENERATE_KSK      = (1 << 0), // KSK flag in metadata
        DNSKEY_GENERATE_ZSK      = (1 << 1), // ZSK flag in metadata
        DNSKEY_GENERATE_SEP_SPEC = (1 << 2), // not (SEP bit set iff KSK)
        DNSKEY_GENERATE_SEP_ON   = (1 << 3), // SEP bit set on
} kdnssec_generate_flags_t;

void normalize_generate_flags(kdnssec_generate_flags_t *flags);

/*!
 * \brief Generate new key, store all details in new kasp key structure.
 *
 * \param ctx           kasp context
 * \param flags         determine if to use the key as KSK and/or ZSK and SEP flag
 * \param key_ptr       output if KNOT_EOK: new pointer to generated key
 *
 * \return KNOT_E*
 */
int kdnssec_generate_key(kdnssec_ctx_t *ctx, kdnssec_generate_flags_t flags,
                         knot_kasp_key_t **key_ptr);

/*!
 * \brief Take a key from another zone (copying info, sharing privkey).
 *
 * \param ctx           kasp context
 * \param from_zone     name of the zone to take from
 * \param key_id        ID of the key to take
 *
 * \return KNOT_E*
 */
int kdnssec_share_key(kdnssec_ctx_t *ctx, const knot_dname_t *from_zone, const char *key_id);

/*!
 * \brief Remove key from zone.
 *
 * Deletes the key in keystore, unlinks the key from the zone in KASP db,
 * moreover if no more zones use this key in KASP db, deletes it completely there
 * and deletes it also from key storage (PKCS8dir/PKCS11).
 *
 * \param ctx           kasp context (zone, keystore, kaspdb) to be modified
 * \param key_ptr       pointer to key to be removed, must be inside keystore structure, NOT a copy of it!
 *
 * \return KNOT_E*
 */
int kdnssec_delete_key(kdnssec_ctx_t *ctx, knot_kasp_key_t *key_ptr);

/*!
 * \brief Load zone keys and init cryptographic context.
 *
 * \param ctx            Zone signing context.
 * \param keyset_ptr     Resulting zone keyset.
 * \param verbose        Print key summary into log.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int load_zone_keys(kdnssec_ctx_t *ctx, zone_keyset_t *keyset_ptr, bool verbose);

/*!
 * \brief Get zone keys by a keytag.
 *
 * \param keyset  Zone keyset.
 * \param search  Keytag to lookup a key for.
 *
 * \return Dynarray of pointers to keys.
 */
struct keyptr_dynarray get_zone_keys(const zone_keyset_t *keyset, uint16_t search);

/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 *
 * \param keyset  Zone keys.
 */
void free_zone_keys(zone_keyset_t *keyset);

/*!
 * \brief Get timestamp of next key event.
 *
 * \param keyset  Zone keys.
 *
 * \return Timestamp of next key event.
 */
knot_time_t knot_get_next_zone_key_event(const zone_keyset_t *keyset);

/*!
 * \brief Returns DS record rdata for given key.
 *
 * This function caches the results, so caaling again with the same key returns immediately.
 *
 * \param for_key The key to compute DS for.
 * \param out_donotfree Output: the DS record rdata. Do not call dnssec_binry_free() on this ever.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int zone_key_calculate_ds(zone_key_t *for_key, dnssec_binary_t *out_donotfree);
