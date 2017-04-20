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
/*!
 * \file zone-keys.h
 *
 * \brief Loading of zone keys.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "contrib/dynarray.h"
#include "dnssec/keystore.h"
#include "dnssec/sign.h"

#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/dnssec/kasp/policy.h"
#include "knot/dnssec/context.h"

/*!
 * \brief Zone key context used during signing.
 */
struct zone_key {
	const char *id;
	dnssec_key_t *key;
	dnssec_sign_ctx_t *ctx;

	dnssec_binary_t precomputed_ds;

	time_t next_event;

	bool is_ksk;
	bool is_zsk;
	bool is_active;
	bool is_public;
	bool is_ready;
};

typedef struct zone_key zone_key_t;

dynarray_declare(keyptr, zone_key_t *, DYNARRAY_VISIBILITY_PUBLIC, 1)

struct zone_keyset {
	size_t count;
	zone_key_t *keys;
};

typedef struct zone_keyset zone_keyset_t;

/*!
 * \brief Flags determining key type
 */
extern const uint16_t DNSKEY_FLAGS_KSK;
extern const uint16_t DNSKEY_FLAGS_ZSK;
uint16_t dnskey_flags(bool is_ksk);

/*!
 * \brief Generate new key, store all details in new kasp key structure.
 *
 * \param ctx           kasp context
 * \param ksk           true = generate KSK, false = generate ZSK
 * \param key_ptr       output if KNOT_EOK: new pointer to generated key
 *
 * \return KNOT_E*
 */
int kdnssec_generate_key(kdnssec_ctx_t *ctx, bool ksk, knot_kasp_key_t **key_ptr);

/*
 * TODO comment
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
 * \param zone           KASP zone.
 * \param keystore       KASP key store.
 * \param nsec3_enabled  Zone uses NSEC3 for authenticated denial.
 * \param now            Current time.
 * \param keyset         Resulting zone keyset.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int load_zone_keys(knot_kasp_zone_t *zone, dnssec_keystore_t *store,
                   bool nsec3_enabled, time_t now, zone_keyset_t *keyset_ptr);

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
 * \param keys    Zone keys.
 */
void free_zone_keys(zone_keyset_t *keyset);

/*!
 * \brief Get timestamp of next key event.
 *
 * \param keys  Zone keys.
 *
 * \return Timestamp of next key event.
 */
time_t knot_get_next_zone_key_event(const zone_keyset_t *keyset);

/*!
 * \todo this comment (needed?)
 */
int zone_key_calculate_ds(zone_key_t *for_key, dnssec_binary_t *out_donotfree);

/*! @} */
