#pragma once

#include <dnssec/key.h>
#include <time.h>

/*
 * KASP
 */

struct dnssec_kasp;
typedef struct dnssec_kasp dnssec_kasp_t;

/*!
 * Open default dir store for KASP.
 *
 * \param[in]  path   Path to the KASP storage.
 * \param[out] store  Pointer to KASP store instance.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_kasp_open_dir(const char *path, dnssec_kasp_t **kasp);

/*!
 * Close KASP store.
 *
 * \param store  KASP store to be closed.
 */
void dnssec_kasp_close(dnssec_kasp_t *kasp);

/*
 * ZONE
 */

struct dnssec_kasp_zone;
typedef struct dnssec_kasp_zone dnssec_kasp_zone_t;

dnssec_kasp_zone_t *dnssec_kasp_zone_new(const char *name);

void dnssec_kasp_zone_free(dnssec_kasp_zone_t *zone);

int dnssec_kasp_load_zone(dnssec_kasp_t *kasp, const char *zone_name,
			  dnssec_kasp_zone_t **zone);

int dnssec_kasp_save_zone(dnssec_kasp_t *kasp, dnssec_kasp_zone_t *zone);

/*
 * POLICY
 */

struct dnssec_kasp_policy;
typedef struct dnssec_kasp_policy dnssec_kasp_policy_t;

/*
 * EVENT
 */

struct dnssec_kasp_event;
typedef struct dnssec_kasp_event dnssec_kasp_event_t;

/*
 * KEY
 */

typedef struct dnssec_kasp_key_timing {
	time_t publish;
	time_t active;
	time_t retire;
	time_t remove;
} dnssec_kasp_key_timing_t;

typedef struct dnssec_kasp_key {
	dnssec_key_t *key;
	dnssec_kasp_key_timing_t timing;
} dnssec_kasp_key_t;

/*
 * KEYSETS
 */

struct dnssec_kasp_keyset;
typedef struct dnssec_kasp_keyset dnssec_kasp_keyset_t;

void dnssec_kasp_keyset_init(dnssec_kasp_keyset_t *keys);
dnssec_kasp_keyset_t *dnssec_kasp_keyset_new(void);
void dnssec_kasp_keyset_free(dnssec_kasp_keyset_t *keyset);

size_t dnssec_kasp_keyset_count(dnssec_kasp_keyset_t *keys);
int dnssec_kasp_keyset_add(dnssec_kasp_keyset_t *keys, dnssec_kasp_key_t *key);
int dnssec_kasp_keyset_remove(dnssec_kasp_keyset_t *keys, dnssec_kasp_key_t *key);
void dnssec_kasp_keyset_empty(dnssec_kasp_keyset_t *keys);
dnssec_kasp_key_t *dnssec_kasp_keyset_at(dnssec_kasp_keyset_t *keys, size_t number);

dnssec_kasp_keyset_t *dnssec_kasp_zone_get_keys(dnssec_kasp_zone_t *zone);
