#pragma once

#include <dnssec/key.h>
#include <time.h>

struct dnssec_kasp;
typedef struct dnssec_kasp dnssec_kasp_t;

struct dnssec_kasp_zone;
typedef struct dnssec_kasp_zone dnssec_kasp_zone_t;

struct dnssec_kasp_policy;
typedef struct dnssec_kasp_policy dnssec_kasp_policy_t;

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

struct dnssec_kasp_event;
typedef struct dnssec_kasp_event dnssec_kasp_event_t;

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

int dnssec_kasp_get_zone(dnssec_kasp_t *kasp, const char *zone_name,
			 dnssec_kasp_zone_t **zone);

void dnssec_kasp_free_zone(dnssec_kasp_zone_t *zone);
