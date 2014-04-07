#pragma once

#include <dnssec/key.h>
#include <time.h>

struct dnssec_kasp;
typedef struct dnssec_kasp dnssec_kasp_t;

typedef struct dnssec_kasp_key {

	dnssec_key_t *key;

	time_t publish;
	time_t active;
	time_t retire;
	time_t remove;

} dnssec_kasp_key_t;

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

/*!
 * Get keys for given zone.
 *
 * \param[in]  kasp   KASP.
 * \param[in]  zone   Name of the zone.
 * \param[out] keys   Zone keys.
 * \param[out] count  Number of the keys.
 */
int dnssec_kasp_get_keys(dnssec_kasp_t *kasp, const char *zone,
			 dnssec_kasp_key_t *keys, size_t *count);
