#pragma once

#include "zone.h"

/*!
 * KASP store API implementation.
 */
typedef struct dnssec_kasp_store_functions {
	// internal context initialization
	int (*open)(void **ctx_ptr, const char *config);
	void (*close)(void *ctx);
	// zone serialization/deserialization
	int (*load_zone)(dnssec_kasp_zone_t *zone, void *ctx);
	int (*save_zone)(dnssec_kasp_zone_t *zone, void *ctx);
} dnssec_kasp_store_functions_t;

/*!
 * DNSSEC KASP reference.
 */
struct dnssec_kasp {
	const dnssec_kasp_store_functions_t *functions;
	void *ctx;
};

int dnssec_kasp_create(dnssec_kasp_t **kasp_ptr,
                       const dnssec_kasp_store_functions_t *functions,
                       const char *open_config);
