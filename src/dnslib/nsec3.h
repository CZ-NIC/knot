/*!
 * \file nsec3.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Functions for calcularing NSEC3 hashes.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_NSEC3_H_
#define _KNOT_DNSLIB_NSEC3_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/rrset.h"

#define DNSLIB_NSEC3_SHA_USE_EVP 0

/*----------------------------------------------------------------------------*/

struct dnslib_nsec3_params {
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	uint8_t salt_length;
	uint8_t *salt;
};

typedef struct dnslib_nsec3_params dnslib_nsec3_params_t;

/*----------------------------------------------------------------------------*/

int dnslib_nsec3_params_from_wire(dnslib_nsec3_params_t *params,
                                  const dnslib_rrset_t *nsec3param);

int dnslib_nsec3_sha1(const dnslib_nsec3_params_t *params, const uint8_t *data,
                      size_t size, uint8_t **digest, size_t *digest_size);

void dnslib_nsec3_params_free(dnslib_nsec3_params_t *params);

/*----------------------------------------------------------------------------*/

#endif /* _KNOT_DNSLIB_NSEC3_H_ */

/*! @} */
