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
/*!
 * \brief Structure representing the NSEC3PARAM resource record.
 */
struct dnslib_nsec3_params {
	uint8_t algorithm;    /*!< Hash algorithm. */
	uint8_t flags;        /*!< Flags. */
	uint16_t iterations;  /*!< Additional iterations of the hash function.*/
	uint8_t salt_length;  /*!< Length of the salt field in bytes. */
	uint8_t *salt;        /*!< Salt used in hashing. */
};

typedef struct dnslib_nsec3_params dnslib_nsec3_params_t;

/*----------------------------------------------------------------------------*/
/*!
 * \param Initializes the NSEC3PARAM structure.
 *
 * \param params NSEC3PARAM structure to initialize.
 * \param nsec3param The NSEC3PARAM RRset.
 *
 * \retval DNSLIB_EOK on success (always).
 */
int dnslib_nsec3_params_from_wire(dnslib_nsec3_params_t *params,
                                  const dnslib_rrset_t *nsec3param);

/*!
 * \brief Hashes the given data using the SHA1 hash and the given parameters.
 *
 * \param[in] params NSEC3PARAM structure with the required parameters for
 *                   hashing.
 * \param[in] data Data to hash.
 * \param[in] size Size of the data in bytes.
 * \param[out] digest Result will be store here.
 * \param[out] digest_size Size of the result in octets will be stored here.
 *
 * \retval DNSLIB_EOK if successful.
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ECRYPTO
 */
int dnslib_nsec3_sha1(const dnslib_nsec3_params_t *params, const uint8_t *data,
                      size_t size, uint8_t **digest, size_t *digest_size);

/*!
 * \brief Properly cleans up (but does not deallocate) the NSEC3PARAM structure.
 *
 * \param params NSEC3PARAMS structure to clean up.
 */
void dnslib_nsec3_params_free(dnslib_nsec3_params_t *params);

/*----------------------------------------------------------------------------*/

#endif /* _KNOT_DNSLIB_NSEC3_H_ */

/*! @} */
