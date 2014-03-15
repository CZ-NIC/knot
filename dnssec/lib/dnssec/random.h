#pragma once

#include <stdint.h>
#include <dnssec/binary.h>

/*!
 * Fill a buffer with pseudo-random data.
 *
 * \param data  Pointer to the output buffer.
 * \param size  Size of the output buffer.
 *
 * \return Error code, DNSEC_EOK if successful.
 */
int dnssec_random_buffer(uint8_t *data, size_t size);

/*!
 * Fill a binary structure with random data.
 *
 * \param data  Preallocated binary structure to be filled..
 *
 * \return Error code, DNSEC_EOK if successful.
 */
int dnssec_random_binary(dnssec_binary_t *data);

/*!
 * \brief Declare function dnssec_random_<type>().
 */
#define dnssec_register_random_type(type) \
	static inline type dnssec_random_##type(void) { \
		type value; \
		dnssec_random_buffer((uint8_t *)&value, sizeof(value)); \
		return value; \
	}

dnssec_register_random_type(uint16_t);
dnssec_register_random_type(uint32_t);
