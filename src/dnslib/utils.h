/*!
 * \file utils.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Various utilities.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _CUTEDNS_DNSLIB_UTILS_H_
#define _CUTEDNS_DNSLIB_UTILS_H_

#include <stdint.h>

/*
 * Writing / reading arbitrary data to / from wireformat.
 */

static inline uint16_t dnslib_wire_read_u16(const uint8_t *pos)
{
	return (pos[0] << 8) | pos[1];
}

static inline uint16_t dnslib_wire_read_u32(const uint8_t *pos)
{
	return (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
}

static inline void dnslib_wire_write_u16(uint8_t *pos, uint16_t data)
{
	pos[0] = (uint8_t)((data >> 8) & 0xff);
	pos[1] = (uint8_t)(data & 0xff);
}

static inline void dnslib_wire_write_u32(uint8_t *pos, uint32_t data)
{
	pos[0] = (uint8_t)((data >> 24) & 0xff);
	pos[0] = (uint8_t)((data >> 16) & 0xff);
	pos[2] = (uint8_t)((data >> 8) & 0xff);
	pos[3] = (uint8_t)(data & 0xff);
}

#endif /* _CUTEDNS_DNSLIB_UTILS_H_ */

/*! @} */

