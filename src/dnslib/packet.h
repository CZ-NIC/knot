/*!
 * \file packet.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Functions for manipulating and parsing raw data in DNS packets.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _CUTEDNS_DNSLIB_PACKET_H_
#define _CUTEDNS_DNSLIB_PACKET_H_

#include <stdint.h>

enum dnslib_packet_offsets {
	OFFSET_ID = 0,
	OFFSET_FLAGS1 = 2,
	OFFSET_FLAGS2 = 3,
	OFFSET_QDCOUNT = 4,
	OFFSET_ANCOUNT = 6,
	OFFSET_NSCOUNT = 8,
	OFFSET_ARCOUNT = 10
};

/*
 * Writing / reading arbitrary data to / from wireformat.
 */

static inline uint16_t wire_read_u16(const uint8_t *pos)
{
	return (pos[0] << 8) | pos[1];
}

static inline uint16_t wire_read_u32(const uint8_t *pos)
{
	return (pos[0] << 24) | (pos[1] << 16) | (pos[2] << 8) | pos[3];
}

static inline void wire_write_u16(uint8_t *pos, uint16_t data)
{
	pos[0] = (uint8_t)((data >> 8) & 0xff);
	pos[1] = (uint8_t)(data & 0xff);
}

static inline void wire_write_u32(uint8_t *pos, uint32_t data)
{
	pos[0] = (uint8_t)((data >> 24) & 0xff);
	pos[0] = (uint8_t)((data >> 16) & 0xff);
	pos[2] = (uint8_t)((data >> 8) & 0xff);
	pos[3] = (uint8_t)(data & 0xff);
}

/*
 * Packet header manipulation functions.
 */

static inline uint16_t dnslib_packet_get_id(const uint8_t *packet)
{
	return wire_read_u16(packet + OFFSET_ID);
}

static inline void dnslib_packet_set_id(uint8_t *packet, uint16_t id)
{
	wire_write_u16(packet + OFFSET_ID, id);
}

static inline uint8_t dnslib_packet_get_flags1(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS1);
}

static inline uint8_t dnslib_packet_set_flags1(uint8_t *packet, uint8_t flags1)
{
	return *(packet + OFFSET_FLAGS1) = flags1;
}

static inline uint8_t dnslib_packet_get_flags2(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS2);
}

static inline uint8_t dnslib_packet_set_flags2(uint8_t *packet, uint8_t flags2)
{
	return *(packet + OFFSET_FLAGS2) = flags2;
}

static inline uint16_t dnslib_packet_get_qdcount(const uint8_t *packet)
{
	return wire_read_u16(packet + OFFSET_QDCOUNT);
}

static inline void dnslib_packet_set_qdcount(uint8_t *packet, uint16_t qdcount)
{
	wire_write_u16(packet + OFFSET_QDCOUNT, qdcount);
}

static inline uint16_t dnslib_packet_get_ancount(const uint8_t *packet)
{
	return wire_read_u16(packet + OFFSET_ANCOUNT);
}

static inline void dnslib_packet_set_ancount(uint8_t *packet, uint16_t ancount)
{
	wire_write_u16(packet + OFFSET_ANCOUNT, ancount);
}

static inline uint16_t dnslib_packet_get_nscount(const uint8_t *packet)
{
	return wire_read_u16(packet + OFFSET_NSCOUNT);
}

static inline void dnslib_packet_set_nscount(uint8_t *packet, uint16_t nscount)
{
	wire_write_u16(packet + OFFSET_NSCOUNT, nscount);
}

static inline uint16_t dnslib_packet_get_arcount(const uint8_t *packet)
{
	return wire_read_u16(packet + OFFSET_ARCOUNT);
}

static inline void dnslib_packet_set_arcount(uint8_t *packet, uint16_t arcount)
{
	wire_write_u16(packet + OFFSET_ARCOUNT, arcount);
}

/*
 * Packet header flags manipulation functions.
 */

enum dnslib_packet_flags1_consts {
	RD_MASK = (uint8_t)0x01U,
	RD_SHIFT = 0,
	TC_MASK = (uint8_t)0x02U,
	TC_SHIFT = 1,
	AA_MASK = (uint8_t)0x04U,
	AA_SHIFT = 2,
	OPCODE_MASK = (uint8_t)0x78U,
	OPCODE_SHIFT = 3,
	QR_MASK = (uint8_t)0x80U,
	QR_SHIFT = 7
};

enum dnslib_packet_flags2_consts {
	RCODE_MASK = (uint8_t)0x0fU,
	RCODE_SHIFT = 0,
	CD_MASK = (uint8_t)0x10U,
	CD_SHIFT = 4,
	AD_MASK = (uint8_t)0x20U,
	AD_SHIFT = 5,
	Z_MASK = (uint8_t)0x40U,
	Z_SHIFT = 6,
	RA_MASK = (uint8_t)0x80U,
	RA_SHIFT = 7
};

static inline uint8_t dnslib_packet_get_rd(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS1) & RD_MASK;
}

static inline void dnslib_packet_set_rd(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS1) |= RD_MASK;
}

static inline void dnslib_packet_flags_clear_rd(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS1) &= ~RD_MASK;
}

static inline uint8_t dnslib_packet_get_tc(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS1) & TC_MASK;
}

static inline void dnslib_packet_set_tc(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS1) |= TC_MASK;
}

static inline void dnslib_packet_clear_tc(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS1) &= ~TC_MASK;
}

static inline uint8_t dnslib_packet_get_aa(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS1) & AA_MASK;
}

static inline void dnslib_packet_set_aa(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS1) |= AA_MASK;
}

static inline void dnslib_packet_clear_aa(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS1) &= ~AA_MASK;
}

static inline uint8_t dnslib_packet_get_opcode(const uint8_t *packet)
{
	return (*(packet + OFFSET_FLAGS1) & OPCODE_MASK) >> OPCODE_SHIFT;
}

static inline void dnslib_packet_set_opcode(uint8_t *packet, short opcode)
{
	uint8_t *flags1 = packet + OFFSET_FLAGS1;
	*flags1 = (*flags1 & ~OPCODE_MASK) | ((opcode) << OPCODE_SHIFT);
}

static inline uint8_t dnslib_packet_get_qr(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS1) & QR_MASK;
}

static inline void dnslib_packet_set_qr(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS1) |= QR_MASK;
}

static inline void dnslib_packet_clear_qr(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS1) &= ~QR_MASK;
}

static inline uint8_t dnslib_packet_get_rcode(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS2) & RCODE_MASK;
}

static inline void dnslib_packet_set_rcode(uint8_t *packet, short rcode)
{
	uint8_t *flags1 = packet + OFFSET_FLAGS2;
	*flags1 = (*flags1 & ~RCODE_MASK) | (rcode);
}

static inline uint8_t dnslib_packet_get_cd(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS2) & CD_MASK;
}

static inline void dnslib_packet_set_cd(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS2) |= CD_MASK;
}

static inline void dnslib_packet_clear_cd(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS2) &= ~CD_MASK;
}

static inline uint8_t dnslib_packet_get_ad(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS2) & AD_MASK;
}

static inline void dnslib_packet_set_ad(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS2) |= AD_MASK;
}

static inline void dnslib_packet_clear_ad(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS2) &= ~AD_MASK;
}

static inline uint8_t dnslib_packet_get_z(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS2) & Z_MASK;
}

static inline void dnslib_packet_set_z(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS2) |= Z_MASK;
}

static inline void dnslib_packet_clear_z(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS2) &= ~Z_MASK;
}

static inline uint8_t dnslib_packet_get_ra(const uint8_t *packet)
{
	return *(packet + OFFSET_FLAGS2) & RA_MASK;
}

static inline void dnslib_packet_set_ra(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS2) |= RA_MASK;
}

static inline void dnslib_packet_clear_ra(uint8_t *packet)
{
	*(packet + OFFSET_FLAGS2) &= ~RA_MASK;
}

#endif /* _CUTEDNS_DNSLIB_PACKET_H_ */

/*! @} */
