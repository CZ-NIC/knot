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
#include <assert.h>

#include "utils.h"

enum dnslib_packet_offsets {
	DNSLIB_PACKET_OFFSET_ID = 0,
	DNSLIB_PACKET_OFFSET_FLAGS1 = 2,
	DNSLIB_PACKET_OFFSET_FLAGS2 = 3,
	DNSLIB_PACKET_OFFSET_QDCOUNT = 4,
	DNSLIB_PACKET_OFFSET_ANCOUNT = 6,
	DNSLIB_PACKET_OFFSET_NSCOUNT = 8,
	DNSLIB_PACKET_OFFSET_ARCOUNT = 10
};

enum dnslib_packet_sizes {
	DNSLIB_PACKET_HEADER_SIZE = 12,
	DNSLIB_PACKET_QUESTION_MIN_SIZE = 5,
	DNSLIB_PACKET_RR_MIN_SIZE = 11
};

/*
 * Packet header manipulation functions.
 */

static inline uint16_t dnslib_packet_get_id(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_ID);
}

static inline void dnslib_packet_set_id(uint8_t *packet, uint16_t id)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_ID, id);
}

static inline uint8_t dnslib_packet_get_flags1(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1);
}

static inline uint8_t dnslib_packet_set_flags1(uint8_t *packet, uint8_t flags1)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) = flags1;
}

static inline uint8_t dnslib_packet_get_flags2(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2);
}

static inline uint8_t dnslib_packet_set_flags2(uint8_t *packet, uint8_t flags2)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) = flags2;
}

static inline uint16_t dnslib_packet_get_qdcount(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_QDCOUNT);
}

static inline void dnslib_packet_set_qdcount(uint8_t *packet, uint16_t qdcount)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_QDCOUNT, qdcount);
}

static inline uint16_t dnslib_packet_get_ancount(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_ANCOUNT);
}

static inline void dnslib_packet_set_ancount(uint8_t *packet, uint16_t ancount)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_ANCOUNT, ancount);
}

static inline uint16_t dnslib_packet_get_nscount(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_NSCOUNT);
}

static inline void dnslib_packet_set_nscount(uint8_t *packet, uint16_t nscount)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_NSCOUNT, nscount);
}

static inline uint16_t dnslib_packet_get_arcount(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_ARCOUNT);
}

static inline void dnslib_packet_set_arcount(uint8_t *packet, uint16_t arcount)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_ARCOUNT, arcount);
}

/*
 * Packet header flags manipulation functions.
 */

enum dnslib_packet_flags1_consts {
	DNSLIB_PACKET_RD_MASK = (uint8_t)0x01U,
	DNSLIB_PACKET_RD_SHIFT = 0,
	DNSLIB_PACKET_TC_MASK = (uint8_t)0x02U,
	DNSLIB_PACKET_TC_SHIFT = 1,
	DNSLIB_PACKET_AA_MASK = (uint8_t)0x04U,
	DNSLIB_PACKET_AA_SHIFT = 2,
	DNSLIB_PACKET_OPCODE_MASK = (uint8_t)0x78U,
	DNSLIB_PACKET_OPCODE_SHIFT = 3,
	DNSLIB_PACKET_QR_MASK = (uint8_t)0x80U,
	DNSLIB_PACKET_QR_SHIFT = 7
};

enum dnslib_packet_flags2_consts {
	DNSLIB_PACKET_RCODE_MASK = (uint8_t)0x0fU,
	DNSLIB_PACKET_RCODE_SHIFT = 0,
	DNSLIB_PACKET_CD_MASK = (uint8_t)0x10U,
	DNSLIB_PACKET_CD_SHIFT = 4,
	DNSLIB_PACKET_AD_MASK = (uint8_t)0x20U,
	DNSLIB_PACKET_AD_SHIFT = 5,
	DNSLIB_PACKET_Z_MASK = (uint8_t)0x40U,
	DNSLIB_PACKET_Z_SHIFT = 6,
	DNSLIB_PACKET_RA_MASK = (uint8_t)0x80U,
	DNSLIB_PACKET_RA_SHIFT = 7
};

/*
 * Functions for getting / setting / clearing flags and codes directly in packet
 */

static inline uint8_t dnslib_packet_get_rd(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) & DNSLIB_PACKET_RD_MASK;
}

static inline void dnslib_packet_set_rd(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) |= DNSLIB_PACKET_RD_MASK;
}

static inline void dnslib_packet_flags_clear_rd(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) &= ~DNSLIB_PACKET_RD_MASK;
}

static inline uint8_t dnslib_packet_get_tc(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) & DNSLIB_PACKET_TC_MASK;
}

static inline void dnslib_packet_set_tc(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) |= DNSLIB_PACKET_TC_MASK;
}

static inline void dnslib_packet_clear_tc(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) &= ~DNSLIB_PACKET_TC_MASK;
}

static inline uint8_t dnslib_packet_get_aa(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) & DNSLIB_PACKET_AA_MASK;
}

static inline void dnslib_packet_set_aa(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) |= DNSLIB_PACKET_AA_MASK;
}

static inline void dnslib_packet_clear_aa(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) &= ~DNSLIB_PACKET_AA_MASK;
}

static inline uint8_t dnslib_packet_get_opcode(const uint8_t *packet)
{
	return (*(packet + DNSLIB_PACKET_OFFSET_FLAGS1)
	        & DNSLIB_PACKET_OPCODE_MASK) >> DNSLIB_PACKET_OPCODE_SHIFT;
}

static inline void dnslib_packet_set_opcode(uint8_t *packet, short opcode)
{
	uint8_t *flags1 = packet + DNSLIB_PACKET_OFFSET_FLAGS1;
	*flags1 = (*flags1 & ~DNSLIB_PACKET_OPCODE_MASK)
	          | ((opcode) << DNSLIB_PACKET_OPCODE_SHIFT);
}

static inline uint8_t dnslib_packet_get_qr(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) & DNSLIB_PACKET_QR_MASK;
}

static inline void dnslib_packet_set_qr(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) |= DNSLIB_PACKET_QR_MASK;
}

static inline void dnslib_packet_clear_qr(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) &= ~DNSLIB_PACKET_QR_MASK;
}

static inline uint8_t dnslib_packet_get_rcode(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2)
	       & DNSLIB_PACKET_RCODE_MASK;
}

static inline void dnslib_packet_set_rcode(uint8_t *packet, short rcode)
{
	uint8_t *flags2 = packet + DNSLIB_PACKET_OFFSET_FLAGS2;
	*flags2 = (*flags2 & ~DNSLIB_PACKET_RCODE_MASK) | (rcode);
}

static inline uint8_t dnslib_packet_get_cd(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) & DNSLIB_PACKET_CD_MASK;
}

static inline void dnslib_packet_set_cd(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) |= DNSLIB_PACKET_CD_MASK;
}

static inline void dnslib_packet_clear_cd(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) &= ~DNSLIB_PACKET_CD_MASK;
}

static inline uint8_t dnslib_packet_get_ad(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) & DNSLIB_PACKET_AD_MASK;
}

static inline void dnslib_packet_set_ad(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) |= DNSLIB_PACKET_AD_MASK;
}

static inline void dnslib_packet_clear_ad(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) &= ~DNSLIB_PACKET_AD_MASK;
}

static inline uint8_t dnslib_packet_get_z(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) & DNSLIB_PACKET_Z_MASK;
}

static inline void dnslib_packet_set_z(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) |= DNSLIB_PACKET_Z_MASK;
}

static inline void dnslib_packet_clear_z(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) &= ~DNSLIB_PACKET_Z_MASK;
}

static inline uint8_t dnslib_packet_get_ra(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) & DNSLIB_PACKET_RA_MASK;
}

static inline void dnslib_packet_set_ra(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) |= DNSLIB_PACKET_RA_MASK;
}

static inline void dnslib_packet_clear_ra(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) &= ~DNSLIB_PACKET_RA_MASK;
}

/*
 * Functions for getting / setting / clearing flags in flags variable
 */

static inline uint8_t dnslib_packet_flags_get_rd(uint8_t flags1)
{
	return flags1 & DNSLIB_PACKET_RD_MASK;
}

static inline void dnslib_packet_flags_set_rd(uint8_t *flags1)
{
	*flags1 |= DNSLIB_PACKET_RD_MASK;
}

static inline void dnslib_packet_flags_flags_clear_rd(uint8_t *flags1)
{
	*flags1 &= ~DNSLIB_PACKET_RD_MASK;
}

static inline uint8_t dnslib_packet_flags_get_tc(uint8_t flags1)
{
	return flags1 & DNSLIB_PACKET_TC_MASK;
}

static inline void dnslib_packet_flags_set_tc(uint8_t *flags1)
{
	*flags1 |= DNSLIB_PACKET_TC_MASK;
}

static inline void dnslib_packet_flags_clear_tc(uint8_t *flags1)
{
	*flags1 &= ~DNSLIB_PACKET_TC_MASK;
}

static inline uint8_t dnslib_packet_flags_get_aa(uint8_t flags1)
{
	return flags1 & DNSLIB_PACKET_AA_MASK;
}

static inline void dnslib_packet_flags_set_aa(uint8_t *flags1)
{
	*flags1 |= DNSLIB_PACKET_AA_MASK;
}

static inline void dnslib_packet_flags_clear_aa(uint8_t *flags1)
{
	*flags1 &= ~DNSLIB_PACKET_AA_MASK;
}

static inline uint8_t dnslib_packet_flags_get_opcode(uint8_t flags1)
{
	return (flags1 & DNSLIB_PACKET_OPCODE_MASK)
	        >> DNSLIB_PACKET_OPCODE_SHIFT;
}

static inline void dnslib_packet_flags_set_opcode(uint8_t *flags1, short opcode)
{
	*flags1 = (*flags1 & ~DNSLIB_PACKET_OPCODE_MASK)
	          | ((opcode) << DNSLIB_PACKET_OPCODE_SHIFT);
}

static inline uint8_t dnslib_packet_flags_get_qr(uint8_t flags1)
{
	return flags1 & DNSLIB_PACKET_QR_MASK;
}

static inline void dnslib_packet_flags_set_qr(uint8_t *flags1)
{
	*flags1 |= DNSLIB_PACKET_QR_MASK;
}

static inline void dnslib_packet_flags_clear_qr(uint8_t *flags1)
{
	*flags1 &= ~DNSLIB_PACKET_QR_MASK;
}

static inline uint8_t dnslib_packet_flags_get_rcode(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_RCODE_MASK;
}

static inline void dnslib_packet_flags_set_rcode(uint8_t *flags2, short rcode)
{
	*flags2 = (*flags2 & ~DNSLIB_PACKET_RCODE_MASK) | (rcode);
}

static inline uint8_t dnslib_packet_flags_get_cd(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_CD_MASK;
}

static inline void dnslib_packet_flags_set_cd(uint8_t *flags2)
{
	*flags2 |= DNSLIB_PACKET_CD_MASK;
}

static inline void dnslib_packet_flags_clear_cd(uint8_t *flags2)
{
	*flags2 &= ~DNSLIB_PACKET_CD_MASK;
}

static inline uint8_t dnslib_packet_flags_get_ad(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_AD_MASK;
}

static inline void dnslib_packet_flags_set_ad(uint8_t *flags2)
{
	*flags2 |= DNSLIB_PACKET_AD_MASK;
}

static inline void dnslib_packet_flags_clear_ad(uint8_t *flags2)
{
	*flags2 &= ~DNSLIB_PACKET_AD_MASK;
}

static inline uint8_t dnslib_packet_flags_get_z(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_Z_MASK;
}

static inline void dnslib_packet_flags_set_z(uint8_t *flags2)
{
	*flags2 |= DNSLIB_PACKET_Z_MASK;
}

static inline void dnslib_packet_flags_clear_z(uint8_t *flags2)
{
	*flags2 &= ~DNSLIB_PACKET_Z_MASK;
}

static inline uint8_t dnslib_packet_flags_get_ra(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_RA_MASK;
}

static inline void dnslib_packet_flags_set_ra(uint8_t *flags2)
{
	*flags2 |= DNSLIB_PACKET_RA_MASK;
}

static inline void dnslib_packet_flags_clear_ra(uint8_t *flags2)
{
	*flags2 &= ~DNSLIB_PACKET_RA_MASK;
}

/*
 * Pointer manipulation
 */

enum dnslib_packet_pointer_consts {
	DNSLIB_PACKET_PTR = (uint8_t)0xc0U
};

static inline void dnslib_packet_put_pointer(uint8_t *pos, short ptr)
{
	uint16_t p = ptr;
	dnslib_wire_write_u16(pos, p);
	assert((pos[0] & DNSLIB_PACKET_PTR) == 0);
	pos[0] |= DNSLIB_PACKET_PTR;
}

#endif /* _CUTEDNS_DNSLIB_PACKET_H_ */

/*! @} */
