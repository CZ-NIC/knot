/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file
 *
 * \brief Functions for manipulating and parsing raw data in DNS packets.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include "libknot/attribute.h"

/*! \brief Offset of DNS header fields in wireformat. */
enum knot_wire_offsets {
	KNOT_WIRE_OFFSET_ID = 0,
	KNOT_WIRE_OFFSET_FLAGS1 = 2,
	KNOT_WIRE_OFFSET_FLAGS2 = 3,
	KNOT_WIRE_OFFSET_QDCOUNT = 4,
	KNOT_WIRE_OFFSET_ANCOUNT = 6,
	KNOT_WIRE_OFFSET_NSCOUNT = 8,
	KNOT_WIRE_OFFSET_ARCOUNT = 10
};

/*! \brief Minimum size for some parts of the DNS packet. */
enum knot_wire_sizes {
	KNOT_WIRE_HEADER_SIZE = 12,
	KNOT_WIRE_QUESTION_MIN_SIZE = 5,
	KNOT_WIRE_RR_MIN_SIZE = 11,
	KNOT_WIRE_MIN_PKTSIZE = 512,
	KNOT_WIRE_MAX_PKTSIZE = 65535,
	KNOT_WIRE_MAX_PAYLOAD = KNOT_WIRE_MAX_PKTSIZE
	                        - KNOT_WIRE_HEADER_SIZE
	                        - KNOT_WIRE_QUESTION_MIN_SIZE
};

/*
 * Packet header manipulation functions.
 */

/*!
 * \brief Returns the ID from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return DNS packet ID.
 */
uint16_t knot_wire_get_id(const uint8_t *packet);

/*!
 * \brief Sets the ID to the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param id DNS packet ID.
 */
void knot_wire_set_id(uint8_t *packet, uint16_t id);

/*!
 * \brief Returns the first byte of flags from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return First byte of DNS flags.
 */
static inline uint8_t knot_wire_get_flags1(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS1);
}

/*!
 * \brief Sets the first byte of flags to the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param flags1 First byte of the DNS flags.
 */
static inline uint8_t knot_wire_set_flags1(uint8_t *packet, uint8_t flags1)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS1) = flags1;
}

/*!
 * \brief Returns the second byte of flags from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Second byte of DNS flags.
 */
static inline uint8_t knot_wire_get_flags2(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS2);
}

/*!
 * \brief Sets the second byte of flags to the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param flags2 Second byte of the DNS flags.
 */
static inline uint8_t knot_wire_set_flags2(uint8_t *packet, uint8_t flags2)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS2) = flags2;
}

/*!
 * \brief Returns the QDCOUNT (count of Question entries) from wire format of
 *        the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return QDCOUNT (count of Question entries in the packet).
 */
uint16_t knot_wire_get_qdcount(const uint8_t *packet);

/*!
 * \brief Sets the QDCOUNT (count of Question entries) to wire format of the
 *        packet.
 *
 * \param packet Wire format of the packet.
 * \param qdcount QDCOUNT (count of Question entries in the packet).
 */
void knot_wire_set_qdcount(uint8_t *packet, uint16_t qdcount);

/*!
 * \brief Adds to QDCOUNT.
 */
void knot_wire_add_qdcount(uint8_t *packet, int16_t n);

/*!
 * \brief Returns the ANCOUNT (count of Answer entries) from wire format of
 *        the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return ANCOUNT (count of Answer entries in the packet).
 */
uint16_t knot_wire_get_ancount(const uint8_t *packet);

/*!
 * \brief Sets the ANCOUNT (count of Answer entries) to wire format of the
 *        packet.
 *
 * \param packet Wire format of the packet.
 * \param ancount ANCOUNT (count of Answer entries in the packet).
 */
void knot_wire_set_ancount(uint8_t *packet, uint16_t ancount);

/*!
 * \brief Adds to ANCOUNT.
 */
void knot_wire_add_ancount(uint8_t *packet, int16_t n);

/*!
 * \brief Returns the NSCOUNT (count of Authority entries) from wire format of
 *        the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return NSCOUNT (count of Authority entries in the packet).
 */
uint16_t knot_wire_get_nscount(const uint8_t *packet);

/*!
 * \brief Sets the NSCOUNT (count of Authority entries) to wire format of the
 *        packet.
 *
 * \param packet Wire format of the packet.
 * \param nscount NSCOUNT (count of Authority entries in the packet).
 */
void knot_wire_set_nscount(uint8_t *packet, uint16_t nscount);

/*!
 * \brief Adds to NSCOUNT.
 */
void knot_wire_add_nscount(uint8_t *packet, int16_t n);

/*!
 * \brief Returns the ARCOUNT (count of Additional entries) from wire format of
 *        the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return ARCOUNT (count of Additional entries in the packet).
 */
uint16_t knot_wire_get_arcount(const uint8_t *packet);

/*!
 * \brief Sets the ARCOUNT (count of Additional entries) to wire format of the
 *        packet.
 *
 * \param packet Wire format of the packet.
 * \param arcount ARCOUNT (count of Additional entries in the packet).
 */
void knot_wire_set_arcount(uint8_t *packet, uint16_t arcount);

/*!
 * \brief Adds to ARCOUNT.
 */
void knot_wire_add_arcount(uint8_t *packet, int16_t n);

/*
 * Packet header flags manipulation functions.
 */
/*! \brief Constants for DNS header flags in the first flags byte. */
enum knot_wire_flags1_consts {
	KNOT_WIRE_RD_MASK = (uint8_t)0x01U,      /*!< RD bit mask. */
	KNOT_WIRE_RD_SHIFT = 0,                  /*!< RD bit shift. */
	KNOT_WIRE_TC_MASK = (uint8_t)0x02U,      /*!< TC bit mask. */
	KNOT_WIRE_TC_SHIFT = 1,                  /*!< TC bit shift. */
	KNOT_WIRE_AA_MASK = (uint8_t)0x04U,      /*!< AA bit mask. */
	KNOT_WIRE_AA_SHIFT = 2,                  /*!< AA bit shift. */
	KNOT_WIRE_OPCODE_MASK = (uint8_t)0x78U,  /*!< OPCODE mask. */
	KNOT_WIRE_OPCODE_SHIFT = 3,              /*!< OPCODE shift. */
	KNOT_WIRE_QR_MASK = (uint8_t)0x80U,      /*!< QR bit mask. */
	KNOT_WIRE_QR_SHIFT = 7                   /*!< QR bit shift. */
};

/*! \brief Constants for DNS header flags in the second flags byte. */
enum knot_wire_flags2_consts {
	KNOT_WIRE_RCODE_MASK = (uint8_t)0x0fU,  /*!< RCODE mask. */
	KNOT_WIRE_RCODE_SHIFT = 0,              /*!< RCODE shift. */
	KNOT_WIRE_CD_MASK = (uint8_t)0x10U,     /*!< CD bit mask. */
	KNOT_WIRE_CD_SHIFT = 4,                 /*!< CD bit shift. */
	KNOT_WIRE_AD_MASK = (uint8_t)0x20U,     /*!< AD bit mask. */
	KNOT_WIRE_AD_SHIFT = 5,                 /*!< AD bit shift. */
	KNOT_WIRE_Z_MASK = (uint8_t)0x40U,      /*!< Zero bit mask. */
	KNOT_WIRE_Z_SHIFT = 6,                  /*!< Zero bit shift. */
	KNOT_WIRE_RA_MASK = (uint8_t)0x80U,     /*!< RA bit mask. */
	KNOT_WIRE_RA_SHIFT = 7                  /*!< RA bit shift. */
};

/*
 * Functions for getting / setting / clearing flags and codes directly in packet
 */

/*!
 * \brief Returns the RD bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the RD bit according to its setting in the packet.
 */
static inline uint8_t knot_wire_get_rd(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS1) & KNOT_WIRE_RD_MASK;
}

/*!
 * \brief Sets the RD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_set_rd(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS1) |= KNOT_WIRE_RD_MASK;
}

/*!
 * \brief Clears the RD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_flags_clear_rd(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS1) &= ~KNOT_WIRE_RD_MASK;
}

/*!
 * \brief Returns the TC bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the TC bit according to its setting in the packet.
 */
static inline uint8_t knot_wire_get_tc(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS1) & KNOT_WIRE_TC_MASK;
}

/*!
 * \brief Sets the TC bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_set_tc(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS1) |= KNOT_WIRE_TC_MASK;
}

/*!
 * \brief Clears the TC bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_clear_tc(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS1) &= ~KNOT_WIRE_TC_MASK;
}

/*!
 * \brief Returns the AA bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the AA bit according to its setting in the packet.
 */
static inline uint8_t knot_wire_get_aa(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS1) & KNOT_WIRE_AA_MASK;
}

/*!
 * \brief Sets the AA bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_set_aa(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS1) |= KNOT_WIRE_AA_MASK;
}

/*!
 * \brief Clears the AA bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_clear_aa(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS1) &= ~KNOT_WIRE_AA_MASK;
}

/*!
 * \brief Returns the OPCODE from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return OPCODE of the packet.
 */
static inline uint8_t knot_wire_get_opcode(const uint8_t *packet)
{
	return (*(packet + KNOT_WIRE_OFFSET_FLAGS1)
	        & KNOT_WIRE_OPCODE_MASK) >> KNOT_WIRE_OPCODE_SHIFT;
}

/*!
 * \brief Sets the OPCODE in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param opcode OPCODE to set.
 */
static inline void knot_wire_set_opcode(uint8_t *packet, short opcode)
{
	uint8_t *flags1 = packet + KNOT_WIRE_OFFSET_FLAGS1;
	*flags1 = (*flags1 & ~KNOT_WIRE_OPCODE_MASK)
	          | ((opcode) << KNOT_WIRE_OPCODE_SHIFT);
}

/*!
 * \brief Returns the QR bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the QR bit according to its setting in the packet.
 */
static inline uint8_t knot_wire_get_qr(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS1) & KNOT_WIRE_QR_MASK;
}

/*!
 * \brief Sets the QR bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_set_qr(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS1) |= KNOT_WIRE_QR_MASK;
}

/*!
 * \brief Clears the QR bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_clear_qr(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS1) &= ~KNOT_WIRE_QR_MASK;
}

/*!
 * \brief Returns the RCODE from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return RCODE of the packet.
 */
static inline uint8_t knot_wire_get_rcode(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS2)
	       & KNOT_WIRE_RCODE_MASK;
}

/*!
 * \brief Sets the RCODE in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param rcode RCODE to set.
 */
static inline void knot_wire_set_rcode(uint8_t *packet, short rcode)
{
	uint8_t *flags2 = packet + KNOT_WIRE_OFFSET_FLAGS2;
	*flags2 = (*flags2 & ~KNOT_WIRE_RCODE_MASK) | (rcode);
}

/*!
 * \brief Returns the CD bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the CD bit according to its setting in the packet.
 */
static inline uint8_t knot_wire_get_cd(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS2) & KNOT_WIRE_CD_MASK;
}

/*!
 * \brief Sets the CD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_set_cd(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS2) |= KNOT_WIRE_CD_MASK;
}

/*!
 * \brief Clears the CD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_clear_cd(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS2) &= ~KNOT_WIRE_CD_MASK;
}

/*!
 * \brief Returns the AD bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the AD bit according to its setting in the packet.
 */
static inline uint8_t knot_wire_get_ad(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS2) & KNOT_WIRE_AD_MASK;
}

/*!
 * \brief Sets the AD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_set_ad(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS2) |= KNOT_WIRE_AD_MASK;
}

/*!
 * \brief Clears the AD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_clear_ad(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS2) &= ~KNOT_WIRE_AD_MASK;
}

/*!
 * \brief Returns the Zero bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the Zero bit according to its setting in the packet.
 */
static inline uint8_t knot_wire_get_z(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS2) & KNOT_WIRE_Z_MASK;
}

/*!
 * \brief Sets the Zero bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_set_z(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS2) |= KNOT_WIRE_Z_MASK;
}

/*!
 * \brief Clears the Zero bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_clear_z(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS2) &= ~KNOT_WIRE_Z_MASK;
}

/*!
 * \brief Returns the RA bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the RA bit according to its setting in the packet.
 */
static inline uint8_t knot_wire_get_ra(const uint8_t *packet)
{
	return *(packet + KNOT_WIRE_OFFSET_FLAGS2) & KNOT_WIRE_RA_MASK;
}

/*!
 * \brief Sets the RA bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_set_ra(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS2) |= KNOT_WIRE_RA_MASK;
}

/*!
 * \brief Clears the RA bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void knot_wire_clear_ra(uint8_t *packet)
{
	*(packet + KNOT_WIRE_OFFSET_FLAGS2) &= ~KNOT_WIRE_RA_MASK;
}

/*
 * Functions for getting / setting / clearing flags in flags variable
 */

/*!
 * \brief Returns the RD bit from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return Flags byte with only the RD bit according to its setting in
 *         \a flags1.
 */
static inline uint8_t knot_wire_flags_get_rd(uint8_t flags1)
{
	return flags1 & KNOT_WIRE_RD_MASK;
}

/*!
 * \brief Sets the RD bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void knot_wire_flags_set_rd(uint8_t *flags1)
{
	*flags1 |= KNOT_WIRE_RD_MASK;
}

/*!
 * \brief Clears the RD bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void knot_wire_flags_flags_clear_rd(uint8_t *flags1)
{
	*flags1 &= ~KNOT_WIRE_RD_MASK;
}

/*!
 * \brief Returns the TC bit from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return Flags byte with only the TC bit according to its setting in
 *         \a flags1.
 */
static inline uint8_t knot_wire_flags_get_tc(uint8_t flags1)
{
	return flags1 & KNOT_WIRE_TC_MASK;
}

/*!
 * \brief Sets the TC bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void knot_wire_flags_set_tc(uint8_t *flags1)
{
	*flags1 |= KNOT_WIRE_TC_MASK;
}

/*!
 * \brief Clears the TC bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void knot_wire_flags_clear_tc(uint8_t *flags1)
{
	*flags1 &= ~KNOT_WIRE_TC_MASK;
}

/*!
 * \brief Returns the AA bit from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return Flags byte with only the AA bit according to its setting in
 *         \a flags1.
 */
static inline uint8_t knot_wire_flags_get_aa(uint8_t flags1)
{
	return flags1 & KNOT_WIRE_AA_MASK;
}

/*!
 * \brief Sets the AA bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void knot_wire_flags_set_aa(uint8_t *flags1)
{
	*flags1 |= KNOT_WIRE_AA_MASK;
}

/*!
 * \brief Clears the AA bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void knot_wire_flags_clear_aa(uint8_t *flags1)
{
	*flags1 &= ~KNOT_WIRE_AA_MASK;
}

/*!
 * \brief Returns the OPCODE from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return OPCODE
 */
static inline uint8_t knot_wire_flags_get_opcode(uint8_t flags1)
{
	return (flags1 & KNOT_WIRE_OPCODE_MASK)
	        >> KNOT_WIRE_OPCODE_SHIFT;
}

/*!
 * \brief Sets the OPCODE in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 * \param opcode OPCODE to set.
 */
static inline void knot_wire_flags_set_opcode(uint8_t *flags1, short opcode)
{
	*flags1 = (*flags1 & ~KNOT_WIRE_OPCODE_MASK)
	          | ((opcode) << KNOT_WIRE_OPCODE_SHIFT);
}

/*!
 * \brief Returns the QR bit from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return Flags byte with only the QR bit according to its setting in
 *         \a flags1.
 */
static inline uint8_t knot_wire_flags_get_qr(uint8_t flags1)
{
	return flags1 & KNOT_WIRE_QR_MASK;
}

/*!
 * \brief Sets the QR bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void knot_wire_flags_set_qr(uint8_t *flags1)
{
	*flags1 |= KNOT_WIRE_QR_MASK;
}

/*!
 * \brief Clears the QR bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void knot_wire_flags_clear_qr(uint8_t *flags1)
{
	*flags1 &= ~KNOT_WIRE_QR_MASK;
}

/*!
 * \brief Returns the RCODE from the second byte of flags.
 *
 * \param flags2 First byte of DNS header flags.
 *
 * \return RCODE
 */
static inline uint8_t knot_wire_flags_get_rcode(uint8_t flags2)
{
	return flags2 & KNOT_WIRE_RCODE_MASK;
}

/*!
 * \brief Sets the RCODE in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 * \param rcode RCODE to set.
 */
static inline void knot_wire_flags_set_rcode(uint8_t *flags2, short rcode)
{
	*flags2 = (*flags2 & ~KNOT_WIRE_RCODE_MASK) | (rcode);
}

/*!
 * \brief Returns the CD bit from the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 *
 * \return Flags byte with only the CD bit according to its setting in
 *         \a flags2.
 */
static inline uint8_t knot_wire_flags_get_cd(uint8_t flags2)
{
	return flags2 & KNOT_WIRE_CD_MASK;
}

/*!
 * \brief Sets the CD bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void knot_wire_flags_set_cd(uint8_t *flags2)
{
	*flags2 |= KNOT_WIRE_CD_MASK;
}

/*!
 * \brief Clears the CD bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void knot_wire_flags_clear_cd(uint8_t *flags2)
{
	*flags2 &= ~KNOT_WIRE_CD_MASK;
}

/*!
 * \brief Returns the AD bit from the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 *
 * \return Flags byte with only the AD bit according to its setting in
 *         \a flags2.
 */
static inline uint8_t knot_wire_flags_get_ad(uint8_t flags2)
{
	return flags2 & KNOT_WIRE_AD_MASK;
}

/*!
 * \brief Sets the AD bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void knot_wire_flags_set_ad(uint8_t *flags2)
{
	*flags2 |= KNOT_WIRE_AD_MASK;
}

/*!
 * \brief Clears the AD bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void knot_wire_flags_clear_ad(uint8_t *flags2)
{
	*flags2 &= ~KNOT_WIRE_AD_MASK;
}

/*!
 * \brief Returns the Zero bit from the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 *
 * \return Flags byte with only the Zero bit according to its setting in
 *         \a flags2.
 */
static inline uint8_t knot_wire_flags_get_z(uint8_t flags2)
{
	return flags2 & KNOT_WIRE_Z_MASK;
}

/*!
 * \brief Sets the Zero bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void knot_wire_flags_set_z(uint8_t *flags2)
{
	*flags2 |= KNOT_WIRE_Z_MASK;
}

/*!
 * \brief Clears the Zero bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void knot_wire_flags_clear_z(uint8_t *flags2)
{
	*flags2 &= ~KNOT_WIRE_Z_MASK;
}

/*!
 * \brief Returns the RA bit from the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 *
 * \return Flags byte with only the RA bit according to its setting in
 *         \a flags2.
 */
static inline uint8_t knot_wire_flags_get_ra(uint8_t flags2)
{
	return flags2 & KNOT_WIRE_RA_MASK;
}

/*!
 * \brief Sets the RA bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void knot_wire_flags_set_ra(uint8_t *flags2)
{
	*flags2 |= KNOT_WIRE_RA_MASK;
}

/*!
 * \brief Clears the RA bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void knot_wire_flags_clear_ra(uint8_t *flags2)
{
	*flags2 &= ~KNOT_WIRE_RA_MASK;
}

/*
 * Pointer manipulation
 */

enum knot_wire_pointer_consts {
	/*! \brief DNS packet pointer designation (first two bits set to 1). */
	KNOT_WIRE_PTR = (uint8_t)0xC0,
	/*! \brief DNS packet minimal pointer (KNOT_WIRE_PTR + 1 zero byte). */
	KNOT_WIRE_PTR_BASE = (uint16_t)0xC000,
	/*! \brief DNS packet maximal offset (KNOT_WIRE_BASE complement). */
	KNOT_WIRE_PTR_MAX = (uint16_t)0x3FFF
};

/*!
 * \brief Creates a DNS packet pointer and stores it in wire format.
 *
 * \param pos Position where tu put the pointer.
 * \param ptr Relative position of the item to which the pointer should point in
 *            the wire format of the packet.
 */
void knot_wire_put_pointer(uint8_t *pos, uint16_t ptr);

uint16_t knot_wire_get_pointer(const uint8_t *pos);

static inline int knot_wire_is_pointer(const uint8_t *pos)
{
	return pos && ((pos[0] & KNOT_WIRE_PTR) == KNOT_WIRE_PTR);
}

_pure_ _mustcheck_
static inline const uint8_t *knot_wire_seek_label(const uint8_t *lp, const uint8_t *wire)
{
	while (knot_wire_is_pointer(lp)) {
		if (!wire)
			return NULL;
		lp = wire + knot_wire_get_pointer(lp);
	}
	return lp;
}

_pure_ _mustcheck_
static inline const uint8_t *knot_wire_next_label(const uint8_t *lp, const uint8_t *wire)
{
	if (!lp || !lp[0]) /* No label after final label. */
		return NULL;
	return knot_wire_seek_label(lp + (lp[0] + sizeof(uint8_t)), wire);
}

/*! @} */
