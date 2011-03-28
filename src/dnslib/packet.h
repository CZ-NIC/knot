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

#ifndef _KNOT_DNSLIB_PACKET_H_
#define _KNOT_DNSLIB_PACKET_H_

#include <stdint.h>
#include <assert.h>

#include "utils.h"

/*! \brief Offset of DNS header fields in wireformat. */
enum dnslib_packet_offsets {
	DNSLIB_PACKET_OFFSET_ID = 0,
	DNSLIB_PACKET_OFFSET_FLAGS1 = 2,
	DNSLIB_PACKET_OFFSET_FLAGS2 = 3,
	DNSLIB_PACKET_OFFSET_QDCOUNT = 4,
	DNSLIB_PACKET_OFFSET_ANCOUNT = 6,
	DNSLIB_PACKET_OFFSET_NSCOUNT = 8,
	DNSLIB_PACKET_OFFSET_ARCOUNT = 10
};

/*! \brief Minimum size for some parts of the DNS packet. */
enum dnslib_packet_sizes {
	DNSLIB_PACKET_HEADER_SIZE = 12,
	DNSLIB_PACKET_QUESTION_MIN_SIZE = 5,
	DNSLIB_PACKET_RR_MIN_SIZE = 11
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
static inline uint16_t dnslib_packet_get_id(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_ID);
}

/*!
 * \brief Sets the ID to the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param id DNS packet ID.
 */
static inline void dnslib_packet_set_id(uint8_t *packet, uint16_t id)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_ID, id);
}

/*!
 * \brief Returns the first byte of flags from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return First byte of DNS flags.
 */
static inline uint8_t dnslib_packet_get_flags1(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1);
}

/*!
 * \brief Sets the first byte of flags to the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param flags1 First byte of the DNS flags.
 */
static inline uint8_t dnslib_packet_set_flags1(uint8_t *packet, uint8_t flags1)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) = flags1;
}

/*!
 * \brief Returns the second byte of flags from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Second byte of DNS flags.
 */
static inline uint8_t dnslib_packet_get_flags2(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2);
}

/*!
 * \brief Sets the second byte of flags to the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param flags1 Second byte of the DNS flags.
 */
static inline uint8_t dnslib_packet_set_flags2(uint8_t *packet, uint8_t flags2)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) = flags2;
}

/*!
 * \brief Returns the QDCOUNT (count of Question entries) from wire format of
 *        the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return QDCOUNT (count of Question entries in the packet).
 */
static inline uint16_t dnslib_packet_get_qdcount(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_QDCOUNT);
}

/*!
 * \brief Sets the QDCOUNT (count of Question entries) to wire format of the
 *        packet.
 *
 * \param packet Wire format of the packet.
 * \param qdcount QDCOUNT (count of Question entries in the packet).
 */
static inline void dnslib_packet_set_qdcount(uint8_t *packet, uint16_t qdcount)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_QDCOUNT, qdcount);
}

/*!
 * \brief Returns the ANCOUNT (count of Answer entries) from wire format of
 *        the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return ANCOUNT (count of Answer entries in the packet).
 */
static inline uint16_t dnslib_packet_get_ancount(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_ANCOUNT);
}

/*!
 * \brief Sets the ANCOUNT (count of Answer entries) to wire format of the
 *        packet.
 *
 * \param packet Wire format of the packet.
 * \param qdcount ANCOUNT (count of Answer entries in the packet).
 */
static inline void dnslib_packet_set_ancount(uint8_t *packet, uint16_t ancount)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_ANCOUNT, ancount);
}

/*!
 * \brief Returns the NSCOUNT (count of Authority entries) from wire format of
 *        the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return NSCOUNT (count of Authority entries in the packet).
 */
static inline uint16_t dnslib_packet_get_nscount(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_NSCOUNT);
}

/*!
 * \brief Sets the NSCOUNT (count of Authority entries) to wire format of the
 *        packet.
 *
 * \param packet Wire format of the packet.
 * \param qdcount NSCOUNT (count of Authority entries in the packet).
 */
static inline void dnslib_packet_set_nscount(uint8_t *packet, uint16_t nscount)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_NSCOUNT, nscount);
}

/*!
 * \brief Returns the ARCOUNT (count of Additional entries) from wire format of
 *        the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return ARCOUNT (count of Additional entries in the packet).
 */
static inline uint16_t dnslib_packet_get_arcount(const uint8_t *packet)
{
	return dnslib_wire_read_u16(packet + DNSLIB_PACKET_OFFSET_ARCOUNT);
}

/*!
 * \brief Sets the ARCOUNT (count of Additional entries) to wire format of the
 *        packet.
 *
 * \param packet Wire format of the packet.
 * \param qdcount ARCOUNT (count of Additional entries in the packet).
 */
static inline void dnslib_packet_set_arcount(uint8_t *packet, uint16_t arcount)
{
	dnslib_wire_write_u16(packet + DNSLIB_PACKET_OFFSET_ARCOUNT, arcount);
}

/*
 * Packet header flags manipulation functions.
 */
/*! \brief Constants for DNS header flags in the first flags byte. */
enum dnslib_packet_flags1_consts {
	DNSLIB_PACKET_RD_MASK = (uint8_t)0x01U,      /*!< RD bit mask. */
	DNSLIB_PACKET_RD_SHIFT = 0,                  /*!< RD bit shift. */
	DNSLIB_PACKET_TC_MASK = (uint8_t)0x02U,      /*!< TC bit mask. */
	DNSLIB_PACKET_TC_SHIFT = 1,                  /*!< TC bit shift. */
	DNSLIB_PACKET_AA_MASK = (uint8_t)0x04U,      /*!< AA bit mask. */
	DNSLIB_PACKET_AA_SHIFT = 2,                  /*!< AA bit shift. */
	DNSLIB_PACKET_OPCODE_MASK = (uint8_t)0x78U,  /*!< OPCODE mask. */
	DNSLIB_PACKET_OPCODE_SHIFT = 3,              /*!< OPCODE shift. */
	DNSLIB_PACKET_QR_MASK = (uint8_t)0x80U,      /*!< QR bit mask. */
	DNSLIB_PACKET_QR_SHIFT = 7                   /*!< QR bit shift. */
};

/*! \brief Constants for DNS header flags in the second flags byte. */
enum dnslib_packet_flags2_consts {
	DNSLIB_PACKET_RCODE_MASK = (uint8_t)0x0fU,  /*!< RCODE mask. */
	DNSLIB_PACKET_RCODE_SHIFT = 0,              /*!< RCODE shift. */
	DNSLIB_PACKET_CD_MASK = (uint8_t)0x10U,     /*!< CD bit mask. */
	DNSLIB_PACKET_CD_SHIFT = 4,                 /*!< CD bit shift. */
	DNSLIB_PACKET_AD_MASK = (uint8_t)0x20U,     /*!< AD bit mask. */
	DNSLIB_PACKET_AD_SHIFT = 5,                 /*!< AD bit shift. */
	DNSLIB_PACKET_Z_MASK = (uint8_t)0x40U,      /*!< Zero bit mask. */
	DNSLIB_PACKET_Z_SHIFT = 6,                  /*!< Zero bit shift. */
	DNSLIB_PACKET_RA_MASK = (uint8_t)0x80U,     /*!< RA bit mask. */
	DNSLIB_PACKET_RA_SHIFT = 7                  /*!< RA bit shift. */
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
static inline uint8_t dnslib_packet_get_rd(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) & DNSLIB_PACKET_RD_MASK;
}

/*!
 * \brief Sets the RD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_set_rd(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) |= DNSLIB_PACKET_RD_MASK;
}

/*!
 * \brief Clears the RD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_flags_clear_rd(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) &= ~DNSLIB_PACKET_RD_MASK;
}

/*!
 * \brief Returns the TC bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the TC bit according to its setting in the packet.
 */
static inline uint8_t dnslib_packet_get_tc(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) & DNSLIB_PACKET_TC_MASK;
}

/*!
 * \brief Sets the TC bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_set_tc(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) |= DNSLIB_PACKET_TC_MASK;
}

/*!
 * \brief Clears the TC bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_clear_tc(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) &= ~DNSLIB_PACKET_TC_MASK;
}

/*!
 * \brief Returns the AA bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the AA bit according to its setting in the packet.
 */
static inline uint8_t dnslib_packet_get_aa(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) & DNSLIB_PACKET_AA_MASK;
}

/*!
 * \brief Sets the AA bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_set_aa(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) |= DNSLIB_PACKET_AA_MASK;
}

/*!
 * \brief Clears the AA bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_clear_aa(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) &= ~DNSLIB_PACKET_AA_MASK;
}

/*!
 * \brief Returns the OPCODE from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return OPCODE of the packet.
 */
static inline uint8_t dnslib_packet_get_opcode(const uint8_t *packet)
{
	return (*(packet + DNSLIB_PACKET_OFFSET_FLAGS1)
	        & DNSLIB_PACKET_OPCODE_MASK) >> DNSLIB_PACKET_OPCODE_SHIFT;
}

/*!
 * \brief Sets the OPCODE in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param opcode OPCODE to set.
 */
static inline void dnslib_packet_set_opcode(uint8_t *packet, short opcode)
{
	uint8_t *flags1 = packet + DNSLIB_PACKET_OFFSET_FLAGS1;
	*flags1 = (*flags1 & ~DNSLIB_PACKET_OPCODE_MASK)
	          | ((opcode) << DNSLIB_PACKET_OPCODE_SHIFT);
}

/*!
 * \brief Returns the QR bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the QR bit according to its setting in the packet.
 */
static inline uint8_t dnslib_packet_get_qr(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS1) & DNSLIB_PACKET_QR_MASK;
}

/*!
 * \brief Sets the QR bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_set_qr(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) |= DNSLIB_PACKET_QR_MASK;
}

/*!
 * \brief Clears the QR bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_clear_qr(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS1) &= ~DNSLIB_PACKET_QR_MASK;
}

/*!
 * \brief Returns the RCODE from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return RCODE of the packet.
 */
static inline uint8_t dnslib_packet_get_rcode(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2)
	       & DNSLIB_PACKET_RCODE_MASK;
}

/*!
 * \brief Sets the RCODE in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 * \param rcode RCODE to set.
 */
static inline void dnslib_packet_set_rcode(uint8_t *packet, short rcode)
{
	uint8_t *flags2 = packet + DNSLIB_PACKET_OFFSET_FLAGS2;
	*flags2 = (*flags2 & ~DNSLIB_PACKET_RCODE_MASK) | (rcode);
}

/*!
 * \brief Returns the CD bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the CD bit according to its setting in the packet.
 */
static inline uint8_t dnslib_packet_get_cd(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) & DNSLIB_PACKET_CD_MASK;
}

/*!
 * \brief Sets the CD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_set_cd(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) |= DNSLIB_PACKET_CD_MASK;
}

/*!
 * \brief Clears the CD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_clear_cd(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) &= ~DNSLIB_PACKET_CD_MASK;
}

/*!
 * \brief Returns the AD bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the AD bit according to its setting in the packet.
 */
static inline uint8_t dnslib_packet_get_ad(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) & DNSLIB_PACKET_AD_MASK;
}

/*!
 * \brief Sets the AD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_set_ad(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) |= DNSLIB_PACKET_AD_MASK;
}

/*!
 * \brief Clears the AD bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_clear_ad(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) &= ~DNSLIB_PACKET_AD_MASK;
}

/*!
 * \brief Returns the Zero bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the Zero bit according to its setting in the packet.
 */
static inline uint8_t dnslib_packet_get_z(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) & DNSLIB_PACKET_Z_MASK;
}

/*!
 * \brief Sets the Zero bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_set_z(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) |= DNSLIB_PACKET_Z_MASK;
}

/*!
 * \brief Clears the Zero bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_clear_z(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) &= ~DNSLIB_PACKET_Z_MASK;
}

/*!
 * \brief Returns the RA bit from wire format of the packet.
 *
 * \param packet Wire format of the packet.
 *
 * \return Flags with only the RA bit according to its setting in the packet.
 */
static inline uint8_t dnslib_packet_get_ra(const uint8_t *packet)
{
	return *(packet + DNSLIB_PACKET_OFFSET_FLAGS2) & DNSLIB_PACKET_RA_MASK;
}

/*!
 * \brief Sets the RA bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_set_ra(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) |= DNSLIB_PACKET_RA_MASK;
}

/*!
 * \brief Clears the RA bit in the wire format of the packet.
 *
 * \param packet Wire format of the packet.
 */
static inline void dnslib_packet_clear_ra(uint8_t *packet)
{
	*(packet + DNSLIB_PACKET_OFFSET_FLAGS2) &= ~DNSLIB_PACKET_RA_MASK;
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
static inline uint8_t dnslib_packet_flags_get_rd(uint8_t flags1)
{
	return flags1 & DNSLIB_PACKET_RD_MASK;
}

/*!
 * \brief Sets the RD bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void dnslib_packet_flags_set_rd(uint8_t *flags1)
{
	*flags1 |= DNSLIB_PACKET_RD_MASK;
}

/*!
 * \brief Clears the RD bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void dnslib_packet_flags_flags_clear_rd(uint8_t *flags1)
{
	*flags1 &= ~DNSLIB_PACKET_RD_MASK;
}

/*!
 * \brief Returns the TC bit from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return Flags byte with only the TC bit according to its setting in
 *         \a flags1.
 */
static inline uint8_t dnslib_packet_flags_get_tc(uint8_t flags1)
{
	return flags1 & DNSLIB_PACKET_TC_MASK;
}

/*!
 * \brief Sets the TC bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void dnslib_packet_flags_set_tc(uint8_t *flags1)
{
	*flags1 |= DNSLIB_PACKET_TC_MASK;
}

/*!
 * \brief Clears the TC bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void dnslib_packet_flags_clear_tc(uint8_t *flags1)
{
	*flags1 &= ~DNSLIB_PACKET_TC_MASK;
}

/*!
 * \brief Returns the AA bit from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return Flags byte with only the AA bit according to its setting in
 *         \a flags1.
 */
static inline uint8_t dnslib_packet_flags_get_aa(uint8_t flags1)
{
	return flags1 & DNSLIB_PACKET_AA_MASK;
}

/*!
 * \brief Sets the AA bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void dnslib_packet_flags_set_aa(uint8_t *flags1)
{
	*flags1 |= DNSLIB_PACKET_AA_MASK;
}

/*!
 * \brief Clears the AA bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void dnslib_packet_flags_clear_aa(uint8_t *flags1)
{
	*flags1 &= ~DNSLIB_PACKET_AA_MASK;
}

/*!
 * \brief Returns the OPCODE from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return OPCODE
 */
static inline uint8_t dnslib_packet_flags_get_opcode(uint8_t flags1)
{
	return (flags1 & DNSLIB_PACKET_OPCODE_MASK)
	        >> DNSLIB_PACKET_OPCODE_SHIFT;
}

/*!
 * \brief Sets the OPCODE in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 * \param opcode OPCODE to set.
 */
static inline void dnslib_packet_flags_set_opcode(uint8_t *flags1, short opcode)
{
	*flags1 = (*flags1 & ~DNSLIB_PACKET_OPCODE_MASK)
	          | ((opcode) << DNSLIB_PACKET_OPCODE_SHIFT);
}

/*!
 * \brief Returns the QR bit from the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return Flags byte with only the QR bit according to its setting in
 *         \a flags1.
 */
static inline uint8_t dnslib_packet_flags_get_qr(uint8_t flags1)
{
	return flags1 & DNSLIB_PACKET_QR_MASK;
}

/*!
 * \brief Sets the QR bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void dnslib_packet_flags_set_qr(uint8_t *flags1)
{
	*flags1 |= DNSLIB_PACKET_QR_MASK;
}

/*!
 * \brief Clears the QR bit in the first byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 */
static inline void dnslib_packet_flags_clear_qr(uint8_t *flags1)
{
	*flags1 &= ~DNSLIB_PACKET_QR_MASK;
}

/*!
 * \brief Returns the RCODE from the second byte of flags.
 *
 * \param flags1 First byte of DNS header flags.
 *
 * \return RCODE
 */
static inline uint8_t dnslib_packet_flags_get_rcode(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_RCODE_MASK;
}

/*!
 * \brief Sets the RCODE in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 * \param rcode RCODE to set.
 */
static inline void dnslib_packet_flags_set_rcode(uint8_t *flags2, short rcode)
{
	*flags2 = (*flags2 & ~DNSLIB_PACKET_RCODE_MASK) | (rcode);
}

/*!
 * \brief Returns the CD bit from the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 *
 * \return Flags byte with only the CD bit according to its setting in
 *         \a flags2.
 */
static inline uint8_t dnslib_packet_flags_get_cd(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_CD_MASK;
}

/*!
 * \brief Sets the CD bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void dnslib_packet_flags_set_cd(uint8_t *flags2)
{
	*flags2 |= DNSLIB_PACKET_CD_MASK;
}

/*!
 * \brief Clears the CD bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void dnslib_packet_flags_clear_cd(uint8_t *flags2)
{
	*flags2 &= ~DNSLIB_PACKET_CD_MASK;
}

/*!
 * \brief Returns the AD bit from the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 *
 * \return Flags byte with only the AD bit according to its setting in
 *         \a flags2.
 */
static inline uint8_t dnslib_packet_flags_get_ad(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_AD_MASK;
}

/*!
 * \brief Sets the AD bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void dnslib_packet_flags_set_ad(uint8_t *flags2)
{
	*flags2 |= DNSLIB_PACKET_AD_MASK;
}

/*!
 * \brief Clears the AD bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void dnslib_packet_flags_clear_ad(uint8_t *flags2)
{
	*flags2 &= ~DNSLIB_PACKET_AD_MASK;
}

/*!
 * \brief Returns the Zero bit from the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 *
 * \return Flags byte with only the Zero bit according to its setting in
 *         \a flags2.
 */
static inline uint8_t dnslib_packet_flags_get_z(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_Z_MASK;
}

/*!
 * \brief Sets the Zero bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void dnslib_packet_flags_set_z(uint8_t *flags2)
{
	*flags2 |= DNSLIB_PACKET_Z_MASK;
}

/*!
 * \brief Clears the Zero bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void dnslib_packet_flags_clear_z(uint8_t *flags2)
{
	*flags2 &= ~DNSLIB_PACKET_Z_MASK;
}

/*!
 * \brief Returns the RA bit from the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 *
 * \return Flags byte with only the RA bit according to its setting in
 *         \a flags2.
 */
static inline uint8_t dnslib_packet_flags_get_ra(uint8_t flags2)
{
	return flags2 & DNSLIB_PACKET_RA_MASK;
}

/*!
 * \brief Sets the RA bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
static inline void dnslib_packet_flags_set_ra(uint8_t *flags2)
{
	*flags2 |= DNSLIB_PACKET_RA_MASK;
}

/*!
 * \brief Clears the RA bit in the second byte of flags.
 *
 * \param flags2 Second byte of DNS header flags.
 */
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

#endif /* _KNOT_DNSLIB_PACKET_H_ */

/*! @} */
