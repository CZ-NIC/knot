/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Functions for manipulating the EDNS OPT pseudo-RR.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <assert.h>

#include "libknot/consts.h"
#include "libknot/rrset.h"

/*! \brief Constants related to EDNS. */
enum knot_edns_const {
	/*! \brief Supported EDNS version. */
	KNOT_EDNS_VERSION = 0,

	/*! \brief Minimal UDP payload with EDNS enabled. */
	KNOT_EDNS_MIN_UDP_PAYLOAD    = 512,
	/*! \brief Minimal payload when using DNSSEC (RFC4035/sec.3). */
	KNOT_EDNS_MIN_DNSSEC_PAYLOAD = 1220,
	/*! \brief Maximal UDP payload with EDNS enabled. */
	KNOT_EDNS_MAX_UDP_PAYLOAD    = 4096,

	/*! \brief Minimum size of EDNS OPT RR in wire format. */
	KNOT_EDNS_MIN_SIZE                 = 11,
	/*! \brief Position of the Ext RCODE field in wire format of OPT RR. */
	KNOT_EDNS_EXT_RCODE_POS            = 5,
	/*! \brief EDNS OPTION header size. */
	KNOT_EDNS_OPTION_HDRLEN            = 4,
	/*! \brief Maximal edns client subnet data size (IPv6). */
	KNOT_EDNS_MAX_OPTION_CLIENT_SUBNET = 20,

	/*! \brief NSID option code. */
	KNOT_EDNS_OPTION_NSID          = 3,
	/*! \brief EDNS client subnet option code. */
	KNOT_EDNS_OPTION_CLIENT_SUBNET = 8,
	/*! \brief EDNS DNS Cookie option code. */
	KNOT_EDNS_OPTION_COOKIE        = 10,
	/*! \brief EDNS Padding option code. */
	KNOT_EDNS_OPTION_PADDING       = 12
};

/* Helpers for splitting extended RCODE. */
#define KNOT_EDNS_RCODE_HI(rc) ((rc >> 4) & 0x00ff)
#define KNOT_EDNS_RCODE_LO(rc) (rc & 0x000f)

/*!
 * \brief Initialize OPT RR.
 *
 * \param max_pld    Max UDP payload.
 * \param ext_rcode  Extended RCODE.
 * \param ver        Version.
 * \param mm         Memory context.
 *
 * \return KNOT_EOK or an error
 */
int knot_edns_init(knot_rrset_t *opt_rr, uint16_t max_pld,
                   uint8_t ext_rcode, uint8_t ver, knot_mm_t *mm);

/*!
 * \brief Returns size of the OPT RR in wire format.
 *
 * \param opt_rr  OPT RR to count the wire size of.
 *
 * \return Size of the OPT RR in bytes.
 */
size_t knot_edns_wire_size(knot_rrset_t *opt_rr);

/*!
 * \brief Returns the Max UDP payload value stored in the OPT RR.
 *
 * \warning This function does not check the parameter, so ensure to check it
 *          before calling the function. It must not be NULL.
 * \note There is an assert() for debug checking of the parameter.
 *
 * \param opt_rr  OPT RR to get the value from.
 *
 * \return Max UDP payload in bytes.
 */
uint16_t knot_edns_get_payload(const knot_rrset_t *opt_rr);

/*!
 * \brief Sets the Max UDP payload field in the OPT RR.
 *
 * \warning This function does not check the parameter, so ensure to check it
 *          before calling the function. It must not be NULL.
 * \note There is an assert() for debug checking of the parameter.
 *
 * \param opt_rr   OPT RR to set the value to.
 * \param payload  UDP payload in bytes.
 */
void knot_edns_set_payload(knot_rrset_t *opt_rr, uint16_t payload);

/*!
 * \brief Returns the Extended RCODE stored in the OPT RR.
 *
 * \warning This function does not check the parameter, so ensure to check it
 *          before calling the function. It must not be NULL.
 * \note There is an assert() for debug checking of the parameter.
 *
 * \param opt_rr  OPT RR to get the Extended RCODE from.
 *
 * \return Extended RCODE.
 */
uint8_t knot_edns_get_ext_rcode(const knot_rrset_t *opt_rr);

/*!
 * \brief Concatenates OPT RR Extended RCODE field and normal RCODE to get the
 *        whole Extended RCODE.
 *
 * Extended RCODE is created by using the Extended RCODE field from OPT RR as
 * higher 8 bits and the RCODE from DNS Header as the lower 4 bits, resulting
 * in a 12-bit unsigned integer. (See RFC 6891, Section 6.1.3).
 *
 * \param ext_rcode  Extended RCODE field from OPT RR.
 * \param rcode      RCODE from DNS Header.
 *
 * \return 12-bit Extended RCODE.
 */
static inline uint16_t knot_edns_whole_rcode(uint8_t ext_rcode, uint8_t rcode)
{
	uint16_t high = ext_rcode;
	return (high << 4) | rcode;
}

/*!
 * \brief Sets the Extended RCODE field in the OPT RR.
 *
 * \warning This function does not check the parameter, so ensure to check it
 *          before calling the function. It must not be NULL.
 * \note There is an assert() for debug checking of the parameter.
 *
 * \param opt_rr     OPT RR to set the Extended RCODE to.
 * \param ext_rcode  Extended RCODE to set.
 */
void knot_edns_set_ext_rcode(knot_rrset_t *opt_rr, uint8_t ext_rcode);

/*!
 * \brief Sets the Extended RCODE field in OPT RR wire.
 *
 * \param opt_rr     Position of the OPT RR in packet.
 * \param ext_rcode  Higher 8 bits of Extended RCODE.
 */
static inline void knot_edns_set_ext_rcode_wire(uint8_t *opt_rr,
                                                uint8_t ext_rcode)
{
	*(opt_rr + KNOT_EDNS_EXT_RCODE_POS) = ext_rcode;
}

/*!
 * \brief Returns the EDNS version stored in the OPT RR.
 *
 * \warning This function does not check the parameter, so ensure to check it
 *          before calling the function. It must not be NULL.
 * \note There is an assert() for debug checking of the parameter.
 *
 * \param opt_rr  OPT RR to get the EDNS version from.
 *
 * \return EDNS version.
 */
uint8_t knot_edns_get_version(const knot_rrset_t *opt_rr);

/*!
 * \brief Sets the EDNS version field in the OPT RR.
 *
 * \warning This function does not check the parameter, so ensure to check it
 *          before calling the function. It must not be NULL.
 * \note There is an assert() for debug checking of the parameter.
 *
 * \param opt_rr   OPT RR to set the EDNS version to.
 * \param version  EDNS version to set.
 */
void knot_edns_set_version(knot_rrset_t *opt_rr, uint8_t version);

/*!
 * \brief Returns the state of the DO bit in the OPT RR flags.
 *
 * \warning This function does not check the parameter, so ensure to check it
 *          before calling the function. It must not be NULL.
 * \note There is an assert() for debug checking of the parameter.
 *
 * \param opt_rr  OPT RR to get the DO bit from.
 *
 * \return <> 0 if the DO bit is set.
 * \return 0 if the DO bit is not set.
 */
bool knot_edns_do(const knot_rrset_t *opt_rr);

/*!
 * \brief Sets the DO bit in the OPT RR.
 *
 * \warning This function does not check the parameter, so ensure to check it
 *          before calling the function. It must not be NULL.
 * \note There is an assert() for debug checking of the parameter.
 *
 * \param opt_rr  OPT RR to set the DO bit in.
 */
void knot_edns_set_do(knot_rrset_t *opt_rr);

/*!
 * \brief Removes all EDNS options with given \a code.
 *
 * \param[in] opt_rr  OPT RR structure to remove the options from.
 * \param[in] code    Option code.
 *
 * \return Error code, KNOT_EOK if successful (even if nothing removed).
 */
int knot_edns_remove_options(knot_rrset_t *opt_rr, uint16_t code);

/*!
 * \brief Adds EDNS option into the package with empty (zeroed) content.
 *
 * \note All other occurrences of the option type will be removed.
 *
 * \param[in]  opt_rr    OPT RR structure to reserve the option in.
 * \param[in]  code      Option code.
 * \param[in]  size      Desired option size.
 * \param[out] wire_ptr  Pointer to reserved option data (can be NULL).
 * \param[in]  mm        Memory context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_reserve_unique_option(knot_rrset_t *opt_rr, uint16_t code,
                                    uint16_t size, uint8_t **wire_ptr,
                                    knot_mm_t *mm);

/*!
 * \brief Add EDNS option into the package with empty (zeroed) content.
 *
 * \param[in]  opt_rr    OPT RR structure to reserve the option in.
 * \param[in]  code      Option code.
 * \param[in]  size      Desired option size.
 * \param[out] wire_ptr  Pointer to reserved option data (can be NULL).
 * \param[in]  mm        Memory context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_reserve_option(knot_rrset_t *opt_rr, uint16_t code,
                             uint16_t size, uint8_t **wire_ptr, knot_mm_t *mm);

/*!
 * \brief Adds EDNS Option to the OPT RR.
 *
 * \note The function now supports adding empty OPTION (just having its code).
 *       This does not make much sense now with NSID, but may be ok use later.
 *
 * \param opt_rr  OPT RR structure to add the Option to.
 * \param code    Option code.
 * \param size    Option data length in bytes.
 * \param data    Option data.
 * \param mm      Memory context.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
int knot_edns_add_option(knot_rrset_t *opt_rr, uint16_t code,
                         uint16_t size, const uint8_t *data, knot_mm_t *mm);

/*!
 * \brief Checks if the OPT RR contains Option with the specified code.
 *
 * \param opt_rr OPT RR structure to check for the Option in.
 * \param code Option code to check for.
 *
 * \retval <> 0 if the OPT RR contains Option with Option code \a code.
 * \retval 0 otherwise.
 */
bool knot_edns_has_option(const knot_rrset_t *opt_rr, uint16_t code);

/*!
 * \brief Searches the OPT RR for option with the specified code.
 *
 * \param opt_rr  OPT RR structure to search for the Option in.
 * \param code    Option code to search for.
 *
 * \retval pointer to option if found
 * \retval NULL otherwise.
 */
uint8_t *knot_edns_get_option(const knot_rrset_t *opt_rr, uint16_t code);

/*!
 * \brief Returns the option code.
 *
 * \warning No safety checks are performed on the supplied data.
 *
 * \param opt  EDNS option (including code, length and data portion).
 *
 * \retval EDNS option code
 */
uint16_t knot_edns_opt_get_code(const uint8_t *opt);

/*!
 * \brief Returns the option data length.
 *
 * \warning No safety checks are performed on the supplied data.
 *
 * \param opt  EDNS option (including code, length and data portion).
 *
 * \retval EDNS option length
 */
uint16_t knot_edns_opt_get_length(const uint8_t *opt);

/*!
 * \brief Returns pointer to option data.
 *
 * \warning No safety checks are performed on the supplied data.
 *
 * \param opt  EDNS option (including code, length and data portion).
 *
 * \retval pointer to place where ENDS option data would reside
 */
static inline uint8_t *knot_edns_opt_get_data(uint8_t *opt)
{
	return opt + KNOT_EDNS_OPTION_HDRLEN;
}

/*! \brief Return true if RRSet has NSID option. */
bool knot_edns_has_nsid(const knot_rrset_t *opt_rr);

/*!
 * \brief Checks OPT RR semantics.
 *
 * Checks whether RDATA are OK, i.e. that all OPTIONs have proper lengths.
 *
 * \param opt_rr  OPT RR to check.
 *
 * \return true if passed, false if failed
 */
bool knot_edns_check_record(knot_rrset_t *opt_rr);

/*!
 * \brief Creates client subnet wire data.
 *
 * \param family    Address family.
 * \param addr      Binary representation of IP address.
 * \param addr_len  Length of the address.
 * \param src_mask  Source mask.
 * \param dst_mask  Destination mask.
 * \param data      Output data buffer.
 * \param data_len  Size of output data buffer/written data.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_client_subnet_create(const knot_addr_family_t family,
                                   const uint8_t *addr,
                                   const uint16_t addr_len,
                                   uint8_t src_mask,
                                   uint8_t dst_mask,
                                   uint8_t *data,
                                   uint16_t *data_len);

/*!
 * \brief Parses client subnet wire data.
 *
 * \param data      Input data buffer.
 * \param data_len  Length of input data buffer.
 * \param family    Address family.
 * \param addr      Binary representation of IP address.
 * \param addr_len  Size of address buffer/written address data.
 * \param src_mask  Source mask.
 * \param dst_mask  Destination mask.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_client_subnet_parse(const uint8_t *data,
                                  const uint16_t data_len,
                                  knot_addr_family_t *family,
                                  uint8_t *addr,
                                  uint16_t *addr_len,
                                  uint8_t *src_mask,
                                  uint8_t *dst_mask);

/*!
 * \brief Computes additional Padding data length for required packet alignment.
 *
 * \param current_pkt_size  Current packet size.
 * \param current_opt_size  Current OPT rrset size (OPT must be used).
 * \param block_size        Required packet block length (must be non-zero).
 *
 * \return Required padding length or -1 if padding not required.
 */
static inline int knot_edns_alignment_size(size_t current_pkt_size,
                                           size_t current_opt_size,
                                           size_t block_size)
{
	assert(current_opt_size > 0);
	assert(block_size > 0);

	size_t current_size = current_pkt_size + current_opt_size;
	if (current_size % block_size == 0) {
		return -1;
	}

	size_t modulo = (current_size + KNOT_EDNS_OPTION_HDRLEN) % block_size;

	return (modulo == 0) ? 0 : block_size - modulo;
}

/*! @} */
