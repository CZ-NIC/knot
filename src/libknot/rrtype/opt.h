/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \addtogroup rrtype
 * @{
 */

#pragma once

#include <assert.h>

#include "libknot/consts.h"
#include "libknot/rrset.h"

/* Forward decls */
typedef struct knot_pkt knot_pkt_t;

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
	/*! \brief Maximal size of EDNS client subnet address in bytes (IPv6). */
	KNOT_EDNS_CLIENT_SUBNET_ADDRESS_MAXLEN = 16,

	/*! \brief EDNS client cookie size. */
	KNOT_EDNS_COOKIE_CLNT_SIZE     = 8,
	/*! \brief EDNS minimum server cookie size. */
	KNOT_EDNS_COOKIE_SRVR_MIN_SIZE = 8,
	/*! \brief EDNS maximum server cookie size. */
	KNOT_EDNS_COOKIE_SRVR_MAX_SIZE = 32,

	/*! \brief NSID option code. */
	KNOT_EDNS_OPTION_NSID          = 3,
	/*! \brief EDNS Client subnet option code. */
	KNOT_EDNS_OPTION_CLIENT_SUBNET = 8,
	/*! \brief EDNS DNS Cookie option code. */
	KNOT_EDNS_OPTION_COOKIE        = 10,
	/*! \brief EDNS TCP Keepalive option code. */
	KNOT_EDNS_OPTION_TCP_KEEPALIVE = 11,
	/*! \brief EDNS Padding option code. */
	KNOT_EDNS_OPTION_PADDING       = 12,
	/*! \brief EDNS Chain query option code. */
	KNOT_EDNS_OPTION_CHAIN         = 13,
};

/* Helpers for splitting extended RCODE. */
#define KNOT_EDNS_RCODE_HI(rc) ((rc >> 4) & 0x00ff)
#define KNOT_EDNS_RCODE_LO(rc) (rc & 0x000f)

/*!
 * \brief Initialize OPT RR.
 *
 * \param opt_rr     OPT RR to initialize.
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
 * \return true if the DO bit is set.
 * \return false if the DO bit is not set.
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
 * \retval true if the OPT RR contains Option with Option code \a code.
 * \retval false otherwise.
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
 * \brief Computes a reasonable Padding data length for a given packet and opt RR.
 *
 * \param pkt     DNS Packet prepared and otherwise ready to go, no OPT yet added.
 * \param opt_rr  OPT RR, not yet including padding.
 *
 * \return Required padding length or -1 if padding not required.
 */
int knot_edns_default_padding_size(const knot_pkt_t *pkt,
                                   const knot_rrset_t *opt_rr);

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

/*!
 * \brief EDNS Client Subnet content.
 *
 * \see draft-ietf-dnsop-edns-client-subnet
 */
struct knot_edns_client_subnet {
	/*! \brief FAMILY */
	uint16_t family;
	/*! \brief SOURCE PREFIX-LENGTH */
	uint8_t source_len;
	/*! \brief SCOPE PREFIX-LENGTH */
	uint8_t scope_len;
	/*! \brief ADDRESS */
	uint8_t address[KNOT_EDNS_CLIENT_SUBNET_ADDRESS_MAXLEN];
};

typedef struct knot_edns_client_subnet knot_edns_client_subnet_t;
struct sockaddr_storage;

/*!
 * \brief Get the wire size of the EDNS Client Subnet option.
 *
 * \param ecs  EDNS Client Subnet data.
 *
 * \return Size of the EDNS option data.
 */
size_t knot_edns_client_subnet_size(const knot_edns_client_subnet_t *ecs);

/*!
 * \brief Write EDNS Client Subnet data from the ECS structure to wire.
 *
 * \param option      EDNS option data buffer.
 * \param option_len  EDNS option data buffer size.
 * \param ecs         EDNS Client Subnet data.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_client_subnet_write(uint8_t *option, size_t option_len,
                                  const knot_edns_client_subnet_t *ecs);

/*!
 * \brief Parse EDNS Client Subnet data from wire to the ECS structure.
 *
 * \param[out] ecs         EDNS Client Subnet data.
 * \param[in]  option      EDNS option data.
 * \param[in]  option_len  EDNS option size.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_client_subnet_parse(knot_edns_client_subnet_t *ecs,
                                  const uint8_t *option, uint16_t option_len);

/*!
 * \brief Set address to the ECS structure.
 *
 * \note It also resets the lengths.
 *
 * \param ecs   ECS structure to set address into.
 * \param addr  Address to be set.
 *
 * \return Error code. KNOT_EOK if successful.
 */
int knot_edns_client_subnet_set_addr(knot_edns_client_subnet_t *ecs,
                                     const struct sockaddr_storage *addr);

/*!
 * \brief Get address from the ECS structure.
 *
 * Only the family and raw address is set in the structure. The bits not
 * covered by the prefix length are cleared.
 *
 * \param addr  Address to be set.
 * \param ecs   ECS structure to retrieve address from.
 */
int knot_edns_client_subnet_get_addr(struct sockaddr_storage *addr,
                                     const knot_edns_client_subnet_t *ecs);

/*!
 * \brief Get size of the EDNS Keepalive option wire size.
 *
 * \param[in] timeout  EDNS TCP Keepalive timeout.
 *
 * \return Size of the EDNS option data.
 */
size_t knot_edns_keepalive_size(uint16_t timeout);

/*!
 * \brief Writes EDNS TCP Keepalive wire data.
 *
 * \param[out] option      EDNS option data buffer.
 * \param[in]  option_len  EDNS option data buffer size.
 * \param[in]  timeout     EDNS TCP Keepalive timeout.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_keepalive_write(uint8_t *option, size_t option_len, uint16_t timeout);

/*!
 * \brief Parses EDNS TCP Keepalive wire data.
 *
 * \param[out] timeout     EDNS TCP Keepalive timeout.
 * \param[in]  option      EDNS option data.
 * \param[in]  option_len  EDNS option size.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_keepalive_parse(uint16_t *timeout, const uint8_t *option,
                              uint16_t option_len);

/*!
 * \brief Get size of the EDNS Chain option wire size.
 *
 * \param[in] point  EDNS Chain closest trusted point.
 *
 * \return Size of the EDNS option data or 0 if invalid input.
 */
size_t knot_edns_chain_size(const knot_dname_t *point);

/*!
 * \brief Writes EDNS Chain wire data.
 *
 * \param[out] option      EDNS option data buffer.
 * \param[in]  option_len  EDNS option data buffer size.
 * \param[in]  point       EDNS Chain closest trusted point.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_chain_write(uint8_t *option, size_t option_len,
                          const knot_dname_t *point);

/*!
 * \brief Parses EDNS Chain wire data.
 *
 * \param[out] point       EDNS Chain closest trusted point.
 * \param[in]  option      EDNS option data.
 * \param[in]  option_len  EDNS option size.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_chain_parse(knot_dname_t **point, const uint8_t *option,
                          uint16_t option_len);

/*!
 * \brief DNS Cookie content.
 */
typedef struct {
	uint8_t data[KNOT_EDNS_COOKIE_SRVR_MAX_SIZE]; /*!< Cookie data. */
	uint16_t len; /*!< Cookie length. */
} knot_edns_cookie_t;

/*!
 * \brief Get size of the EDNS Cookie option wire size.
 *
 * \param[in] cc  Client cookie.
 * \param[in] sc  Server cookie (can be NULL).
 *
 * \return Size of the EDNS option data or 0 if invalid input.
 */
uint16_t knot_edns_cookie_size(const knot_edns_cookie_t *cc,
                               const knot_edns_cookie_t *sc);

/*!
 * \brief Writes EDNS cookie wire data.
 *
 * \param[out] option      EDNS option data buffer.
 * \param[in]  option_len  EDNS option data buffer size.
 * \param[in]  cc          EDNS client cookie.
 * \param[in]  sc          EDNS server cookie (can be NULL).
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_cookie_write(uint8_t *option, size_t option_len,
                           const knot_edns_cookie_t *cc,
                           const knot_edns_cookie_t *sc);

/*!
 * \brief Parses EDNS Cookie wire data.
 *
 * \param[out] cc          EDNS client cookie.
 * \param[out] sc          EDNS server cookie.
 * \param[in]  option      EDNS option data.
 * \param[in]  option_len  EDNS option size.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_edns_cookie_parse(knot_edns_cookie_t *cc, knot_edns_cookie_t *sc,
                           const uint8_t *option, uint16_t option_len);

/*! @} */
