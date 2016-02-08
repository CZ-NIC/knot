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
 * \brief TSIG signing and validating.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdint.h>

#include "libknot/rrtype/tsig.h"
#include "libknot/rrset.h"

/*!
 * \brief Generate TSIG signature of a message.
 *
 * This function generates TSIG digest of the given message prepended with the
 * given Request MAC (if any) and appended with TSIG Variables. It also appends
 * the resulting TSIG RR to the message wire format and accordingly adjusts
 * the message size.
 *
 * \note This function does not save the new digest to the 'digest' parameter
 *       unless everything went OK. This allows to sent the same buffer to
 *       the 'request_mac' and 'digest' parameters.
 *
 * \param msg Message to be signed.
 * \param msg_len Size of the message in bytes.
 * \param msg_max_len Maximum size of the message in bytes.
 * \param request_mac Request MAC. (may be NULL).
 * \param request_mac_len Size of the request MAC in bytes.
 * \param digest Buffer to save the digest in.
 * \param digest_len In: size of the buffer. Out: real size of the digest saved.
 * \param tsig_rr RRSet containing the TSIG RR to be used. Data from the RR are
 *                appended to the signed message.
 *
 * \retval KNOT_EOK if everything went OK.
 * \retval TODO
 *
 * \todo This function should return TSIG errors by their codes which are
 *       positive values - this will be recognized by the caller.
 */
int knot_tsig_sign(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                   const uint8_t *request_mac, size_t request_mac_len,
                   uint8_t *digest, size_t *digest_len,
                   const knot_tsig_key_t *key, uint16_t tsig_rcode,
                   uint64_t request_time_signed);

/*!
 * \brief Generate TSIG signature of a 2nd or later message in a TCP session.
 *
 * This function generates TSIG digest of the given message prepended with the
 * given Request MAC (if any) and appended with TSIG Variables. It also appends
 * the resulting TSIG RR to the message wire format and accordingly adjusts
 * the message size.
 *
 * \note This function does not save the new digest to the 'digest' parameter
 *       unless everything went OK. This allows to sent the same buffer to
 *       the 'request_mac' and 'digest' parameters.
 *
 * \param msg Message to be signed.
 * \param msg_len Size of the message in bytes.
 * \param msg_max_len Maximum size of the message in bytes.
 * \param prev_digest Previous digest sent by the server in the session.
 * \param prev_digest_len Size of the previous digest in bytes.
 * \param digest Buffer to save the digest in.
 * \param digest_len In: size of the buffer. Out: real size of the digest saved.
 * \param tsig_rr RRSet containing the TSIG RR to be used. Data from the RR are
 *                appended to the signed message.
 *
 * \retval KNOT_EOK if successful.
 * \retval TODO
 *
 * \todo This function should return TSIG errors by their codes which are
 *       positive values - this will be recognized by the caller.
 */
int knot_tsig_sign_next(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                        const uint8_t *prev_digest, size_t prev_digest_len,
                        uint8_t *digest, size_t *digest_len,
                        const knot_tsig_key_t *key, uint8_t *to_sign,
                        size_t to_sign_len);

/*!
 * \brief Checks incoming request.
 *
 * \param tsig_rr TSIG extracted from the packet.
 * \param wire Wire format of the packet (including the TSIG RR).
 * \param size Size of the wire format of packet in bytes.
 *
 * \retval KNOT_EOK If the signature is valid.
 * \retval TODO
 *
 * \todo This function should return TSIG errors by their codes which are
 *       positive values - this will be recognized by the caller.
 */
int knot_tsig_server_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const knot_tsig_key_t *tsig_key);

/*!
 * \brief Checks incoming response.
 *
 * \param tsig_rr TSIG extracted from the packet.
 * \param wire Wire format of the packet (including the TSIG RR).
 * \param size Size of the wire format of packet in bytes.
 * \param request_mac Request MAC. (may be NULL).
 * \param request_mac_len Size of the request MAC in bytes.
 *
 * \retval KNOT_EOK If the signature is valid.
 * \retval TODO
 *
 * \todo This function should return TSIG errors by their codes which are
 *       positive values - this will be recognized by the caller.
 */
int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len,
                           const knot_tsig_key_t *key,
                           uint64_t prev_time_signed);

/*!
 * \brief Checks signature of 2nd or next packet in a TCP session.
 *
 * \param tsig_rr TSIG extracted from the packet.
 * \param wire Wire format of the packet (including the TSIG RR).
 * \param size Size of the wire format of packet in bytes.
 * \param prev_digest Previous digest sent by the server in the session.
 * \param prev_digest_len Size of the previous digest in bytes.
 *
 * \retval KNOT_EOK If the signature is valid.
 * \retval TODO
 *
 * \todo This function should return TSIG errors by their codes which are
 *       positive values - this will be recognized by the caller.
 */
int knot_tsig_client_check_next(const knot_rrset_t *tsig_rr,
                                const uint8_t *wire, size_t size,
                                const uint8_t *prev_digest,
                                size_t prev_digest_len,
                                const knot_tsig_key_t *key,
                                uint64_t prev_time_signed);

/*!
 * \todo Documentation!
 */
int knot_tsig_add(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                  uint16_t tsig_rcode, const knot_rrset_t *tsig_rr);

/*! \brief Append TSIG RR to message.
 *  \todo Proper documentation.
 */
int knot_tsig_append(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                     const knot_rrset_t *tsig_rr);

/*! \brief Return true if the TSIG RCODE allows signing the packet.
 *  \todo Proper documentation.
 */
static inline bool knot_tsig_can_sign(uint16_t tsig_rcode) {
	return (tsig_rcode == KNOT_RCODE_NOERROR || tsig_rcode == KNOT_TSIG_ERR_BADTIME);
}

/*! @} */
