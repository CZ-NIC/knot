/*!
 * \file tsig-op.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief TSIG signing and validating.
 *
 * \addtogroup libknot
 * @{
 */
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

#ifndef _KNOT_TSIG_OP_H_
#define _KNOT_TSIG_OP_H_

#include <stdint.h>

#include "tsig.h"
#include "rrset.h"

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
                   const knot_key_t *key);

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
                        const knot_key_t *key);

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
                           const knot_key_t *tsig_key);

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
                           const knot_key_t *key);

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
                                const knot_key_t *key);

#endif /* _KNOT_TSIG_H_ */

/*! @} */
