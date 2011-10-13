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
/*  Copyright (C) 2011 CZ.NIC Labs

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

#include "rrset.h"

/*!
 * \brief Generate TSIG signature of a message.
 *
 * \param msg Message to be signed.
 * \param msg_len Size of the message in bytes.
 * \param request_mac Request MAC. (may be NULL).
 * \param request_mac_len Size of the request MAC in bytes.
 * \param tsig_rr RRSet containing the TSIG RR to be used. Data from the RR are 
 *                appended to the signed message.
 * \param mac Generated message digest.
 * \param size Size of the digest in bytes.
 *
 * \retval KNOT_EOK if everything went OK.
 * \retval TODO
 */
int knot_tsig_sign(const uint8_t *msg, size_t msg_len, 
                   const uint8_t *request_mac, size_t request_mac_len,
                   const knot_rrset_t *tsig_rr,
                   uint8_t *mac, size_t size);

/*!
 * \brief Generate TSIG signature of a 2nd or later message in a TCP session.
 *
 * \param msg Message to be signed.
 * \param msg_len Size of the message in bytes.
 * \param prev_digest Previous digest sent by the server in the session.
 * \param prev_digest_len Size of the previous digest in bytes.
 * \param tsig_rr RRSet containing the TSIG RR to be used. Data from the RR are 
 *                appended to the signed message.
 * \param mac Generated message digest.
 * \param size Size of the digest in bytes.
 *
 * \retval KNOT_EOK if successful.
 * \retval TODO
 */
int knot_tsig_sign_next(const uint8_t *msg, size_t msg_len, 
                        const uint8_t *prev_digest, size_t prev_digest_len,
                        const knot_rrset_t *tsig_rr,
                        uint8_t *mac, size_t size);

/*!
 * \brief Checks incoming request.
 *
 * \param tsig_rr TSIG extracted from the packet.
 * \param wire Wire format of the packet (including the TSIG RR).
 * \param size Size of the wire format of packet in bytes.
 *
 * \retval KNOT_EOK If the signature is valid.
 * \retval TODO
 */
int knot_tsig_server_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size);

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
 */
int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len);

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
 */
int knot_tsig_client_check_next(const knot_rrset_t *tsig_rr,
                                const uint8_t *wire, size_t size,
                                const uint8_t *prev_digest, 
                                size_t prev_digest_len);

#endif /* _KNOT_TSIG_H_ */

/*! @} */
