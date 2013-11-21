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

#include <config.h>
#include "common/errcode.h"
#include "common/errors.h"

const error_table_t knot_error_msgs[] = {
	{ KNOT_EOK, "OK" },

	/* TSIG errors. */
	{ KNOT_TSIG_EBADSIG, "Failed to verify TSIG MAC." },
	{ KNOT_TSIG_EBADKEY, "TSIG key not recognized or invalid." },
	{ KNOT_TSIG_EBADTIME, "TSIG signing time out of range." },

	/* Directly mapped error codes. */
	{ KNOT_ENOMEM, "Not enough memory." },
	{ KNOT_EINVAL, "Invalid parameter." },
	{ KNOT_ENOTSUP, "Operation not supported." },
	{ KNOT_EBUSY,   "Requested resource is busy." },
	{ KNOT_EAGAIN, "OS lacked necessary resources." },
	{ KNOT_EACCES,  "Operation not permitted." },
	{ KNOT_ECONNREFUSED, "Connection refused." },
	{ KNOT_EISCONN, "Already connected." },
	{ KNOT_EADDRINUSE, "Address already in use." },
	{ KNOT_ENOENT, "Resource not found." },
	{ KNOT_ERANGE, "Value is out of range." },

	/* General errors. */
	{ KNOT_ERROR, "General error." },
	{ KNOT_ENOTRUNNING, "Resource is not running." },
	{ KNOT_EPARSEFAIL, "Parser failed." },
	{ KNOT_ENOIPV6, "IPv6 support disabled." },
	{ KNOT_EEXPIRED, "Resource is expired." },
	{ KNOT_EUPTODATE, "Zone is up-to-date." },
	{ KNOT_EFEWDATA, "Not enough data to parse." },
	{ KNOT_ESPACE, "Not enough space provided." },
	{ KNOT_EMALF, "Malformed data." },
	{ KNOT_ECRYPTO, "Error in crypto library." },
	{ KNOT_ENSEC3PAR, "Missing or wrong NSEC3PARAM record." },
	{ KNOT_ENSEC3CHAIN, "Missing or wrong NSEC3 chain in the zone." },
	{ KNOT_EOUTOFZONE, "Name does not belong to the zone." },
	{ KNOT_EHASH, "Error in hash table." },
	{ KNOT_EZONEINVAL, "Invalid zone file." },
	{ KNOT_EZONENOENT, "Zone file not found." },
	{ KNOT_ENOZONE, "No such zone found." },
	{ KNOT_ENONODE, "No such node in zone found." },
	{ KNOT_ENORRSET, "No such RRSet found." },
	{ KNOT_EDNAMEPTR, "Domain name pointer larger than allowed." },
	{ KNOT_EPAYLOAD, "Payload in OPT RR larger than max wire size." },
	{ KNOT_ECRC, "CRC check failed." },
	{ KNOT_EPREREQ, "UPDATE prerequisity not met." },
	{ KNOT_ENOXFR, "Transfer was not sent." },
	{ KNOT_ENOIXFR, "Transfer is not IXFR (is in AXFR format)." },
	{ KNOT_EXFRREFUSED, "Zone transfer refused by the server." },
	{ KNOT_EDENIED, "Not allowed." },
	{ KNOT_ECONN, "Connection reset." },
	{ KNOT_EIXFRSPACE, "IXFR reply did not fit in." },
	{ KNOT_ECNAME, "CNAME loop found in zone." },
	{ KNOT_ENODIFF, "Cannot create zone diff." },
	{ KNOT_EDSDIGESTLEN, "DS digest length does not match digest type." },
	{ KNOT_ENOTSIG, "expected a TSIG or SIG(0)" },
	{ KNOT_ELIMIT, "Exceeded response rate limit." },
	{ KNOT_EWRITABLE, "File is not writable." },

	/* Control states. */
	{ KNOT_CTL_STOP, "Stopping server." },

	/* Network errors. */
	{ KNOT_NET_EADDR, "Bad address or host name." },
	{ KNOT_NET_ESOCKET, "Can't create socket." },
	{ KNOT_NET_ECONNECT, "Can't connect." },
	{ KNOT_NET_ESEND, "Can't send data." },
	{ KNOT_NET_ERECV, "Can't receive data." },
	{ KNOT_NET_ETIMEOUT, "Network timeout." },

	/* Encoding errors. */
	{ KNOT_BASE64_ESIZE, "Invalid base64 string length." },
	{ KNOT_BASE64_ECHAR, "Invalid base64 character." },
	{ KNOT_BASE32HEX_ESIZE, "Invalid base32hex string length." },
	{ KNOT_BASE32HEX_ECHAR, "Invalid base32hex character." },

	/* Key parsing errors. */
	{ KNOT_KEY_EPUBLIC_KEY_OPEN, "Cannot open public key file." },
	{ KNOT_KEY_EPRIVATE_KEY_OPEN, "Cannot open private key file." },
	{ KNOT_KEY_EPUBLIC_KEY_INVALID, "Public key file is invalid." },

	/* Key signing/verification errors. */
	{ KNOT_DNSSEC_ENOTSUP, "Algorithm is not supported." },
	{ KNOT_DNSSEC_EINVALID_KEY, "The signing key is invalid." },
	{ KNOT_DNSSEC_EASSIGN_KEY, "Cannot assign the key." },
	{ KNOT_DNSSEC_ECREATE_DIGEST_CONTEXT, "Cannot create digest context." },
	{ KNOT_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE, "Unexpected signature size." },
	{ KNOT_DNSSEC_EDECODE_RAW_SIGNATURE, "Cannot decode the raw signature." },
	{ KNOT_DNSSEC_EINVALID_SIGNATURE, "Signature is invalid." },
	{ KNOT_DNSSEC_ESIGN, "Cannot create the signature." },
	{ KNOT_DNSSEC_ENOKEY, "No keys for signing." },
	{ KNOT_DNSSEC_ENOKEYDIR, "Keydir does not exist." },

	/* NSEC3 errors. */
	{ KNOT_NSEC3_ECOMPUTE_HASH, "Cannot compute NSEC3 hash." },

	{ KNOT_ERROR, 0 } /* Terminator */
};
