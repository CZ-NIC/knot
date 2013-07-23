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

	/* Control states. */
	{ KNOT_CTL_STOP, "Stopping server." },

	/* Network errors. */
	{ KNOT_NET_EADDR, "Bad address or host name." },
	{ KNOT_NET_ESOCKET, "Can't create socket." },
	{ KNOT_NET_ECONNECT, "Can't connect." },
	{ KNOT_NET_ESEND, "Can't send data." },
	{ KNOT_NET_ERECV, "Can't receive data." },
	{ KNOT_NET_ETIMEOUT, "Network timeout." },

	/* Zone file loader errors. */
	{ FLOADER_EFSTAT, "Fstat error." },
	{ FLOADER_EDIRECTORY, "Zone file is a directory." },
	{ FLOADER_EEMPTY, "Empty zone file." },
	{ FLOADER_EDEFAULTS, "Zone defaults processing error." },
	{ FLOADER_EMMAP, "Mmap error." },
	{ FLOADER_EMUNMAP, "Munmap error." },
	{ FLOADER_ESCANNER, "Zone processing error." },

	/* Zone scanner errors. */
	{ ZSCANNER_UNCOVERED_STATE, "General scanner error." },
	{ ZSCANNER_ELEFT_PARENTHESIS, "Too many left parentheses." },
	{ ZSCANNER_ERIGHT_PARENTHESIS, "Too many right parentheses." },
	{ ZSCANNER_EUNSUPPORTED_TYPE, "Unsupported record type." },
	{ ZSCANNER_EBAD_PREVIOUS_OWNER, "Previous owner is invalid." },
	{ ZSCANNER_EBAD_DNAME_CHAR, "Bad domain name character." },
	{ ZSCANNER_EBAD_OWNER, "Owner is invalid." },
	{ ZSCANNER_ELABEL_OVERFLOW, "Maximal domain name label length has exceeded." },
	{ ZSCANNER_EDNAME_OVERFLOW, "Maximal domain name length has exceeded." },
	{ ZSCANNER_EBAD_NUMBER, "Bad number." },
	{ ZSCANNER_ENUMBER64_OVERFLOW, "Number is too big." },
	{ ZSCANNER_ENUMBER32_OVERFLOW, "Number is bigger than 32 bits." },
	{ ZSCANNER_ENUMBER16_OVERFLOW, "Number is bigger than 16 bits." },
	{ ZSCANNER_ENUMBER8_OVERFLOW, "Number is bigger than 8 bits." },
	{ ZSCANNER_EFLOAT_OVERFLOW, "Float number overflow." },
	{ ZSCANNER_ERDATA_OVERFLOW, "Maximal record data length has exceeded." },
	{ ZSCANNER_EITEM_OVERFLOW, "Maximal item length has exceeded." },
	{ ZSCANNER_EBAD_ADDRESS_CHAR, "Bad address character." },
	{ ZSCANNER_EBAD_IPV4, "Bad IPv4 address." },
	{ ZSCANNER_EBAD_IPV6, "Bad IPv6 address." },
	{ ZSCANNER_EBAD_GATEWAY, "Bad gateway." },
	{ ZSCANNER_EBAD_GATEWAY_KEY, "Bad gateway key." },
	{ ZSCANNER_EBAD_APL, "Bad adress prefix list." },
	{ ZSCANNER_EBAD_RDATA, "Bad record data." },
	{ ZSCANNER_EBAD_HEX_RDATA, "Bad record data in hex format." },
	{ ZSCANNER_EBAD_HEX_CHAR, "Bad hexadecimal character." },
	{ ZSCANNER_EBAD_BASE64_CHAR, "Bad Base64 character." },
	{ ZSCANNER_EBAD_BASE32HEX_CHAR, "Bad Base32hex character." },
	{ ZSCANNER_EBAD_REST, "Unexpected data." },
	{ ZSCANNER_EBAD_TIMESTAMP_CHAR, "Bad timestamp character." },
	{ ZSCANNER_EBAD_TIMESTAMP_LENGTH, "Bad timestamp length." },
	{ ZSCANNER_EBAD_TIMESTAMP, "Bad timestamp." },
	{ ZSCANNER_EBAD_DATE, "Bad date." },
	{ ZSCANNER_EBAD_TIME, "Bad time." },
	{ ZSCANNER_EBAD_TIME_UNIT, "Bad time unit." },
	{ ZSCANNER_EBAD_BITMAP, "Bad bitmap." },
	{ ZSCANNER_ETEXT_OVERFLOW, "Text is too long." },
	{ ZSCANNER_EBAD_TEXT_CHAR, "Bad text character." },
	{ ZSCANNER_EBAD_TEXT, "Bad text string." },
	{ ZSCANNER_EBAD_DIRECTIVE, "Bad directive." },
	{ ZSCANNER_EBAD_TTL, "Bad zone TTL." },
	{ ZSCANNER_EBAD_ORIGIN, "Bad zone origin." },
	{ ZSCANNER_EBAD_INCLUDE_FILENAME, "Bad filename in include directive." },
	{ ZSCANNER_EBAD_INCLUDE_ORIGIN, "Bad origin in include directive." },
	{ ZSCANNER_EUNPROCESSED_INCLUDE, "Include file processing error." },
	{ ZSCANNER_EUNOPENED_INCLUDE, "Include file opening error." },
	{ ZSCANNER_EBAD_RDATA_LENGTH, "The rdata length statement is incorrect." },
	{ ZSCANNER_ECANNOT_TEXT_DATA, "Unable to process text form for this type." },
	{ ZSCANNER_EBAD_LOC_DATA, "Bad zone location data." },
	{ ZSCANNER_EUNKNOWN_BLOCK, "Unknown rdata block." },
	{ ZSCANNER_EBAD_ALGORITHM, "Bad algorithm." },
	{ ZSCANNER_EBAD_CERT_TYPE, "Bad certificate type." },
	{ ZSCANNER_EBAD_EUI_LENGTH, "Bad EUI length." },
	{ ZSCANNER_EBAD_L64_LENGTH, "Bad 64-bit locator." },
	{ ZSCANNER_EBAD_CHAR_COLON, "Missing colon character." },
	{ ZSCANNER_EBAD_CHAR_DASH, "Missing dash character." },

	/* Encoding errors. */
	{ KNOT_BASE64_ESIZE, "Invalid base64 string length." },
	{ KNOT_BASE64_ECHAR, "Invalid base64 character." },
	{ KNOT_BASE32HEX_ESIZE, "Invalid base32hex string length." },
	{ KNOT_BASE32HEX_ECHAR, "Invalid base32hex character." },

	/* Key parsing errors. */
	{ KNOT_KEY_EPUBLIC_KEY_OPEN, "Cannot open public key file." },
	{ KNOT_KEY_EPRIVATE_KEY_OPEN, "Cannot open private key file." },
	{ KNOT_KEY_EPUBLIC_KEY_INVALID, "Public key file is invalid." },

	/* Key signing errors. */
	{ KNOT_DNSSEC_ENOTSUP, "Signing algorithm is not supported." },
	{ KNOT_DNSSEC_EINVALID_KEY, "The signing key is invalid." },
	{ KNOT_DNSSEC_EASSIGN_KEY, "Cannot assign the key." },
	{ KNOT_DNSSEC_ECREATE_DIGEST_CONTEXT, "Cannot create digest context." },
	{ KNOT_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE, "Unexpected signature size." },
	{ KNOT_DNSSEC_EDECODE_RAW_SIGNATURE, "Cannot decode the raw signature." },
	{ KNOT_DNSSEC_ESIGN, "Cannot create the signature." },

	{ KNOT_ERROR, 0 } /* Terminator */
};
