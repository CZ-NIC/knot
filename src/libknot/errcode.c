/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdarg.h>
#include <stdlib.h>

#include "common/errors.h"
#include "libknot/errcode.h"

const error_table_t error_messages[] = {
	{ KNOT_EOK, "OK" },

	/* TSIG errors. */
	{ KNOT_TSIG_EBADSIG,  "failed to verify TSIG MAC" },
	{ KNOT_TSIG_EBADKEY,  "TSIG key not recognized or invalid" },
	{ KNOT_TSIG_EBADTIME, "TSIG signing time out of range" },

	/* Directly mapped error codes. */
	{ KNOT_ENOMEM,       "not enough memory" },
	{ KNOT_EINVAL,       "invalid parameter" },
	{ KNOT_ENOTSUP,      "operation not supported" },
	{ KNOT_EBUSY,        "requested resource is busy" },
	{ KNOT_EAGAIN,       "OS lacked necessary resources" },
	{ KNOT_EACCES,       "operation not permitted" },
	{ KNOT_ECONNREFUSED, "connection refused" },
	{ KNOT_EISCONN,      "already connected" },
	{ KNOT_EADDRINUSE,   "address already in use" },
	{ KNOT_ENOENT,       "not exists" },
	{ KNOT_EEXIST,       "already exists" },
	{ KNOT_ERANGE,       "value is out of range" },

	/* General errors. */
	{ KNOT_ERROR,        "failed" },
	{ KNOT_ENOTRUNNING,  "resource is not running" },
	{ KNOT_EPARSEFAIL,   "parser failed" },
	{ KNOT_ESEMCHECK,    "semantic check" },
	{ KNOT_EEXPIRED,     "resource is expired" },
	{ KNOT_EUPTODATE,    "zone is up-to-date" },
	{ KNOT_EFEWDATA,     "not enough data to parse" },
	{ KNOT_ESPACE,       "not enough space provided" },
	{ KNOT_EMALF,        "malformed data" },
	{ KNOT_ECRYPTO,      "error in crypto library" },
	{ KNOT_ENSEC3PAR,    "missing or wrong NSEC3PARAM record" },
	{ KNOT_ENSEC3CHAIN,  "missing or wrong NSEC3 chain in the zone" },
    { KNOT_ENSEC5CHAIN,  "missing or wrong NSEC5 chain in the zone" },
	{ KNOT_EOUTOFZONE,   "name does not belong to the zone" },
	{ KNOT_EHASH,        "error in hash table" },
	{ KNOT_EZONEINVAL,   "invalid zone file" },
	{ KNOT_EZONENOENT,   "zone file not found" },
	{ KNOT_ENOZONE,      "no such zone found" },
	{ KNOT_ENONODE,      "no such node in zone found" },
	{ KNOT_ENOMASTER,    "no active master" },
	{ KNOT_EDNAMEPTR,    "domain name pointer larger than allowed" },
	{ KNOT_EPAYLOAD,     "payload in OPT RR larger than max wire size" },
	{ KNOT_ECRC,         "CRC check failed" },
	{ KNOT_EPREREQ,      "UPDATE prerequisity not met" },
	{ KNOT_ETTL,         "TTL mismatch" },
	{ KNOT_ENOXFR,       "transfer was not sent" },
	{ KNOT_ENOIXFR,      "transfer is not IXFR (is in AXFR format)" },
	{ KNOT_EXFRREFUSED,  "zone transfer refused by the server" },
	{ KNOT_EDENIED,      "not allowed" },
	{ KNOT_ECONN,        "connection reset" },
	{ KNOT_ETIMEOUT,     "connection timeout" },
	{ KNOT_EIXFRSPACE,   "IXFR reply did not fit in" },
	{ KNOT_ECNAME,       "CNAME loop found in zone" },
	{ KNOT_ENODIFF,      "cannot create zone diff" },
	{ KNOT_EDSDIGESTLEN, "DS digest length does not match digest type" },
	{ KNOT_ENOTSIG,      "expected a TSIG or SIG(0)" },
	{ KNOT_ELIMIT,       "exceeded response rate limit" },
	{ KNOT_EWRITABLE,    "file is not writable" },
	{ KNOT_EOF,          "end of file" },

	/* Control states. */
	{ KNOT_CTL_STOP,     "stopping server" },
	{ KNOT_CTL_ACCEPTED, "command accepted" },

	/* Network errors. */
	{ KNOT_NET_EADDR,    "bad address or host name" },
	{ KNOT_NET_ESOCKET,  "can't create socket" },
	{ KNOT_NET_ECONNECT, "can't connect" },
	{ KNOT_NET_ESEND,    "can't send data" },
	{ KNOT_NET_ERECV,    "can't receive data" },
	{ KNOT_NET_ETIMEOUT, "network timeout" },

	/* Encoding errors. */
	{ KNOT_BASE64_ESIZE,    "invalid base64 string length" },
	{ KNOT_BASE64_ECHAR,    "invalid base64 character" },
	{ KNOT_BASE32HEX_ESIZE, "invalid base32hex string length" },
	{ KNOT_BASE32HEX_ECHAR, "invalid base32hex character" },

	/* Key parsing errors. */
	{ KNOT_KEY_EPUBLIC_KEY_OPEN,    "cannot open public key file" },
	{ KNOT_KEY_EPRIVATE_KEY_OPEN,   "cannot open private key file" },
	{ KNOT_KEY_EPUBLIC_KEY_INVALID, "public key file is invalid" },

	/* Key signing/verification errors. */
	{ KNOT_DNSSEC_ENOTSUP,                    "algorithm is not supported" },
	{ KNOT_DNSSEC_EINVALID_KEY,               "the signing key is invalid" },
	{ KNOT_DNSSEC_EASSIGN_KEY,                "cannot assign the key" },
	{ KNOT_DNSSEC_ECREATE_DIGEST_CONTEXT,     "cannot create digest context" },
	{ KNOT_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE, "unexpected signature size" },
	{ KNOT_DNSSEC_EDECODE_RAW_SIGNATURE,      "cannot decode the raw signature" },
	{ KNOT_DNSSEC_EINVALID_SIGNATURE,         "signature is invalid" },
	{ KNOT_DNSSEC_ESIGN,                      "cannot create the signature" },
	{ KNOT_DNSSEC_ENOKEY,                     "no keys for signing" },
	{ KNOT_DNSSEC_ENOKEYDIR,                  "keydir does not exist" },
	{ KNOT_DNSSEC_EMISSINGKEYTYPE,            "missing active KSK or ZSK" },
    
    /* Key signing/verification errors for NSEC5. */
    { KNOT_NSEC5_ENOTSUP,                    "NSEC5: algorithm is not supported" },
    { KNOT_NSEC5_EINVALID_KEY,               "NSEC5: the signing key is invalid" },
    { KNOT_NSEC5_EASSIGN_KEY,                "NSEC5: cannot assign the key" },
    { KNOT_NSEC5_ECREATE_DIGEST_CONTEXT,     "NSEC5: cannot create digest context" },
    { KNOT_NSEC5_EUNEXPECTED_SIGNATURE_SIZE, "NSEC5: unexpected signature size" },
    { KNOT_NSEC5_EDECODE_RAW_SIGNATURE,      "NSEC5: cannot decode the raw signature" },
    { KNOT_NSEC5_EINVALID_SIGNATURE,         "NSEC5: signature is invalid" },
    { KNOT_NSEC5_ESIGN,                      "NSEC5: cannot create the signature" },
    { KNOT_NSEC5_ENOKEY,                     "NSEC5: no keys for signing" },
    { KNOT_NSEC5_ENOKEYDIR,                  "NSEC5: keydir does not exist" },
    { KNOT_NSEC5_EMISSINGKEYTYPE,            "NSEC5: missing active KSK or ZSK" },

	/* NSEC3 errors. */
	{ KNOT_NSEC3_ECOMPUTE_HASH, "cannot compute NSEC3 hash" },
    
    /* NSEC5 errors. */
    { KNOT_NSEC5_ECOMPUTE_HASH, "cannot compute NSEC5 hash" },

	/* Dynamic backend errors. */
	{ KNOT_DATABASE_ERROR, "unspecified database error" },
    
    { KNOT_ZONE_KEY_ADD_ERROR, "cannot add key to zone: zone_sign.c" },

	{ KNOT_ERROR, NULL } /* Terminator */
};

const char *knot_strerror(int code)
{
	return error_to_str(error_messages, code);
}

int knot_map_errno_internal(int fallback, int arg0, ...)
{
	/* Iterate all variable-length arguments. */
	va_list ap;
	va_start(ap, arg0);

	/* KNOT_ERROR serves as a sentinel. */
	for (int c = arg0; c != 0; c = va_arg(ap, int)) {

		/* Error code matches with mapped. */
		if (c == errno) {
			/* Return negative value of the code. */
			va_end(ap);
			return knot_errno_to_error(abs(c));
		}
	}
	va_end(ap);

	/* Fallback error code. */
	return KNOT_ERROR;
}
