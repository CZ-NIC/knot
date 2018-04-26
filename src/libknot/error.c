/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <lmdb.h>

#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libdnssec/error.h"

struct error {
	int code;
	const char *message;
};

static const struct error errors[] = {
	{ KNOT_EOK, "OK" },

	/* Directly mapped error codes. */
	{ KNOT_ENOMEM,        "not enough memory" },
	{ KNOT_EINVAL,        "invalid parameter" },
	{ KNOT_ENOTSUP,       "operation not supported" },
	{ KNOT_EBUSY,         "requested resource is busy" },
	{ KNOT_EAGAIN,        "OS lacked necessary resources" },
	{ KNOT_EACCES,        "operation not permitted" },
	{ KNOT_ECONNREFUSED,  "connection refused" },
	{ KNOT_EISCONN,       "already connected" },
	{ KNOT_EADDRINUSE,    "address already in use" },
	{ KNOT_ENOENT,        "not exists" },
	{ KNOT_EEXIST,        "already exists" },
	{ KNOT_ERANGE,        "value is out of range" },
	{ KNOT_EADDRNOTAVAIL, "address is not available" },

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
	{ KNOT_EOUTOFZONE,   "name does not belong to the zone" },
	{ KNOT_EHASH,        "error in hash table" },
	{ KNOT_EZONEINVAL,   "invalid zone file" },
	{ KNOT_EZONENOENT,   "zone file not found" },
	{ KNOT_ENOZONE,      "no such zone found" },
	{ KNOT_ENONODE,      "no such node in zone found" },
	{ KNOT_ENORECORD,    "no such record in zone found" },
	{ KNOT_ENOMASTER,    "no usable master" },
	{ KNOT_EDNAMEPTR,    "domain name pointer larger than allowed" },
	{ KNOT_EPAYLOAD,     "invalid EDNS payload size" },
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
	{ KNOT_EZONESIZE,    "zone size exceeded" },
	{ KNOT_EWRITABLE,    "file is not writable" },
	{ KNOT_EOF,          "end of file" },
	{ KNOT_ESYSTEM,      "system error" },
	{ KNOT_EFILE,        "file error" },
	{ KNOT_ESOAINVAL,    "SOA mismatch" },
	{ KNOT_ETRAIL,       "trailing data" },

	/* Control states. */
	{ KNOT_CTL_ESTOP,     "stopping server" },

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

	/* TSIG errors. */
	{ KNOT_TSIG_EBADSIG,   "failed to verify TSIG" },
	{ KNOT_TSIG_EBADKEY,   "TSIG key not recognized or invalid" },
	{ KNOT_TSIG_EBADTIME,  "TSIG out of time window" },
	{ KNOT_TSIG_EBADTRUNC, "TSIG bad truncation" },

	/* Key parsing errors. */
	{ KNOT_KEY_EPUBLIC_KEY_OPEN,    "cannot open public key file" },
	{ KNOT_KEY_EPRIVATE_KEY_OPEN,   "cannot open private key file" },
	{ KNOT_KEY_EPUBLIC_KEY_INVALID, "public key file is invalid" },

	/* DNSSEC errors. */
	{ KNOT_DNSSEC_ENOKEY,          "no keys for signing" },
	{ KNOT_DNSSEC_EMISSINGKEYTYPE, "missing active KSK or ZSK" },

	/* Yparser errors. */
	{ KNOT_YP_ECHAR_TAB,     "tabulator character is not allowed" },
	{ KNOT_YP_EINVAL_ITEM,   "invalid item" },
	{ KNOT_YP_EINVAL_ID,     "invalid identifier" },
	{ KNOT_YP_EINVAL_DATA,   "invalid value" },
	{ KNOT_YP_EINVAL_INDENT, "invalid indentation" },
	{ KNOT_YP_ENOTSUP_DATA,  "value not supported" },
	{ KNOT_YP_ENOTSUP_ID,    "identifier not supported" },
	{ KNOT_YP_ENODATA,       "missing value" },
	{ KNOT_YP_ENOID,         "missing identifier" },

	/* Configuration errors. */
	{ KNOT_CONF_ENOTINIT,  "config DB not initialized" },
	{ KNOT_CONF_EVERSION,  "invalid config DB version" },
	{ KNOT_CONF_EREDEFINE, "duplicate identifier" },

	/* Transaction errors. */
	{ KNOT_TXN_EEXISTS,    "too many transactions" },
	{ KNOT_TXN_ENOTEXISTS, "no active transaction" },

	/* Processing errors. */
	{ KNOT_LAYER_ERROR, "processing layer error" },

	/* DNSSEC errors. */
	{ KNOT_INVALID_PUBLIC_KEY,    "invalid public key" },
	{ KNOT_INVALID_PRIVATE_KEY,   "invalid private key" },
	{ KNOT_INVALID_KEY_ALGORITHM, "invalid key algorithm" },
	{ KNOT_INVALID_KEY_SIZE,      "invalid key size" },
	{ KNOT_INVALID_KEY_ID,        "invalid key ID" },
	{ KNOT_INVALID_KEY_NAME,      "invalid key name" },
	{ KNOT_NO_PUBLIC_KEY,         "no public key" },
	{ KNOT_NO_PRIVATE_KEY,        "no private key" },

	{ KNOT_ERROR, NULL } /* Terminator */
};

/*!
 * \brief Lookup error message by error code.
 */
static const char *lookup_message(int code)
{
	for (const struct error *e = errors; e->message; e++) {
		if (e->code == code) {
			return e->message;
		}
	}

	return NULL;
}

_public_
int knot_error_from_libdnssec(int libdnssec_errcode)
{
	switch (libdnssec_errcode) {
	case DNSSEC_ERROR:
		return KNOT_ERROR;
	case DNSSEC_MALFORMED_DATA:
		return KNOT_EMALF;
	case DNSSEC_OUT_OF_RANGE:
		return KNOT_ERANGE;
	case DNSSEC_NOT_FOUND:
		return KNOT_ENOENT;
	case DNSSEC_NO_PUBLIC_KEY:
	case DNSSEC_NO_PRIVATE_KEY:
		return KNOT_DNSSEC_ENOKEY;
	// EOK, EINVAL, ENOMEM and ENOENT are identical, no need to translate
	case DNSSEC_INVALID_PUBLIC_KEY ... DNSSEC_INVALID_KEY_NAME:
		return libdnssec_errcode
		       - DNSSEC_INVALID_PUBLIC_KEY + KNOT_INVALID_PUBLIC_KEY;
	default:
		return libdnssec_errcode;
	}
}

_public_
const char *knot_strerror(int code)
{
	const char *msg;

	switch (code) {
	case INT_MIN: // Cannot convert to a positive value.
		code = KNOT_ERROR;
		// FALLTHROUGH
	case KNOT_ERROR_MIN ... KNOT_EOK:
		msg = lookup_message(code); break;
	case DNSSEC_ERROR_MIN ... DNSSEC_ERROR_MAX:
		msg = dnssec_strerror(code); break;
	case MDB_KEYEXIST ... MDB_LAST_ERRCODE:
		msg = mdb_strerror(code); break;
	default:
		msg = NULL;
	}

	if (msg != NULL) {
		return msg;
	} else {
		// strerror_r would be better but it requires thread local storage.
		return strerror(abs(code));
	}
}
