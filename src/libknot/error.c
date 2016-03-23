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

#include <stdio.h>
#if HAVE_LMDB
#include <lmdb.h>
#endif

#include "libknot/attribute.h"
#include "libknot/error.h"
#include "dnssec/error.h"

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
	{ KNOT_EWRITABLE,    "file is not writable" },
	{ KNOT_EOF,          "end of file" },
	{ KNOT_ESYSTEM,      "system error" },
	{ KNOT_EFILE,        "file error" },

	/* Control states. */
	{ KNOT_CTL_ESTOP,     "stopping server" },
	{ KNOT_CTL_EACCEPTED, "command accepted" },
	{ KNOT_CTL_EARG_REQ,  "argument required" },

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
	{ KNOT_CONF_ETXN,      "failed to open another config DB transaction" },
	{ KNOT_CONF_ENOTXN,    "no active config DB transaction" },
	{ KNOT_CONF_EMANYTXN,  "too many nested config DB transactions" },

	/* Processing errors. */
	{ KNOT_LAYER_ERROR, "processing layer error" },

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

/*!
 * \brief Get a fallback error message for unknown error code.
 */
static const char *fallback_message(int code)
{
	static __thread char buffer[128];
	if (snprintf(buffer, sizeof(buffer), "unknown error %d", code) < 0) {
		buffer[0] = '\0';
	}
	return buffer;
}

_public_
const char *knot_strerror(int code)
{
	if (KNOT_ERROR_MIN <= code && code <= 0) {
		const char *msg = lookup_message(code);
		if (msg) {
			return msg;
		}
	}

	if (DNSSEC_ERROR_MIN <= code && code <= DNSSEC_ERROR_MAX) {
		return dnssec_strerror(code);
	}

#if HAVE_LMDB
	if (MDB_KEYEXIST <= code && code <= MDB_LAST_ERRCODE) {
		return mdb_strerror(code);
	}
#endif

	return fallback_message(code);
}
