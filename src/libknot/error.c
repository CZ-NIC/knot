/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <lmdb.h>

#include "libknot/attribute.h"
#include "libknot/error.h"

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
	{ KNOT_EAGAIN,        "temporarily out of resources" },
	{ KNOT_ENOBUFS,       "no buffers" },
	{ KNOT_EMFILE,        "too many open files" },
	{ KNOT_ENFILE,        "too many open files in system" },
	{ KNOT_EACCES,        "operation not permitted" },
	{ KNOT_EISCONN,       "already connected" },
	{ KNOT_ECONNREFUSED,  "connection refused" },
	{ KNOT_EALREADY,      "operation already in progress" },
	{ KNOT_ECONNRESET,    "connection reset by peer" },
	{ KNOT_ECONNABORTED,  "connection aborted" },
	{ KNOT_ENETRESET,     "connection aborted by network" },
	{ KNOT_EHOSTUNREACH,  "host is unreachable" },
	{ KNOT_ENETUNREACH,   "network is unreachable" },
	{ KNOT_EHOSTDOWN,     "host is down" },
	{ KNOT_ENETDOWN,      "network is down" },
	{ KNOT_EADDRINUSE,    "address already in use" },
	{ KNOT_ENOENT,        "not exists" },
	{ KNOT_EEXIST,        "already exists" },
	{ KNOT_ERANGE,        "value is out of range" },
	{ KNOT_EADDRNOTAVAIL, "address is not available" },
	{ KNOT_ENOTDIR,       "not a directory" },
	{ KNOT_EPERM,         "operation not permitted" },
	{ KNOT_EROFS,         "read-only file system" },

	{ KNOT_ERRNO_ERROR,   "unknown system error" },

	/* General errors. */
	{ KNOT_ERROR,        "failed" },
	{ KNOT_EPARSEFAIL,   "parser failed" },
	{ KNOT_ESEMCHECK,    "semantic check" },
	{ KNOT_EUPTODATE,    "zone is up-to-date" },
	{ KNOT_EFEWDATA,     "not enough data to parse" },
	{ KNOT_ESPACE,       "not enough space provided" },
	{ KNOT_EMALF,        "malformed data" },
	{ KNOT_ETRYAGAIN,    "try again later" },
	{ KNOT_EOUTOFZONE,   "name does not belong to the zone" },
	{ KNOT_EZONEINVAL,   "invalid zone file" },
	{ KNOT_ENOZONE,      "no such zone found" },
	{ KNOT_ENONODE,      "no such node in zone found" },
	{ KNOT_ENORECORD,    "no such record in zone found" },
	{ KNOT_EISRECORD,    "such record already exists in zone" },
	{ KNOT_ENOMASTER,    "no usable master" },
	{ KNOT_EPREREQ,      "UPDATE prerequisite not met" },
	{ KNOT_ETTL,         "TTL mismatch" },
	{ KNOT_ENOTTL,       "no TTL specified" },
	{ KNOT_ENOXFR,       "transfer was not sent" },
	{ KNOT_EDENIED,      "not allowed" },
	{ KNOT_ECONN,        "connection reset" },
	{ KNOT_ETIMEOUT,     "connection timeout" },
	{ KNOT_ENODIFF,      "cannot create zone diff" },
	{ KNOT_ENOTSIG,      "expected a TSIG or SIG(0)" },
	{ KNOT_ELIMIT,       "exceeded limit" },
	{ KNOT_EZONESIZE,    "zone size exceeded" },
	{ KNOT_EOF,          "end of file" },
	{ KNOT_ESYSTEM,      "system error" },
	{ KNOT_EFILE,        "file error" },
	{ KNOT_ESOAINVAL,    "SOA mismatch" },
	{ KNOT_ETRAIL,       "trailing data" },
	{ KNOT_EPROCESSING,  "processing error" },
	{ KNOT_EPROGRESS,    "in progress" },
	{ KNOT_ELOOP,        "loop detected" },
	{ KNOT_EPROGRAM,     "program not loaded" },
	{ KNOT_EFD,          "file descriptor error" },
	{ KNOT_ENOPARAM,     "missing parameter" },
	{ KNOT_EXPARAM,      "parameter conflict" },
	{ KNOT_EEMPTYZONE,   "zone is empty" },
	{ KNOT_ENODB,        "database does not exist" },
	{ KNOT_EUNREACH,     "remote known to be unreachable" },
	{ KNOT_EBADCERT,     "invalid certificate" },
	{ KNOT_EFACCES,      "file permission denied" },
	{ KNOT_EBACKUPDATA,  "requested data not in backup" },
	{ KNOT_ECPUCOMPAT,   "incompatible CPU architecture" },
	{ KNOT_EMODINVAL,    "invalid module" },
	{ KNOT_EEXTERNAL,    "external validation failed" },
	{ KNOT_ERDB,         "zone database error" },
	{ KNOT_ENOTYPE,      "no such RR type" },
	{ KNOT_ENOCLASS,     "no such CLASS" },

	{ KNOT_GENERAL_ERROR, "unknown general error" },

	/* Control states. */
	{ KNOT_CTL_ESTOP,     "stopping server" },
	{ KNOT_CTL_EZONE,     "operation failed for some zones" },

	/* Network errors. */
	{ KNOT_NET_EADDR,    "bad address or host name" },
	{ KNOT_NET_ESOCKET,  "can't create socket" },
	{ KNOT_NET_ECONNECT, "can't connect" },
	{ KNOT_NET_EHSHAKE,  "handshake failed" },
	{ KNOT_NET_ESEND,    "can't send data" },
	{ KNOT_NET_ERECV,    "can't receive data" },
	{ KNOT_NET_ETIMEOUT, "network timeout" },
	{ KNOT_NET_EAGAIN,   "try network operation again" },

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
	{ KNOT_TXN_ETHREAD,    "transaction thread mismatch" },

	/* DNSSEC errors. */
	{ KNOT_ENSEC3PAR,              "missing or wrong NSEC3PARAM record" },
	{ KNOT_ENSEC3CHAIN,            "missing or wrong NSEC3 chain in the zone" },
	{ KNOT_INVALID_PUBLIC_KEY,     "invalid public key" },
	{ KNOT_INVALID_PRIVATE_KEY,    "invalid private key" },
	{ KNOT_INVALID_KEY_ALGORITHM,  "invalid key algorithm" },
	{ KNOT_INVALID_KEY_SIZE,       "invalid key size" },
	{ KNOT_INVALID_KEY_ID,         "invalid key ID" },
	{ KNOT_INVALID_KEY_NAME,       "invalid key name" },
	{ KNOT_INVALID_SIGNATURE,      "invalid signature" },
	{ KNOT_NO_PUBLIC_KEY,          "no public key" },
	{ KNOT_NO_PRIVATE_KEY,         "no private key" },
	{ KNOT_NO_READY_KEY,           "no key ready for submission" },
	{ KNOT_ESOON_EXPIRE,           "oncoming RRSIG expiration" },
	{ KNOT_DNSSEC_ENOKEY,          "no keys for signing" },
	{ KNOT_DNSSEC_ENOKEYSTORE,     "no suitable keystore" },
	{ KNOT_DNSSEC_EMISSINGKEYTYPE, "missing active KSK or ZSK" },
	{ KNOT_DNSSEC_ENOSIG,          "no valid signature for a record" },
	{ KNOT_DNSSEC_ENONSEC,         "missing NSEC(3) record" },
	{ KNOT_DNSSEC_ENSEC_BITMAP,    "wrong NSEC(3) bitmap" },
	{ KNOT_DNSSEC_ENSEC_CHAIN,     "inconsistent NSEC(3) chain" },
	{ KNOT_DNSSEC_ENSEC3_OPTOUT,   "wrong NSEC3 opt-out" },
	{ KNOT_DNSSEC_EKEYTAG_LIMIT,   "many keys with equal keytag" },
	{ KNOT_DNSSEC_EXTRA_NSEC,      "superfluous NSEC(3)" },
	{ KNOT_KEY_EIMPORT,            "failed to import key" },
	{ KNOT_KEY_EEXPORT,            "failed to export key" },
	{ KNOT_KEY_EGENERATE,          "failed to generate key" },
	{ KNOT_EALGORITHM,             "invalid hash algorithm" },
	{ KNOT_ECRYPTO,                "crypto operation failed" },
	{ KNOT_P11_ELOAD,              "failed to load PKCS #11 module" },
	{ KNOT_P11_ETOKEN,             "PKCS #11 token not available" },
	{ KNOT_P11_ECONFIG,            "invalid PKCS #11 configuration" },

	/* Terminator */
	{ KNOT_ERROR, NULL }
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
const char *knot_strerror(int code)
{
	const char *msg;

	switch (code) {
	case INT_MIN: // Cannot convert to a positive value.
		code = KNOT_ERROR;
		// FALLTHROUGH
	case KNOT_ERROR_MIN ... KNOT_EOK:
		msg = lookup_message(code); break;
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
