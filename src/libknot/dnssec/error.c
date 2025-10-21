/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <string.h>

#include "libknot/dnssec/error.h"
#include "libknot/dnssec/shared/shared.h"

typedef struct error_message_t {
	int code;
	const char *text;
} error_message_t;

static const error_message_t ERROR_MESSAGES[] = {
	{ KNOT_EOK,			"no error" },

	{ KNOT_ENOMEM,		"not enough memory" },
	{ KNOT_EINVAL,		"invalid argument" },
	{ KNOT_ENOENT,		"no such file or directory" },

	{ DNSSEC_ERROR,			"unspecified error" },
	{ KNOT_ENOTSUP,	"not implemented" },
	{ KNOT_EMALF,	"malformed data" },
	{ KNOT_ENOENT,		"not found" },

	{ KNOT_KEY_EIMPORT,	"PKCS #8 import error" },
	{ KNOT_KEY_EEXPORT,	"key export error" },
	{ KNOT_KEY_EIMPORT,	"key import error" },
	{ KNOT_KEY_EGENERATE,	"key generation error" },

	{ KNOT_INVALID_PUBLIC_KEY,	"invalid public key" },
	{ DNSSEC_INVALID_PRIVATE_KEY,	"invalid private key" },
	{ KNOT_INVALID_KEY_ALGORITHM,	"invalid key algorithm" },
	{ KNOT_INVALID_KEY_SIZE,	"invalid key size" },
	{ KNOT_INVALID_KEY_ID,	"invalid key ID" },
	{ DNSSEC_INVALID_KEY_NAME,	"invalid key name" },

	{ DNSSEC_NO_PUBLIC_KEY,		"no public key" },
	{ DNSSEC_NO_PRIVATE_KEY,	"no private key" },
	{ DNSSEC_KEY_ALREADY_PRESENT,	"key already present" },

	{ DNSSEC_SIGN_INIT_ERROR,	"signing initialization error" },
	{ DNSSEC_SIGN_ERROR,		"signing error" },
	{ DNSSEC_INVALID_SIGNATURE,	"invalid signature" },

	{ DNSSEC_INVALID_NSEC3_ALGORITHM, "invalid NSEC3 algorithm" },
	{ DNSSEC_NSEC3_HASHING_ERROR,	"NSEC3 hashing error" },

	{ DNSSEC_INVALID_DS_ALGORITHM,	"invalid DS algorithm" },
	{ DNSSEC_DS_HASHING_ERROR,	"DS hashing error" },

	{ DNSSEC_KEYSTORE_INVALID_CONFIG,  "invalid KASP keystore configuration" },

	{ DNSSEC_P11_FAILED_TO_LOAD_MODULE, "failed to load PKCS #11 module" },
	{ DNSSEC_P11_TOO_MANY_MODULES,      "too many PKCS #11 modules loaded" },
	{ DNSSEC_P11_TOKEN_NOT_AVAILABLE,   "PKCS #11 token not available" },

	{ DNSSEC_INVALID_DIGEST_ALGORITHM,  "invalid digest algorithm" },
	{ DNSSEC_DIGEST_ERROR,              "digest error" },

	{ 0 }
};

_public_
const char *dnssec_strerror(int error)
{
	for (const error_message_t *m = ERROR_MESSAGES; m->text; m++) {
		if (m->code == error) {
			return m->text;
		}
	}

	return NULL;
}
