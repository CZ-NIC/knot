/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>

#include "libdnssec/error.h"
#include "libdnssec/shared/shared.h"

typedef struct error_message_t {
	int code;
	const char *text;
} error_message_t;

static const error_message_t ERROR_MESSAGES[] = {
	{ DNSSEC_EOK,			"no error" },

	{ DNSSEC_ENOMEM,		"not enough memory" },
	{ DNSSEC_EINVAL,		"invalid argument" },
	{ DNSSEC_ENOENT,		"no such file or directory" },

	{ DNSSEC_ERROR,			"unspecified error" },
	{ DNSSEC_NOT_IMPLEMENTED_ERROR,	"not implemented" },
	{ DNSSEC_MALFORMED_DATA,	"malformed data" },
	{ DNSSEC_OUT_OF_RANGE,		"value out of range" },
	{ DNSSEC_NOT_FOUND,		"not found" },

	{ DNSSEC_PKCS8_IMPORT_ERROR,	"PKCS #8 import error" },
	{ DNSSEC_KEY_EXPORT_ERROR,	"key export error" },
	{ DNSSEC_KEY_IMPORT_ERROR,	"key import error" },
	{ DNSSEC_KEY_GENERATE_ERROR,	"key generation error" },

	{ DNSSEC_INVALID_PUBLIC_KEY,	"invalid public key" },
	{ DNSSEC_INVALID_PRIVATE_KEY,	"invalid private key" },
	{ DNSSEC_INVALID_KEY_ALGORITHM,	"invalid key algorithm" },
	{ DNSSEC_INVALID_KEY_SIZE,	"invalid key size" },
	{ DNSSEC_INVALID_KEY_ID,	"invalid key ID" },
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

	{ DNSSEC_CONFIG_MALFORMED,	"malformed config value" },
	{ DNSSEC_CONFIG_INVALID_KEY_ID,	"invalid key ID in config" },

	{ DNSSEC_KEYSTORE_INVALID_BACKEND, "invalid KASP keystore backend" },
	{ DNSSEC_KEYSTORE_INVALID_CONFIG,  "invalid KASP keystore configuration" },

	{ DNSSEC_P11_FAILED_TO_LOAD_MODULE, "failed to load PKCS #11 module" },
	{ DNSSEC_P11_TOO_MANY_MODULES,      "too many PKCS #11 modules loaded" },
	{ DNSSEC_P11_TOKEN_NOT_AVAILABLE,   "PKCS #11 token not available" },

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
