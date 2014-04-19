#include "error.h"
#include "shared.h"

typedef struct error_message_t {
	int code;
	const char *text;
} error_message_t;

const error_message_t ERROR_MESSAGES[] = {
	{ DNSSEC_EOK,			"No error" },

	{ DNSSEC_ENOMEM,		"Not enough memory" },
	{ DNSSEC_EINVAL,		"Invalid argument" },

	{ DNSSEC_ERROR,			"Unspecified error" },
	{ DNSSEC_NOT_IMPLEMENTED_ERROR,	"Not implemeted" },
	{ DNSSEC_MALFORMED_DATA,	"Malformed data" },
	{ DNSSEC_OUT_OF_RANGE,		"Value out of range" },
	{ DNSSEC_NOT_FOUND,		"Not found" },

	{ DNSSEC_PKCS8_IMPORT_ERROR,	"PKCS #8 import error" },
	{ DNSSEC_KEY_EXPORT_ERROR,	"Key export error" },
	{ DNSSEC_KEY_IMPORT_ERROR,	"Key import error" },
	{ DNSSEC_KEY_GENERATE_ERROR,	"Key generation error" },

	{ DNSSEC_INVALID_PUBLIC_KEY,	"Invalid public key" },
	{ DNSSEC_INVALID_PRIVATE_KEY,	"Invalid private key" },
	{ DNSSEC_INVALID_KEY_ALGORITHM,	"Invalid key algorithm" },
	{ DNSSEC_INVALID_KEY_SIZE,	"Invalid key size" },
	{ DNSSEC_INVALID_KEY_ID,	"Invalid key ID" },

	{ DNSSEC_NO_PUBLIC_KEY,		"No public key" },
	{ DNSSEC_NO_PRIVATE_KEY,	"No private key" },
	{ DNSSEC_KEY_ALREADY_PRESENT,	"Key already present" },

	{ DNSSEC_SIGN_INIT_ERROR,	"Signing initialization error" },
	{ DNSSEC_SIGN_ERROR,		"Signing error" },
	{ DNSSEC_INVALID_SIGNATURE,	"Invalid signature" },
	{ DNSSEC_INVALID_NSEC3_ALGORITHM, "Invalid NSEC3 algorithm" },
	{ DNSSEC_NSEC3_HASHING_ERROR,	"NSEC3 hashing error" },

	{ DNSSEC_CONFIG_MALFORMED,	"Malformed config value" },
	{ DNSSEC_CONFIG_INVALID_KEY_ID,	"Invalid key ID in config" },

	{ 0 }
};

const char *FALLBACK_ERROR_MESSAGE = "Unknown error.";

_public_
const char *dnssec_strerror(int error)
{
	for (const error_message_t *m = ERROR_MESSAGES; m->text; m++) {
		if (m->code == error) {
			return m->text;
		}
	}

	return FALLBACK_ERROR_MESSAGE;
}
