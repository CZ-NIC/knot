#include "binary.h"
#include "error.h"
#include "key.h"
#include "shared.h"

_public_
int dnssec_key_create_ds(const dnssec_key_t *key, dnssec_key_digest_t digest,
			 dnssec_binary_t *rdata)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}
