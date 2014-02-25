#include "error.h"
#include "keystore.h"

dnssec_keystore_t *dnssec_keystore_open(const char *path);

int dnssec_keystore_close(dnssec_keystore_t **keystore)
{
	if (!keystore) {
		return DNSSEC_EINVAL;
	}

	return DNSSEC_EOK;
}
