#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>

#include "crypto.h"

void dnssec_crypto_init(void)
{
	gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);
	gnutls_global_init();
}

void dnssec_crypto_cleanup(void)
{
	gnutls_global_deinit();
	gnutls_pkcs11_deinit();
}

void dnssec_crypto_reinit(void)
{
	gnutls_pkcs11_reinit();
}
