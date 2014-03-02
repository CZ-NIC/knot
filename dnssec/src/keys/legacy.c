#include "../binary.h"
#include "../error.h"
#include "../key.h"
#include "legacy.h"

int dnssec_key_from_rsa_params(dnssec_key_t *key,
			       dnssec_key_algorithm_t algorithm,
			       const dnssec_binary_t *modulus,
			       const dnssec_binary_t *public_exponent,
			       const dnssec_binary_t *private_exponent,
			       const dnssec_binary_t *first_prime,
			       const dnssec_binary_t *second_prime,
			       const dnssec_binary_t *coefficient)
{
//	int result;
//	gnutls_x509_privkey_import_rsa_raw(key, m, e, d, p, q, u);

	return DNSSEC_ERROR;
}

int dnssec_key_from_dsa_params(dnssec_key_t *key,
			       dnssec_key_algorithm_t algorithm,
			       const dnssec_binary_t *p,
			       const dnssec_binary_t *q,
			       const dnssec_binary_t *g,
			       const dnssec_binary_t *y,
			       const dnssec_binary_t *x)
{
//	gnutls_x509_privkey_import_dsa_raw()
	return DNSSEC_ERROR;
}

int dnssec_key_from_ecdsa_params(dnssec_key_t *key,
                                 dnssec_key_algorithm_t algorithm,
			         const dnssec_binary_t *x_coordinate,
			         const dnssec_binary_t *y_coordinate,
			         const dnssec_binary_t *private_key)
{
//	gnutls_x509_privkey_import_ecc_raw()
	return DNSSEC_ERROR;
}
