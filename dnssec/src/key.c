#include <string.h>
#include <gnutls/abstract.h>

#include "key.h"
#include "error.h"

typedef uint8_t dnssec_key_id_t[20];

struct dnssec_key {
	dnssec_key_id_t id;
	uint16_t keytag;

	struct {
		uint16_t flags;
		uint8_t algorithm;
		dnssec_binary_t public_key;
	} rdata;

	gnutls_pubkey_t public_key;
	gnutls_privkey_t private_key;
};

int dnssec_key_new(dnssec_key_t **key_ptr)
{
	if (!key_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_key_t *key = malloc(sizeof(dnssec_key_t));
	if (!key) {
		return DNSSEC_ENOMEM;
	}

	memset(key, 0, sizeof(dnssec_key_t));
	*key_ptr = key;

	return DNSSEC_EOK;
}

void dnssec_key_free(dnssec_key_t **key_ptr)
{
	if (!key_ptr || !*key_ptr) {
		return;
	}

	dnssec_key_t *key = *key_ptr;

	dnssec_binary_free(&key->rdata.public_key);
	gnutls_privkey_deinit(key->private_key);
	gnutls_pubkey_deinit(key->public_key);

	free(key);
	*key_ptr = NULL;
}

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

int dnssec_key_from_params(dnssec_key_t *key, uint16_t flags, uint8_t protocol,
			   uint8_t algorithm, const dnssec_binary_t *public_key)
{
	return DNSSEC_ERROR;
}

int dnssec_key_from_dnskey(dnssec_key_t *key, const dnssec_binary_t *rdata)
{
	if (!key || !rdata) {
		return DNSSEC_EINVAL;
	}

	return DNSSEC_ERROR;
}

int dnssec_key_get_dnskey(const dnssec_key_t *key, dnssec_binary_t *rdata)
{
	if (!key || !rdata) {
		return DNSSEC_EINVAL;
	}

	return DNSSEC_ERROR;
}

int dnssec_key_get_ds(const dnssec_key_t *key, dnssec_key_digest_t digest,
		      dnssec_binary_t *rdata)
{
	return DNSSEC_ERROR;
}
