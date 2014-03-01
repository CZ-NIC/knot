#include <assert.h>
#include <gnutls/abstract.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include "key.h"
#include "error.h"
#include "keytag.h"

typedef uint8_t dnssec_key_id_t[20];

struct dnssec_key {
	dnssec_key_id_t id;
	uint16_t keytag;

	dnssec_binary_t rdata;

	gnutls_pubkey_t public_key;
	gnutls_privkey_t private_key;
};

static bool key_is_valid(const dnssec_key_t *key)
{
	/*
	 * 2 bytes: flags
	 * 1 byte:  protocol
	 * 1 byte:  algorithm
	 * rest:    public key
	 */

	return key && key->rdata.size > 4;
}

static void update_keytag(dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return;
	}

	key->keytag = keytag(&key->rdata);
}

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

void dnssec_key_clear(dnssec_key_t *key)
{
	if (!key) {
		return;
	}

	dnssec_binary_free(&key->rdata);
	gnutls_privkey_deinit(key->private_key);
	gnutls_pubkey_deinit(key->public_key);

	memset(key, 0, sizeof(dnssec_key_t));
}

void dnssec_key_free(dnssec_key_t **key_ptr)
{
	if (!key_ptr || !*key_ptr) {
		return;
	}

	dnssec_key_clear(*key_ptr);

	free(*key_ptr);
	*key_ptr = NULL;
}

uint16_t dnssec_key_get_flags(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	return ntohs(*((uint16_t *)key->rdata.data));
}

uint8_t dnssec_key_get_protocol(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	return *(key->rdata.data + 2);

}

uint8_t dnssec_key_get_algorithm(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	return *(key->rdata.data + 3);
}

uint16_t dnssec_key_get_keytag(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	return key->keytag;
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
	if (!key || !public_key) {
		return DNSSEC_EINVAL;
	}

	size_t rdata_size = 4 + public_key->size;
	uint8_t *rdata = malloc(rdata_size);
	if (!rdata) {
		return DNSSEC_ENOMEM;
	}

	key->rdata.data = rdata;
	key->rdata.size = rdata_size;

	uint8_t *write = rdata;
	*((uint16_t *)write) = htons(flags);
	write += 2;
	*write = protocol;
	write += 1;
	*write = algorithm;
	write += 1;
	memcpy(write, public_key->data, public_key->size);
	write += public_key->size;
	assert(write == key->rdata.data + key->rdata.size);

	update_keytag(key);

	return DNSSEC_EOK;
}

int dnssec_key_from_dnskey(dnssec_key_t *key, const dnssec_binary_t *rdata)
{
	if (!key || !rdata) {
		return DNSSEC_EINVAL;
	}

	int result = dnssec_binary_dup(rdata, &key->rdata);
	if (result != DNSSEC_EOK) {
		return result;
	}

	update_keytag(key);

	return DNSSEC_EOK;
}

int dnssec_key_get_dnskey(const dnssec_key_t *key, dnssec_binary_t *rdata)
{
	if (!key_is_valid(key)) {
		return DNSSEC_EINVAL;
	}

	dnssec_binary_t copy = { 0 };
	int result = dnssec_binary_dup(&key->rdata, &copy);
	if (result != DNSSEC_EOK) {
		return result;
	}

	*rdata = copy;
	return DNSSEC_EOK;
}

int dnssec_key_get_ds(const dnssec_key_t *key, dnssec_key_digest_t digest,
		      dnssec_binary_t *rdata)
{
	return DNSSEC_ERROR;
}
