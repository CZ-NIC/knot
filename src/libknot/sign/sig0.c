#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <assert.h>
#include <time.h>
#include "common/descriptor.h"
#include "common/errcode.h"
#include "util/wire.h"
#include "sign/key.h"
#include "sign/sig0.h"
#include "sign/bnutils.h"

/*----------------------------------------------------------------------------*/

static int create_rsa_pkey_from_params(const knot_key_params_t *params,
				       void **result)
{
	if (!result)
		return KNOT_EINVAL;

	RSA *rsa = RSA_new();
	if (rsa == NULL)
		return KNOT_ERROR;

	rsa->n    = knot_b64_to_bignum(params->modulus);
	rsa->e    = knot_b64_to_bignum(params->public_exponent);
	rsa->d    = knot_b64_to_bignum(params->private_exponent);
	rsa->p    = knot_b64_to_bignum(params->prime_one);
	rsa->q    = knot_b64_to_bignum(params->prime_two);
	rsa->dmp1 = knot_b64_to_bignum(params->exponent_one);
	rsa->dmq1 = knot_b64_to_bignum(params->exponent_two);
	rsa->iqmp = knot_b64_to_bignum(params->coefficient);

	if (RSA_check_key(rsa) != 1) {
		RSA_free(rsa);
		return KNOT_DNSSEC_INVALID_KEY;
	}

	*result = rsa;
	return KNOT_EOK;
}

static int create_pkey_from_params(const knot_key_params_t *params,
				   EVP_PKEY **result_key)
{
	if (!result_key)
		return KNOT_EINVAL;

	EVP_PKEY *private_key = EVP_PKEY_new();
	if (!private_key)
		return KNOT_ENOMEM;

	void *key = NULL;
	int key_type = 0;
	int result;

	switch (params->algorithm) {
	case KNOT_DNSSEC_ALG_RSASHA1:
		key_type = EVP_PKEY_RSA;
		result = create_rsa_pkey_from_params(params, &key);
		break;
	default:
		result = KNOT_ENOTSUP;
		break;
	}

	if (result != KNOT_EOK) {
		EVP_PKEY_free(private_key);
		return result;
	}

	// Assigning the 'key' causes binding it into EVP_PKEY struct,
	// it will be freed automatically when EVP_PKEY_free() is called.
	if (!EVP_PKEY_assign(private_key, key_type, key)) {
		EVP_PKEY_free(private_key);
		return KNOT_ERROR;
	}

	*result_key = private_key;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

struct algorithm_data {
	EVP_MD_CTX *context;
	EVP_PKEY *private_key;
};

typedef struct algorithm_data algorithm_data_t;

/*----------------------------------------------------------------------------*/

static int create_sign_context(const knot_key_params_t *params,
			       EVP_MD_CTX **result_context)
{
	if (!result_context)
		return KNOT_EINVAL;

	const EVP_MD *digest_type;

	switch (params->algorithm) {
	case KNOT_DNSSEC_ALG_RSASHA1:
		digest_type = EVP_sha1();
		break;
	default:
		return KNOT_ENOTSUP;
	}

	assert(digest_type); // used libcrypto function should not fail

	EVP_MD_CTX *context = EVP_MD_CTX_create();
	if (!context)
		return KNOT_ENOMEM;

	if (!EVP_SignInit_ex(context, digest_type, NULL)) {
		EVP_MD_CTX_destroy(context);
		return KNOT_ERROR;
	}

	*result_context = context;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static size_t sign_get_size(algorithm_data_t *algorithm_data)
{
	if (!algorithm_data)
		return 0;

	return (size_t)EVP_PKEY_size(algorithm_data->private_key);
}

static int sign_add_data(algorithm_data_t *algorithm_data,
			 const uint8_t *data, size_t len)
{
	if (!algorithm_data | !data)
		return KNOT_EINVAL;

	if (!EVP_SignUpdate(algorithm_data->context, data, len))
		return KNOT_DNSSEC_SIGNING_FAILED;

	return KNOT_EOK;
}

static int sign_finish(algorithm_data_t *algorithm_data, uint8_t *signature)
{
	if (!algorithm_data || !signature)
		return KNOT_EINVAL;

	unsigned int signature_len;
	int result;

	result = EVP_SignFinal(algorithm_data->context, signature,
			       &signature_len, algorithm_data->private_key);

	if (!result)
		return KNOT_DNSSEC_SIGNING_FAILED;

	//! \todo EVP_PKEY_size() can be actually larger than signature, when?
	assert(sign_get_size == sign_get_size(algorithm_data));

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int clean_algorithm_data(algorithm_data_t *data)
{
	if (!data)
		return KNOT_EINVAL;

	if (data->private_key) {
		EVP_PKEY_free(data->private_key);
		data->private_key = NULL;
	}

	if (data->context) {
		EVP_MD_CTX_destroy(data->context);
		data->context = NULL;
	}

	return KNOT_EOK;
}

static int init_algorithm_data(const knot_key_params_t *params,
			       algorithm_data_t *data)
{
	if (!params || !data)
		return KNOT_EINVAL;

	int result;

	result = create_sign_context(params, &data->context);
	if (result != KNOT_EOK) {
		clean_algorithm_data(data);
		return result;
	}

	result = create_pkey_from_params(params, &data->private_key);
	if (result != KNOT_EOK) {
		clean_algorithm_data(data);
		return result;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_dnssec_key_from_params(const knot_key_params_t *params,
				knot_dnssec_key_t *key)
{
	if (!key || !params)
		return KNOT_EINVAL;

	knot_dname_t *name = knot_dname_new_from_nonfqdn_str(params->name,
							     strlen(params->name),
							     NULL);
	if (!name)
		return KNOT_ENOMEM;


	algorithm_data_t *algorithm_data = calloc(1, sizeof(algorithm_data_t));
	if (!algorithm_data)
		return KNOT_ENOMEM;

	int result = init_algorithm_data(params, algorithm_data);
	if (result != KNOT_EOK) {
		free(algorithm_data);
		return result;
	}

	key->name = name;
	key->algorithm = params->algorithm;
	key->algorithm_data = algorithm_data;

	return KNOT_EOK;
}

int knot_dnssec_key_free(knot_dnssec_key_t *key)
{
	if (!key)
		return KNOT_EINVAL;

	if (key->name)
		knot_dname_release(key->name);

	if (key->algorithm_data) {
		algorithm_data_t *algorithm_data = key->algorithm_data;
		clean_algorithm_data(algorithm_data);
		free(algorithm_data);
	}

	memset(key, '\0', sizeof(knot_dnssec_key_t));

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static knot_rrset_t *knot_sig0_create_rrset(void)
{
	knot_dname_t *root = knot_dname_new_from_str(".", 1, NULL);
	uint32_t ttl = 0;
	knot_rrset_t *sig_record = knot_rrset_new(root, KNOT_RRTYPE_SIG,
						  KNOT_CLASS_ANY, ttl);
	knot_dname_release(root);

	return sig_record;
}

static size_t knot_sig0_rdata_size(knot_dnssec_key_t *key)
{
	size_t size;

	// static part

	size = sizeof(uint16_t)		// type covered
	     + sizeof(uint8_t)		// algorithm
	     + sizeof(uint8_t)		// labels
	     + sizeof(uint32_t)		// original TTL
	     + sizeof(uint32_t)		// signature expiration
	     + sizeof(uint32_t)		// signature inception
	     + sizeof(uint16_t);	// key tag (footprint)

	// variable part

	size += sizeof(knot_dname_t *);			// pointer to signer
	size += sign_get_size(key->algorithm_data);	// signature

	return size;
}

static uint8_t *knot_sig0_create_rdata(knot_rrset_t *rrset,
				       knot_dnssec_key_t *key)
{
	assert(rrset);
	assert(key);

	size_t rdata_size = knot_sig0_rdata_size(key);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
	if (!rdata)
		return NULL;

	memset(rdata, '\0', rdata_size);

	return rdata;
}

static int knot_sig0_write_rdata(knot_dnssec_key_t *key, uint8_t *rdata)
{
	assert(key);
	assert(rdata);

	uint32_t incepted = (uint32_t)time(NULL);
	uint32_t expires = incepted + 300; // RFC recommends 5 minutes.
	uint16_t keytag = 59040; //! TODO: HARDCODED

	uint8_t *w = rdata;

	w += sizeof(uint16_t);			// type covered
	*w = key->algorithm;			// algorithm
	w += sizeof(uint8_t);
	w += sizeof(uint8_t);			// labels
	w += sizeof(uint32_t);			// original TTL
	knot_wire_write_u32(w, expires);	// signature expiration
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, incepted);	// signature inception
	w += sizeof(uint32_t);
	knot_wire_write_u16(w, keytag);		// key footprint
	w += sizeof(uint16_t);

	assert(w == rdata + 18);
	memcpy(w, &key->name, sizeof(knot_dname_t *)); // pointer to signer name

	return KNOT_EOK;
}

/*!
 * \todo Skip from wire RR to RDATA more clearly.
 *
 * (Computed from the size of owner (== root), type, class, ttl.)
 */
#define SIG0_RR_HEADER_SIZE 11

static int knot_sig0_write_signature(uint8_t* wire, size_t request_size,
				     size_t sig_rr_size,
				     knot_dnssec_key_t *key)
{
	size_t signature_size = sign_get_size(key->algorithm_data);

	uint8_t *sig_rdata = wire + request_size + SIG0_RR_HEADER_SIZE;
	size_t sig_rdata_size = sig_rr_size - SIG0_RR_HEADER_SIZE - signature_size;

	sign_add_data(key->algorithm_data, sig_rdata, sig_rdata_size);
	sign_add_data(key->algorithm_data, wire, request_size);

	uint8_t *signature = wire + request_size + sig_rr_size - signature_size;

	return sign_finish(key->algorithm_data, signature);
}

int knot_sig0_sign(uint8_t *wire, size_t *wire_size, size_t wire_max_size,
		   knot_dnssec_key_t *key)
{
	knot_rrset_t *sig_rrset = knot_sig0_create_rrset();
	if (!sig_rrset) {
		return KNOT_ENOMEM;
	}

	uint8_t *sig_rdata = knot_sig0_create_rdata(sig_rrset, key);
	if (!sig_rdata) {
		knot_rrset_deep_free(&sig_rrset, 1, 1);
		return KNOT_ENOMEM;
	}

	knot_sig0_write_rdata(key, sig_rdata);

	// convert to wire

	uint8_t *wire_end = wire + *wire_size;
	size_t wire_avail_size = wire_max_size - *wire_size;
	size_t wire_sig_size = 0;
	uint16_t written_rr_count = 0;

	knot_rrset_to_wire(sig_rrset, wire_end, &wire_sig_size,
			   wire_avail_size, &written_rr_count, NULL);
	assert(written_rr_count == 1);
	knot_rrset_deep_free(&sig_rrset, 1, 1);

	// create signature

	int result = knot_sig0_write_signature(wire, *wire_size, wire_sig_size, key);
	if (result != KNOT_EOK) {
		return result;
	}

	uint16_t wire_arcount = knot_wire_get_arcount(wire);
	knot_wire_set_arcount(wire, wire_arcount + written_rr_count);

	*wire_size += wire_sig_size;

	return KNOT_EOK;
}
