#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <assert.h>
#include <time.h>
#include "common/descriptor.h"
#include "common/errcode.h"
#include "util/wire.h"
#include "sign/key.h"
#include "sign/sig0.h"
#include "sign/bnutils.h"

/*----------------------------------------------------------------------------*/

static int rsa_init(knot_dnssec_key_t *key, const knot_key_params_t *params)
{
	if (!key || !params)
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
		return KNOT_EINVAL; //! \todo Better error code?
	}

	key->algorithm_data = (void *)rsa;
	return KNOT_EOK;
}

static int rsa_clean(knot_dnssec_key_t *key)
{
	if (!key)
		return KNOT_EINVAL;

	RSA *rsa = (RSA *)key->algorithm_data;
	if (rsa)
		RSA_free(rsa);

	return KNOT_EOK;
}

static size_t rsa_digest_size(knot_dnssec_key_t *key)
{
	RSA *rsa = (RSA *)key->algorithm_data;
	if (!rsa)
		return 0;

	return RSA_size(rsa);
}

static int rsa_digest_type(knot_dnssec_key_t *key)
{
	switch (key->algorithm) {
	case KNOT_DNSSEC_ALG_RSASHA1: return NID_sha1;
	default:
		return 0;
	}
}

static int rsa_sign(knot_dnssec_key_t *key, const uint8_t *data, size_t length,
		    uint8_t *signature)
{
	if (!key | !data | !signature)
		return KNOT_EINVAL;

	RSA *rsa = (RSA *)key->algorithm_data;
	if (!rsa)
		return KNOT_EINVAL;

	int type = rsa_digest_type(key);
	if (type == 0)
		return KNOT_ENOTSUP;

	unsigned int digest_len = rsa_digest_size(key);
	int result = RSA_sign(type, data, length, signature, &digest_len, rsa);

	return result == 1 ? KNOT_EOK : KNOT_ERROR;
}

/*----------------------------------------------------------------------------*/

struct algorithm_callbacks {
	knot_dnssec_algorithm_t algorithm;
	int (*init)(knot_dnssec_key_t *, const knot_key_params_t *);
	int (*clean)(knot_dnssec_key_t *);
	int (*sign)(knot_dnssec_key_t *, const uint8_t *, size_t, uint8_t *);
	size_t (*digest_size)(knot_dnssec_key_t *);
};

typedef struct algorithm_callbacks algorithm_callbacks_t;

static const algorithm_callbacks_t ALGORITHM_MECHANISMS[] = {
	{ KNOT_DNSSEC_ALG_RSASHA1, rsa_init, rsa_clean, rsa_sign, rsa_digest_size },
	{ 0, NULL, NULL, NULL, 0 }
};

static const algorithm_callbacks_t *get_callbacks(knot_dnssec_algorithm_t alg)
{
	const algorithm_callbacks_t *result = ALGORITHM_MECHANISMS;
	while (result->algorithm != 0 && result->algorithm != alg)
		result += 1;

	if (result->algorithm != 0)
		return result;
	else
		return NULL;
}

/*----------------------------------------------------------------------------*/

int knot_dnssec_key_from_params(const knot_key_params_t *params,
				knot_dnssec_key_t *key)
{
	if (!key || !params)
		return KNOT_EINVAL;

	const algorithm_callbacks_t *callbacks = get_callbacks(params->algorithm);
	if (!callbacks)
		return KNOT_ENOTSUP;

	knot_dname_t *name = knot_dname_new_from_nonfqdn_str(params->name,
							     strlen(params->name),
							     NULL);
	if (!name)
		return KNOT_ENOMEM;

	int result = callbacks->init(key, params);
	if (result != KNOT_EOK) {
		free(name);
		return result;
	}

	key->name = name;
	key->algorithm = params->algorithm;
	key->callbacks = callbacks;

	return KNOT_EOK;
}

int knot_dnssec_key_free(knot_dnssec_key_t *key)
{
	if (!key)
		return KNOT_EINVAL;

	if (key->name)
		knot_dname_release(key->name);

	if (key->callbacks)
		key->callbacks->clean(key);

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

	size += sizeof(knot_dname_t *);		   // pointer to signer
	size += key->callbacks->digest_size(key);  // signature

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
 * (Computed from the size of owner [root], type, class, ttl.)
 */
#define SIG0_RR_HEADER_SIZE 9

static int knot_sig0_write_signature(uint8_t* wire, size_t request_size,
				     size_t sig_rr_size,
				     knot_dnssec_key_t *key)
{
	size_t signature_size = key->callbacks->digest_size(key);
	uint8_t *wire_sig_rdata = wire + request_size + SIG0_RR_HEADER_SIZE;
	size_t wire_sig_rdata_size = sig_rr_size - SIG0_RR_HEADER_SIZE
				     - signature_size;

	size_t data_size = request_size + wire_sig_rdata_size;
	uint8_t *data = (uint8_t *)malloc(data_size);
	if (!data)
		return KNOT_ENOMEM;

	memcpy(data, wire_sig_rdata, wire_sig_rdata_size);
	memcpy(data + wire_sig_rdata_size, wire, request_size);

	uint8_t *wire_signature = wire + request_size + sig_rr_size
				  - signature_size;

	int result = key->callbacks->sign(key, data, data_size, wire_signature);

	free(data);

	return result;
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
