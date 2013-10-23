/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <assert.h>
#include <openssl/dsa.h>
#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "common/descriptor.h"
#include "common/errcode.h"
#include "libknot/common.h"
#include "libknot/dnssec/algorithm.h"
#include "libknot/dnssec/config.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/sign.h"

#ifdef KNOT_ENABLE_ECDSA
#include <openssl/ecdsa.h>
#endif

#define DNSKEY_RDATA_PUBKEY_OFFSET 4

struct algorithm_functions;
typedef struct algorithm_functions algorithm_functions_t;

//! \brief Algorithm private key data and algorithm implementation.
struct knot_dnssec_key_data {
	const algorithm_functions_t *functions; //!< Implementation specific.
	EVP_PKEY *private_key;                  //!< Private key.
};

//! \brief DNSSEC signature contextual data.
struct knot_dnssec_sign_context {
	const knot_dnssec_key_t *key; //!< Associated key.
	EVP_MD_CTX *digest_context;   //!< Digest computation context.
};

/*!
 * \brief Algorithm implementation specific functions.
 */
struct algorithm_functions {
	//! \brief Callback: create private key from key parameters.
	int (*create_pkey)(const knot_key_params_t *, EVP_PKEY *);
	//! \brief Callback: get signature size in bytes.
	size_t (*sign_size)(const knot_dnssec_key_t *);
	//! \brief Callback: cover supplied data with the signature.
	int (*sign_add)(const knot_dnssec_sign_context_t *, const uint8_t *, size_t);
	//! \brief Callback: finish the signing and write out the signature.
	int (*sign_write)(const knot_dnssec_sign_context_t *, uint8_t *);
	//! \brief Callback: finish the signing and validate the signature.
	int (*sign_verify)(const knot_dnssec_sign_context_t *, const uint8_t *, size_t);
};

/**
 * \brief Convert binary data to OpenSSL BIGNUM format.
 */
static BIGNUM *binary_to_bn(const knot_binary_t *bin)
{
	return BN_bin2bn((unsigned char *)bin->data, (int)bin->size, NULL);
}

/*- Algorithm independent ----------------------------------------------------*/

/*!
 * \brief Get size of the resulting signature.
 *
 * \param key  DNSSEC key.
 *
 * \return Signature size in bytes.
 */
static size_t any_sign_size(const knot_dnssec_key_t *key)
{
	assert(key);

	return (size_t)EVP_PKEY_size(key->data->private_key);
}

/*!
 * \brief Add data to be covered by the signature.
 *
 * \param context    DNSSEC signature context.
 * \param data       Data to be signed.
 * \param data_size  Size of the data to be signed.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int any_sign_add(const knot_dnssec_sign_context_t *context,
                        const uint8_t *data, size_t data_size)
{
	assert(context);
	assert(data);

	if (!EVP_DigestUpdate(context->digest_context, data, data_size)) {
		return KNOT_DNSSEC_ESIGN;
	}

	return KNOT_EOK;
}

/*!
 * \brief Finish the signing and get the RAW signature.
 *
 * Caller should free the memory returned via signature parameter.
 *
 * \param context         DNSSEC signature context.
 * \param signature       Pointer to signature (output).
 * \param signature_size  Signature size (output).
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int any_sign_write(const knot_dnssec_sign_context_t *context,
                           uint8_t **signature, size_t *signature_size)
{
	assert(context);
	assert(signature);
	assert(signature_size);

	size_t max_size = (size_t)EVP_PKEY_size(context->key->data->private_key);
	uint8_t *output = calloc(1, max_size);
	if (!output) {
		return KNOT_ENOMEM;
	}

	unsigned int actual_size;
	int result = EVP_SignFinal(context->digest_context, output,
	                           &actual_size, context->key->data->private_key);
	if (!result) {
		free(output);
		return KNOT_DNSSEC_ESIGN;
	}

	assert(actual_size <= max_size);

	*signature = output;
	*signature_size = actual_size;

	return KNOT_EOK;
}

/*!
 * \brief Verify the DNSSEC signature for supplied data.
 *
 * \param context         DNSSEC signature context.
 * \param signature       Pointer to signature.
 * \param signature_size  Size of the signature.
 *
 * \return Error code.
 * \retval KNOT_EOK                        The signature is valid.
 * \retval KNOT_DNSSEC_EINVALID_SIGNATURE  The signature is invalid.
 * \retval KNOT_DNSSEC_ESIGN               Some error occured.
 */
static int any_sign_verify(const knot_dnssec_sign_context_t *context,
                            const uint8_t *signature, size_t signature_size)
{
	assert(context);
	assert(signature);

	int result = EVP_VerifyFinal(context->digest_context,
	                             signature, signature_size,
	                             context->key->data->private_key);

	switch (result) {
	case 1:
		return KNOT_EOK;
	case 0:
		return KNOT_DNSSEC_EINVALID_SIGNATURE;
	default:
		return KNOT_DNSSEC_ESIGN;
	};
}

/*- RSA specific -------------------------------------------------------------*/

/*!
 * \brief Create RSA private key from key parameters.
 *
 * \param params  Key parameters.
 * \param key     Output private key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int rsa_create_pkey(const knot_key_params_t *params, EVP_PKEY *key)
{
	assert(params);
	assert(key);

	RSA *rsa = RSA_new();
	if (rsa == NULL) {
		return KNOT_ENOMEM;
	}

	rsa->n    = binary_to_bn(&params->modulus);
	rsa->e    = binary_to_bn(&params->public_exponent);
	rsa->d    = binary_to_bn(&params->private_exponent);
	rsa->p    = binary_to_bn(&params->prime_one);
	rsa->q    = binary_to_bn(&params->prime_two);
	rsa->dmp1 = binary_to_bn(&params->exponent_one);
	rsa->dmq1 = binary_to_bn(&params->exponent_two);
	rsa->iqmp = binary_to_bn(&params->coefficient);

	if (RSA_check_key(rsa) != 1) {
		RSA_free(rsa);
		return KNOT_DNSSEC_EINVALID_KEY;
	}

	if (!EVP_PKEY_assign_RSA(key, rsa)) {
		RSA_free(rsa);
		return KNOT_DNSSEC_EASSIGN_KEY;
	}

	return KNOT_EOK;
}

/*!
 * \brief Finish the signing and write out the RSA signature.
 *
 * \param context    DNSSEC signing context.
 * \param signature  Pointer to memory where the signature will be written.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int rsa_sign_write(const knot_dnssec_sign_context_t *context,
                          uint8_t *signature)
{
	assert(context);
	assert(signature);

	int result;
	uint8_t *raw_signature;
	size_t raw_signature_size;
	const knot_dnssec_key_t *key = context->key;

	result = any_sign_write(context, &raw_signature, &raw_signature_size);
	if (result != KNOT_EOK) {
		return result;
	}

	if (raw_signature_size != key->data->functions->sign_size(key)) {
		free(raw_signature);
		return KNOT_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE;
	}

	memcpy(signature, raw_signature, raw_signature_size);
	free(raw_signature);

	return KNOT_EOK;
}

/*- DSA specific -------------------------------------------------------------*/

/*!
 * \brief Create DSA private key from key parameters.
 * \see rsa_create_pkey
 */
static int dsa_create_pkey(const knot_key_params_t *params, EVP_PKEY *key)
{
	assert(params);
	assert(key);

	DSA *dsa = DSA_new();
	if (dsa == NULL) {
		return KNOT_ENOMEM;
	}

	dsa->p        = binary_to_bn(&params->prime);
	dsa->q        = binary_to_bn(&params->subprime);
	dsa->g        = binary_to_bn(&params->base);
	dsa->priv_key = binary_to_bn(&params->private_value);
	dsa->pub_key  = binary_to_bn(&params->public_value);

	if (!EVP_PKEY_assign_DSA(key, dsa)) {
		DSA_free(dsa);
		return KNOT_DNSSEC_EASSIGN_KEY;
	}

	return KNOT_EOK;
}

/*!
 * \brief Get size of the resulting signature for DSA algorithm.
 * \see any_sign_size
 */
static size_t dsa_sign_size(const knot_dnssec_key_t *key)
{
	UNUSED(key);
	// RFC 2536 (section 3 - DSA SIG Resource Record)
	return 41;
}

/*!
 * \brief Finish the signing and write out the DSA signature.
 * \see rsa_sign_write
 */
static int dsa_sign_write(const knot_dnssec_sign_context_t *context,
                          uint8_t *signature)
{
	assert(context);
	assert(signature);

	int result;
	uint8_t *raw_signature;
	size_t raw_signature_size;

	result = any_sign_write(context, &raw_signature, &raw_signature_size);
	if (result != KNOT_EOK) {
		return result;
	}

	// decode signature, X.509 Dss-Sig-Value (RFC2459)

	DSA_SIG *decoded = DSA_SIG_new();
	if (!decoded) {
		free(raw_signature);
		return KNOT_ENOMEM;
	}

	const uint8_t *decode_scan = raw_signature;
	if (!d2i_DSA_SIG(&decoded, &decode_scan, (long)raw_signature_size)) {
		DSA_SIG_free(decoded);
		free(raw_signature);
		return KNOT_DNSSEC_EDECODE_RAW_SIGNATURE;
	}

	free(raw_signature);

	// convert to format defined by RFC 2536 (DSA keys and SIGs in DNS)

	// T (1 byte), R (20 bytes), S (20 bytes)
	uint8_t *signature_t = signature;
	uint8_t *signature_r = signature + 21 - BN_num_bytes(decoded->r);
	uint8_t *signature_s = signature + 41 - BN_num_bytes(decoded->s);

	memset(signature, '\0', dsa_sign_size(context->key));
	*signature_t = 0x00; //! \todo Take from public key. Only recommended.
	BN_bn2bin(decoded->r, signature_r);
	BN_bn2bin(decoded->s, signature_s);

	DSA_SIG_free(decoded);

	return KNOT_EOK;
}

/*!
 * \brief Verify the DNSSEC signature for supplied data and DSA algorithm.
 * \see any_sign_verify
 */
static int dsa_sign_verify(const knot_dnssec_sign_context_t *context,
                           const uint8_t *signature, size_t signature_size)
{
	assert(context);
	assert(signature);

	if (signature_size != dsa_sign_size(context->key)) {
		return KNOT_EINVAL;
	}

	// see dsa_sign_write() for conversion details

	// T (1 byte), R (20 bytes), S (20 bytes)
	const uint8_t *signature_r = signature + 1;
	const uint8_t *signature_s = signature + 21;

	DSA_SIG *decoded = DSA_SIG_new();
	if (!decoded) {
		return KNOT_ENOMEM;
	}

	decoded->r = BN_bin2bn(signature_r, 20, decoded->r);
	decoded->s = BN_bin2bn(signature_s, 20, decoded->s);

	size_t max_size = EVP_PKEY_size(context->key->data->private_key);
	uint8_t *raw_signature = malloc(max_size);
	if (!raw_signature) {
		DSA_SIG_free(decoded);
		return KNOT_ENOMEM;
	}

	uint8_t *raw_write = raw_signature;
	int raw_size = i2d_DSA_SIG(decoded, &raw_write);
	if (raw_size < 0) {
		free(raw_signature);
		DSA_SIG_free(decoded);
		return KNOT_DNSSEC_EDECODE_RAW_SIGNATURE;
	}
	assert(raw_write == raw_signature + raw_size);

	int result = any_sign_verify(context, raw_signature, raw_size);

	DSA_SIG_free(decoded);
	free(raw_signature);

	return result;
}

/*- EC specific --------------------------------------------------------------*/

#ifdef KNOT_ENABLE_ECDSA

/*!
 * \brief Decode ECDSA public key from RDATA and set it into EC key.
 * \note DNSKEY format for ECDSA is described in RFC 6605 section 4.
 */
static int ecdsa_set_public_key(const knot_binary_t *rdata, EC_KEY *ec_key)
{
	assert(rdata);
	assert(ec_key);

	if (rdata->size <= DNSKEY_RDATA_PUBKEY_OFFSET) {
		return KNOT_EINVAL;
	}

	uint8_t *pubkey_data = rdata->data + DNSKEY_RDATA_PUBKEY_OFFSET;
	size_t pubkey_size = rdata->size - DNSKEY_RDATA_PUBKEY_OFFSET;

	if (pubkey_size % 2 != 0) {
		return KNOT_EINVAL;
	}

	size_t param_size = pubkey_size / 2;
	uint8_t *x_ptr = pubkey_data;
	uint8_t *y_ptr = pubkey_data + param_size;

	BIGNUM *x = BN_bin2bn(x_ptr, param_size, NULL);
	BIGNUM *y = BN_bin2bn(y_ptr, param_size, NULL);

	int result = EC_KEY_set_public_key_affine_coordinates(ec_key, x, y);

	BN_free(x);
	BN_free(y);

	return result == 1 ? KNOT_EOK : KNOT_DNSSEC_EINVALID_KEY;
}

static int ecdsa_set_private_key(const knot_binary_t *data, EC_KEY *ec_key)
{
	assert(data);
	assert(ec_key);

	BIGNUM *private = binary_to_bn(data);
	int result = EC_KEY_set_private_key(ec_key, private);
	BN_free(private);

	return result == 1 ? KNOT_EOK : KNOT_DNSSEC_EINVALID_KEY;
}

/*!
 * \brief Create ECDSA private key from key parameters.
 * \see rsa_create_pkey
 */
static int ecdsa_create_pkey(const knot_key_params_t *params, EVP_PKEY *key)
{
	assert(params);
	assert(key);

	int curve;
	if (params->algorithm == KNOT_DNSSEC_ALG_ECDSAP256SHA256) {
		curve = NID_X9_62_prime256v1; // == secp256r1
	} else if (params->algorithm == KNOT_DNSSEC_ALG_ECDSAP384SHA384) {
		curve = NID_secp384r1;
	} else {
		return KNOT_DNSSEC_ENOTSUP;
	}

	EC_KEY *ec_key = EC_KEY_new_by_curve_name(curve);
	if (ec_key == NULL) {
		return KNOT_ENOMEM;
	}

	int result = ecdsa_set_public_key(&params->rdata, ec_key);
	if (result != KNOT_EOK) {
		EC_KEY_free(ec_key);
		return result;
	}

	result = ecdsa_set_private_key(&params->private_key, ec_key);
	if (result != KNOT_EOK) {
		EC_KEY_free(ec_key);
		return result;
	}

	if (EC_KEY_check_key(ec_key) != 1) {
		EC_KEY_free(ec_key);
		return KNOT_DNSSEC_EINVALID_KEY;
	}

	if (!EVP_PKEY_assign_EC_KEY(key, ec_key)) {
		EC_KEY_free(ec_key);
		return KNOT_DNSSEC_EASSIGN_KEY;
	}

	return KNOT_EOK;
}

/*!
 * \brief Get size of the resulting signature for ECDSA algorithm.
 * \see any_sign_size
 */
static size_t ecdsa_sign_size(const knot_dnssec_key_t *key)
{
	assert(key);

	// RFC 6605 (section 4 - DNSKEY and RRSIG Resource Records for ECDSA)

	switch (key->algorithm) {
	case KNOT_DNSSEC_ALG_ECDSAP256SHA256:
		return 2 * 32;
	case KNOT_DNSSEC_ALG_ECDSAP384SHA384:
		return 2 * 48;
	default:
		assert(0);
		return 0;
	}
}

/*!
 * \brief Finish the signing and write out the ECDSA signature.
 * \see rsa_sign_write
 */
static int ecdsa_sign_write(const knot_dnssec_sign_context_t *context,
                            uint8_t *signature)
{
	assert(context);
	assert(signature);

	int result;
	uint8_t *raw_signature;
	size_t raw_signature_size;

	result = any_sign_write(context, &raw_signature, &raw_signature_size);
	if (result != KNOT_EOK) {
		return result;
	}

	// decode signature

	ECDSA_SIG *decoded = ECDSA_SIG_new();
	if (!decoded) {
		free(raw_signature);
		return KNOT_ENOMEM;
	}

	const uint8_t *decode_scan = raw_signature;
	if (!d2i_ECDSA_SIG(&decoded, &decode_scan, (long)raw_signature_size)) {
		ECDSA_SIG_free(decoded);
		free(raw_signature);
		return KNOT_DNSSEC_EDECODE_RAW_SIGNATURE;
	}

	free(raw_signature);

	// convert to format defined by RFC 6605 (EC DSA for DNSSEC)
	// R and S parameters are encoded in halves of the output signature

	uint8_t *signature_r;
	uint8_t *signature_s;
	size_t signature_size = ecdsa_sign_size(context->key);
	size_t param_size = signature_size / 2;

	memset(signature, '\0', signature_size);
	signature_r = signature + param_size - BN_num_bytes(decoded->r);
	signature_s = signature + 2 * param_size - BN_num_bytes(decoded->s);

	BN_bn2bin(decoded->r, signature_r);
	BN_bn2bin(decoded->s, signature_s);

	ECDSA_SIG_free(decoded);

	return KNOT_EOK;
}

/*!
 * \brief Verify the DNSSEC signature for supplied data and ECDSA algorithm.
 * \see any_sign_verify
 */
static int ecdsa_sign_verify(const knot_dnssec_sign_context_t *context,
                             const uint8_t *signature, size_t signature_size)
{
	assert(context);
	assert(signature);

	if (signature_size != ecdsa_sign_size(context->key)) {
		return KNOT_EINVAL;
	}

	// see ecdsa_sign_write() for conversion details

	size_t parameter_size = signature_size / 2;
	const uint8_t *signature_r = signature;
	const uint8_t *signature_s = signature + parameter_size;

	ECDSA_SIG *decoded = ECDSA_SIG_new();
	if (!decoded) {
		return KNOT_ENOMEM;
	}

	decoded->r = BN_bin2bn(signature_r, parameter_size, decoded->r);
	decoded->s = BN_bin2bn(signature_s, parameter_size, decoded->s);

	size_t max_size = EVP_PKEY_size(context->key->data->private_key);
	uint8_t *raw_signature = malloc(max_size);
	if (!raw_signature) {
		ECDSA_SIG_free(decoded);
		return KNOT_ENOMEM;
	}

	uint8_t *raw_write = raw_signature;
	int raw_size = i2d_ECDSA_SIG(decoded, &raw_write);
	if (raw_size < 0) {
		free(raw_signature);
		ECDSA_SIG_free(decoded);
		return KNOT_DNSSEC_EDECODE_RAW_SIGNATURE;
	}
	assert(raw_write == raw_signature + raw_size);

	int result = any_sign_verify(context, raw_signature, raw_size);

	ECDSA_SIG_free(decoded);

	free(raw_signature);

	return result;
}

#endif

/*- Algorithm specifications -------------------------------------------------*/

static const algorithm_functions_t rsa_functions = {
	rsa_create_pkey,
	any_sign_size,
	any_sign_add,
	rsa_sign_write,
	any_sign_verify
};

static const algorithm_functions_t dsa_functions = {
	dsa_create_pkey,
	dsa_sign_size,
	any_sign_add,
	dsa_sign_write,
	dsa_sign_verify
};

#ifdef KNOT_ENABLE_ECDSA
static const algorithm_functions_t ecdsa_functions = {
	ecdsa_create_pkey,
	ecdsa_sign_size,
	any_sign_add,
	ecdsa_sign_write,
	ecdsa_sign_verify
};
#endif

/*!
 * \brief Get implementation specific callbacks for a given algorithm.
 *
 * \param algorithm  Algorithm number.
 *
 * \return Pointer to structure with functions, NULL if not implemented.
 */
static const algorithm_functions_t *get_implementation(int algorithm)
{
	switch (algorithm) {
	case KNOT_DNSSEC_ALG_RSAMD5:
	case KNOT_DNSSEC_ALG_RSASHA1:
	case KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1:
	case KNOT_DNSSEC_ALG_RSASHA256:
	case KNOT_DNSSEC_ALG_RSASHA512:
		return &rsa_functions;
	case KNOT_DNSSEC_ALG_DSA:
	case KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1:
		return &dsa_functions;
	case KNOT_DNSSEC_ALG_ECDSAP256SHA256:
	case KNOT_DNSSEC_ALG_ECDSAP384SHA384:
#ifdef KNOT_ENABLE_ECDSA
		return &ecdsa_functions;
#endif
	default:
		return NULL;
	}
}

/*!
 * \brief Get message digest type for a given algorithm.
 *
 * \param algorithm  Algorithm number.
 *
 * \return Pointer to digest type specification, NULL if not implemented.
 */
static const EVP_MD *get_digest_type(knot_dnssec_algorithm_t algorithm)
{
	// EVP_<digest>() functions should not fail (return NULL)

	switch (algorithm) {
	case KNOT_DNSSEC_ALG_RSASHA1:
	case KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1:
	case KNOT_DNSSEC_ALG_DSA:
	case KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1:
		return EVP_sha1();
	case KNOT_DNSSEC_ALG_RSAMD5:
		return EVP_md5();
	case KNOT_DNSSEC_ALG_RSASHA256:
	case KNOT_DNSSEC_ALG_ECDSAP256SHA256:
		return EVP_sha256();
	case KNOT_DNSSEC_ALG_ECDSAP384SHA384:
		return EVP_sha384();
	case KNOT_DNSSEC_ALG_RSASHA512:
		return EVP_sha512();
	default:
		return NULL;
	}
}

/*- Internal init/clean functions --------------------------------------------*/

/*!
 * \brief Create private key.
 *
 * \param params      Key parameters.
 * \param functions   Algorithm specific callbacks.
 * \param result_key  Output private key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_pkey(const knot_key_params_t *params,
                       const algorithm_functions_t *functions,
                       EVP_PKEY **result_key)
{
	assert(params);
	assert(functions);
        assert(result_key);

	EVP_PKEY *private_key = EVP_PKEY_new();
	if (!private_key) {
		return KNOT_ENOMEM;
	}

	int result = functions->create_pkey(params, private_key);
	if (result != KNOT_EOK) {
		EVP_PKEY_free(private_key);
		return result;
	}

	*result_key = private_key;
	return KNOT_EOK;
}

/*!
 * \brief Create message digest context.
 *
 * \param key             DNSSEC key.
 * \param result_context  Output message digest context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_digest_context(const knot_dnssec_key_t *key,
                                 EVP_MD_CTX **result_context)
{
	assert(key);
	assert(result_context);

	const EVP_MD *digest_type = get_digest_type(key->algorithm);
	if (digest_type == NULL) {
		return KNOT_DNSSEC_ENOTSUP;
	}

	EVP_MD_CTX *context = EVP_MD_CTX_create();
	if (!context) {
		return KNOT_ENOMEM;
	}

	if (!EVP_DigestInit_ex(context, digest_type, NULL)) {
		EVP_MD_CTX_destroy(context);
		return KNOT_DNSSEC_ECREATE_DIGEST_CONTEXT;
	}

	*result_context = context;
	return KNOT_EOK;
}

/*!
 * \brief Destroy message digest context.
 *
 * \param context  Context to be freed.
 *
 * \return Always KNOT_EOK.
 */
static int destroy_digest_context(EVP_MD_CTX **context)
{
	assert(context);

	if (*context) {
		EVP_MD_CTX_destroy(*context);
		*context = NULL;
	}

	return KNOT_EOK;
}

/*!
 * \brief Free algorithm data.
 *
 * \param data  Algorithm context.
 *
 * \return Error code, always KNOT_EOK.
 */
static int clean_algorithm_data(knot_dnssec_key_data_t *data)
{
	assert(data);

	if (data->private_key) {
		EVP_PKEY_free(data->private_key);
		data->private_key = NULL;
	}

	return KNOT_EOK;
}

/*!
 * \brief Initialize algorithm data.
 *
 * \param params  Key parameters.
 * \param data    Algorithm context to be initialized.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int init_algorithm_data(const knot_key_params_t *params,
                               knot_dnssec_key_data_t *data)
{
	assert(params);
	assert(data);

	data->functions = get_implementation(params->algorithm);
	if (!data->functions) {
		return KNOT_DNSSEC_ENOTSUP;
	}

	int result = create_pkey(params, data->functions, &data->private_key);
	if (result != KNOT_EOK) {
		clean_algorithm_data(data);
		return result;
	}

	return KNOT_EOK;
}

/*- Public init/clean functions ----------------------------------------------*/

/*!
 * \brief Fill DNSSEC key structure according to key parameters.
 */
int knot_dnssec_key_from_params(const knot_key_params_t *params,
                                knot_dnssec_key_t *key)
{
	if (!key || !params) {
		return KNOT_EINVAL;
	}

	knot_dname_t *name = knot_dname_copy(params->name);
	if (!name) {
		return KNOT_ENOMEM;
	}

	knot_dnssec_key_data_t *data;
	data = calloc(1, sizeof(knot_dnssec_key_data_t));
	if (!data) {
		knot_dname_free(&name);
		return KNOT_ENOMEM;
	}

	knot_binary_t rdata_copy = { 0 };
	int result = knot_binary_dup(&params->rdata, &rdata_copy);
	if (result != KNOT_EOK) {
		knot_dname_free(&name);
		free(data);
		return result;
	}

	result = init_algorithm_data(params, data);
	if (result != KNOT_EOK) {
		knot_dname_free(&name);
		free(data);
		knot_binary_free(&rdata_copy);
		return result;
	}

	key->name = name;
	key->keytag = params->keytag;
	key->algorithm = params->algorithm;
	key->data = data;
	key->dnskey_rdata = rdata_copy;

	return KNOT_EOK;
}

/*!
 * \brief Free DNSSEC key structure content.
 */
int knot_dnssec_key_free(knot_dnssec_key_t *key)
{
	if (!key) {
		return KNOT_EINVAL;
	}

	knot_dname_free(&key->name);

	if (key->data) {
		clean_algorithm_data(key->data);
		free(key->data);
	}

	knot_binary_free(&key->dnskey_rdata);

	memset(key, '\0', sizeof(knot_dnssec_key_t));

	return KNOT_EOK;
}

/*- Public low level signing interface ---------------------------------------*/

/*!
 * \brief Initialize DNSSEC signing context.
 */
knot_dnssec_sign_context_t *knot_dnssec_sign_init(const knot_dnssec_key_t *key)
{
	if (!key) {
		return NULL;
	}

	knot_dnssec_sign_context_t *context = malloc(sizeof(*context));
	if (!context) {
		return NULL;
	}

	context->key = key;

	if (create_digest_context(key, &context->digest_context) != KNOT_EOK) {
		free(context);
		return NULL;
	}

	return context;
}

/*!
 * \brief Free DNSSEC signing context.
 */
void knot_dnssec_sign_free(knot_dnssec_sign_context_t *context)
{
	if (!context) {
		return;
	}

	context->key = NULL;
	destroy_digest_context(&context->digest_context);
	free(context);
}

/*!
 * \brief Get DNSSEC signature size.
 */
size_t knot_dnssec_sign_size(const knot_dnssec_key_t *key)
{
	if (!key) {
		return 0;
	}

	return key->data->functions->sign_size(key);
}

/**
 * \brief Clean DNSSEC signing context to start a new signature.
 */
int knot_dnssec_sign_new(knot_dnssec_sign_context_t *context)
{
	if (!context) {
		return KNOT_EINVAL;
	}

	destroy_digest_context(&context->digest_context);
	return create_digest_context(context->key, &context->digest_context);
}

/*!
 * \brief Add data to be covered by DNSSEC signature.
 */
int knot_dnssec_sign_add(knot_dnssec_sign_context_t *context,
                         const uint8_t *data, size_t data_size)
{
	if (!context || !context->key || !data) {
		return KNOT_EINVAL;
	}

	return context->key->data->functions->sign_add(context, data, data_size);
}

/**
 * \brief Write down the DNSSEC signature for supplied data.
 */
int knot_dnssec_sign_write(knot_dnssec_sign_context_t *context, uint8_t *signature)
{
	if (!context || !context->key || !signature) {
		return KNOT_EINVAL;
	}

	return context->key->data->functions->sign_write(context, signature);
}

/**
 * \brief Verify the DNSSEC signature for supplied data.
 */
int knot_dnssec_sign_verify(knot_dnssec_sign_context_t *context,
			    const uint8_t *signature, size_t signature_size)
{
	if (!context || !context->key || !signature) {
		return KNOT_EINVAL;
	}

	return context->key->data->functions->sign_verify(context, signature,
	                                                  signature_size);
}
