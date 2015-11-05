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

#include <assert.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/opensslconf.h>
#include <openssl/rsa.h>
#include <pthread.h>
#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "libknot/common.h"
#include "libknot/consts.h"
#include "libknot/dnssec/config.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/sign.h"

#ifdef KNOT_ENABLE_ECDSA
#include <openssl/ecdsa.h>
#endif
#ifdef KNOT_ENABLE_GOST
#include <openssl/x509.h>
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
	//! \brief Callback: function called before creating any keys/contexts
	int (*algorithm_init)(void);
	//! \brief Callback: create private key from key parameters.
	int (*create_pkey)(const knot_key_params_t *, EVP_PKEY *);
	//! \brief Callback: get signature size in bytes.
	size_t (*sign_size)(const knot_dnssec_key_t *);
	//! \brief Callback: cover supplied data with the signature.
	int (*sign_add)(const knot_dnssec_sign_context_t *, const uint8_t *, size_t);
	//! \brief Callback: finish the signing and write out the signature.
	int (*sign_write)(const knot_dnssec_sign_context_t *, uint8_t *, size_t);
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
 * \brief Initialize algorithm.
 */
static int any_algorithm_init(void)
{
	return KNOT_EOK;
}

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
 * \brief Finish the signing and write the signature while checking boundaries.
 *
 * \param context    DNSSEC signing context.
 * \param signature  Pointer to signature to be written.
 * \param max_size   Maximal size of the signature.
 * \param size       Actual size of written signature.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_safe_write(const knot_dnssec_sign_context_t *context,
                           uint8_t *signature, size_t max_size, size_t *size)
{
	assert(context);
	assert(signature);
	assert(size);

	EVP_MD_CTX *digest_ctx = context->digest_context;
	EVP_PKEY *private_key = context->key->data->private_key;

	// check target size

	unsigned int max_write = EVP_PKEY_size(private_key);
	if (max_write > max_size) {
		return KNOT_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE;
	}

	// write signature

	unsigned int written = 0;
	int result = EVP_SignFinal(digest_ctx, signature, &written, private_key);
	if (!result) {
		return KNOT_DNSSEC_ESIGN;
	}

	assert(written <= max_write);
	*size = written;

	return KNOT_EOK;
}

/*!
 * \brief Allocate space for signature, finish signature, and write it.
 *
 * \param context    DNSSEC signing context.
 * \param signature  Pointer to allocated signature.
 * \param size       Size of the written signature.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_alloc_and_write(const knot_dnssec_sign_context_t *context,
                                uint8_t **signature, size_t *size)
{
	assert(context);
	assert(signature);
	assert(size);

	size_t buffer_size = EVP_PKEY_size(context->key->data->private_key);
	uint8_t *buffer = malloc(buffer_size);
	if (!buffer) {
		return KNOT_ENOMEM;
	}

	size_t written = 0;
	int result = sign_safe_write(context, buffer, buffer_size, &written);
	if (result != KNOT_EOK) {
		free(buffer);
		return result;
	}

	assert(written <= buffer_size);

	*signature = buffer;
	*size = written;

	return KNOT_EOK;
}

/*!
 * \brief Finish the signing and write out the signature.
 *
 * \note Expects algorithm whose signature size is constant.
 *
 * \param context         DNSSEC signing context.
 * \param signature       Pointer to memory where the signature will be written.
 * \param signature_size  Expected size of the signature.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int any_sign_write(const knot_dnssec_sign_context_t *context,
                          uint8_t *signature, size_t signature_size)
{
	assert(context);
	assert(signature);

	size_t written_size = 0;
	int result = sign_safe_write(context, signature,
	                             signature_size, &written_size);

	assert(written_size == signature_size);

	return result;
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

/*!
 * \brief Get pointer to and size of public key in DNSKEY RDATA.
 *
 * \param[in]  rdata        DNSKEY RDATA.
 * \param[out] pubkey       Public key.
 * \param[out] pubkey_size  Size of public key.
 *
 * \return Success.
 */
static bool any_dnskey_get_pubkey(const knot_binary_t *rdata,
                                  const uint8_t **pubkey, size_t *pubkey_size)
{
	assert(rdata);
	assert(pubkey);
	assert(pubkey_size);

	if (rdata->size <= DNSKEY_RDATA_PUBKEY_OFFSET) {
		return false;
	}

	*pubkey = rdata->data + DNSKEY_RDATA_PUBKEY_OFFSET;
	*pubkey_size = rdata->size - DNSKEY_RDATA_PUBKEY_OFFSET;

	return true;
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
 * \see any_sign_write
 */
static int dsa_sign_write(const knot_dnssec_sign_context_t *context,
                          uint8_t *signature, size_t signature_size)
{
	assert(context);
	assert(signature);

	size_t output_size = dsa_sign_size(context->key);
	if (output_size != signature_size) {
		return KNOT_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE;
	}

	// create raw signature

	uint8_t *raw_signature = NULL;
	size_t raw_size = 0;
	int result = sign_alloc_and_write(context, &raw_signature, &raw_size);
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
	if (!d2i_DSA_SIG(&decoded, &decode_scan, (long)raw_size)) {
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

	memset(signature, '\0', output_size);
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
 * \brief Decode ECDSA pulic key from RDATA and set it into EC key.
 * \note DNSKEY format for ECDSA is described in RFC 6605 section 4.
 */
static int ecdsa_set_public_key(const knot_binary_t *rdata, EC_KEY *ec_key)
{
	assert(rdata);
	assert(ec_key);

	const uint8_t *pubkey_data = NULL;
	size_t pubkey_size = 0;
	if (!any_dnskey_get_pubkey(rdata, &pubkey_data, &pubkey_size)) {
		return KNOT_EINVAL;
	}

	if (pubkey_size % 2 != 0) {
		return KNOT_EINVAL;
	}

	size_t param_size = pubkey_size / 2;
	const uint8_t *x_ptr = pubkey_data;
	const uint8_t *y_ptr = pubkey_data + param_size;

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
                            uint8_t *signature, size_t signature_size)
{
	assert(context);
	assert(signature);

	size_t output_size = ecdsa_sign_size(context->key);
	if (output_size != signature_size) {
		return KNOT_DNSSEC_EUNEXPECTED_SIGNATURE_SIZE;
	}

	// create raw signature

	uint8_t *raw_signature = NULL;
	size_t raw_size = 0;
	int result = sign_alloc_and_write(context, &raw_signature, &raw_size);
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
	if (!d2i_ECDSA_SIG(&decoded, &decode_scan, (long)raw_size)) {
		ECDSA_SIG_free(decoded);
		free(raw_signature);
		return KNOT_DNSSEC_EDECODE_RAW_SIGNATURE;
	}

	free(raw_signature);

	// convert to format defined by RFC 6605 (EC DSA for DNSSEC)
	// R and S parameters are encoded in halves of the output signature

	uint8_t *signature_r;
	uint8_t *signature_s;
	size_t param_size = output_size / 2;

	memset(signature, '\0', output_size);
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

/*- GOST specific ------------------------------------------------------------*/

#ifdef KNOT_ENABLE_GOST

static pthread_once_t gost_init_control = PTHREAD_ONCE_INIT;

static void gost_algorithm_init_once(void)
{
	knot_crypto_load_engines();
}

/*!
 * \brief Initialize GOST algorithm.
 * \see any_algorithm_init
 */
static int gost_algorithm_init(void)
{
	pthread_once(&gost_init_control, gost_algorithm_init_once);

	return KNOT_EOK;
}

// future feature (disabled now)
#if 0
/*!
 * Prefix for GOST public keys allowing to load them using X.509 API functions.
 *
 * GOST keys in X.509 PKI start with prefix which identifies key algorithm.
 * GOST public keys in DNS do not contain this prefix. We have to add it as
 * OpenSSL supports GOST using dynamic engine and has no GOST specific API.
 *
 * RFC 5933 (GOST in DNSSEC, specifies this prefix), RFC 4491 (GOST in X.509)
 */
static const uint8_t gost_x509_pubkey_prefix[] = {
	0x30, 0x63, 0x30, 0x1c, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02,
	0x02, 0x13, 0x30, 0x12, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02,
	0x02, 0x23, 0x01, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02,
	0x1e, 0x01, 0x03, 0x43, 0x00, 0x04, 0x40
};

#define GOST_DNSSEC_PUBKEY_SIZE 64
#define GOST_X509_PUBKEY_PREFIX_SIZE sizeof(gost_x509_pubkey_prefix)
#define GOST_X509_PUBKEY_SIZE (GOST_X509_PUBKEY_PREFIX_SIZE + GOST_DNSSEC_PUBKEY_SIZE)

static int gost_get_public_key(const knot_binary_t *dnskey_rdata, EVP_PKEY **key)
{
	assert(dnskey_rdata);
	assert(key);

	const uint8_t *pubkey_data = NULL;
	size_t pubkey_size = 0;
	if (!any_dnskey_get_pubkey(dnskey_rdata, &pubkey_data, &pubkey_size)) {
		return KNOT_EINVAL;
	}

	if (pubkey_size != GOST_DNSSEC_PUBKEY_SIZE) {
		return KNOT_DNSSEC_EINVALID_KEY;
	}

	// construct X.509 public key

	uint8_t x509_pubkey[GOST_X509_PUBKEY_SIZE] = { '\0' };
	uint8_t *prefix = x509_pubkey;
	uint8_t *keydata = x509_pubkey + GOST_X509_PUBKEY_PREFIX_SIZE;

	memcpy(prefix, gost_x509_pubkey_prefix, GOST_X509_PUBKEY_PREFIX_SIZE);
	memcpy(keydata, pubkey_data, pubkey_size);

	// construct EVP_PKEY

	const unsigned char **parse = (const unsigned char **)&prefix;
	EVP_PKEY *result = d2i_PUBKEY(NULL, parse, GOST_X509_PUBKEY_SIZE);
	if (!result) {
		return KNOT_DNSSEC_EINVALID_KEY;
	}

	*key = result;

	return KNOT_EOK;
}
#endif

static int gost_set_private_key(const knot_binary_t *private, EVP_PKEY **key)
{
	assert(private);
	assert(key && *key);

	const unsigned char *parse = private->data;
	EVP_PKEY *result = d2i_PrivateKey(NID_id_GostR3410_2001, key,
	                                  &parse, private->size);

	if (result != *key) {
		return KNOT_DNSSEC_EINVALID_KEY;
	}

	return KNOT_EOK;
}

/*!
 * \brief Create GOST private key from key parameters.
 * \see rsa_create_pkey
 */
static int gost_create_pkey(const knot_key_params_t *params, EVP_PKEY * key)
{
	assert(params);
	assert(key);

	int result = gost_set_private_key(&params->private_key, &key);
	if (result != KNOT_EOK) {
		return result;
	}

	return KNOT_EOK;
}

#endif

/*- Algorithm specifications -------------------------------------------------*/

static const algorithm_functions_t rsa_functions = {
	any_algorithm_init,
	rsa_create_pkey,
	any_sign_size,
	any_sign_add,
	any_sign_write,
	any_sign_verify
};

static const algorithm_functions_t dsa_functions = {
	any_algorithm_init,
	dsa_create_pkey,
	dsa_sign_size,
	any_sign_add,
	dsa_sign_write,
	dsa_sign_verify
};

#ifdef KNOT_ENABLE_ECDSA
static const algorithm_functions_t ecdsa_functions = {
	any_algorithm_init,
	ecdsa_create_pkey,
	ecdsa_sign_size,
	any_sign_add,
	ecdsa_sign_write,
	ecdsa_sign_verify
};
#endif

#ifdef KNOT_ENABLE_GOST
static const algorithm_functions_t gost_functions = {
	gost_algorithm_init,
	gost_create_pkey,
	any_sign_size,
	any_sign_add,
	any_sign_write,
	any_sign_verify
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
#ifdef KNOT_ENABLE_ECDSA
	case KNOT_DNSSEC_ALG_ECDSAP256SHA256:
	case KNOT_DNSSEC_ALG_ECDSAP384SHA384:
		return &ecdsa_functions;
#endif
#ifdef KNOT_ENABLE_GOST
	case KNOT_DNSSEC_ALG_ECC_GOST:
		return &gost_functions;
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
#if KNOT_ENABLE_GOST
	case KNOT_DNSSEC_ALG_ECC_GOST:
		return EVP_get_digestbyname(SN_id_GostR3411_94);
#endif
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
 * \brief Initialize algorithm.
 *
 * \param functions  Algorithm specific callbacks.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int init_algorithm(const algorithm_functions_t *functions)
{
	assert(functions);
	assert(functions->algorithm_init);

	return functions->algorithm_init();
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

	memset(data, '\0', sizeof(*data));

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

	knot_dnssec_key_data_t result = { 0 };

	result.functions = get_implementation(params->algorithm);
	if (!result.functions) {
		return KNOT_DNSSEC_ENOTSUP;
	}

	int error = init_algorithm(result.functions);
	if (error != KNOT_EOK) {
		return error;
	}

	error = create_pkey(params, result.functions, &result.private_key);
	if (error != KNOT_EOK) {
		return error;
	}

	*data = result;

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

	knot_dname_t *name = knot_dname_copy(params->name, NULL);
	if (!name) {
		return KNOT_ENOMEM;
	}

	knot_dnssec_key_data_t *data;
	data = calloc(1, sizeof(knot_dnssec_key_data_t));
	if (!data) {
		knot_dname_free(&name, NULL);
		return KNOT_ENOMEM;
	}

	knot_binary_t rdata_copy = { 0 };
	int result = knot_binary_dup(&params->rdata, &rdata_copy);
	if (result != KNOT_EOK) {
		knot_dname_free(&name, NULL);
		free(data);
		return result;
	}

	result = init_algorithm_data(params, data);
	if (result != KNOT_EOK) {
		knot_dname_free(&name, NULL);
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

	knot_dname_free(&key->name, NULL);

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
int knot_dnssec_sign_write(knot_dnssec_sign_context_t *context,
                           uint8_t *signature, size_t signature_size)
{
	if (!context || !context->key || !signature || signature_size == 0) {
		return KNOT_EINVAL;
	}

	return context->key->data->functions->sign_write(context, signature,
	                                                 signature_size);
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
