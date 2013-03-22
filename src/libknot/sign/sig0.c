#include <assert.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <time.h>
#include "common/descriptor.h"
#include "common/errcode.h"
#include "sign/bnutils.h"
#include "sign/key.h"
#include "sign/sig0.h"
#include "util/wire.h"

//! \todo Add support for Eliptic Curves (EC).

/*!
 * \brief Lifetime fudge of the SIG(0) packets in seconds.
 *
 * RFC recommends [now-5min, now+5min] lifetime interval.
 */
#define SIG0_LIFETIME_FUDGE_SECONDS 300

struct algorithm_functions;
typedef struct algorithm_functions algorithm_functions_t;

// intentionally without knot_ prefix (used only locally)
typedef struct knot_dnssec_algorithm_context algorithm_context_t;

//! \brief Algorithm state data.
struct knot_dnssec_algorithm_context {
	const algorithm_functions_t *functions;	//!< Implementation specific.
	EVP_MD_CTX *digest_context;		//!< Digest computation context.
	EVP_PKEY *private_key;			//!< Private key.
};

/*!
 * \brief Algorithm implementation specific functions.
 */
struct algorithm_functions {
	//! \brief Callback: create private key from key parameters.
	int (*create_pkey)(const knot_key_params_t *, EVP_PKEY *);
	//! \brief Callback: get signature size in bytes.
	size_t (*signature_size)(algorithm_context_t *);
	//! \brief Callback: cover supplied data with the signature.
	int (*sign_add)(algorithm_context_t *, const uint8_t *, size_t);
	//! \brief Callback: finish the signing and write out the signature.
	int (*sign_finish)(algorithm_context_t *, uint8_t *);
};

/*- Algorithm independent ----------------------------------------------------*/

/*!
 * \brief Get size of the resulting signature.
 *
 * \param context	Algorithm context.
 *
 * \return Signature size in bytes.
 */
static size_t any_sign_size(algorithm_context_t *context)
{
	assert(context);

	return (size_t)EVP_PKEY_size(context->private_key);
}

/*!
 * \brief Add data to be covered by the signature.
 *
 * \param context	Algorithm context.
 * \param data		Data to be signed.
 * \param data_size	Size of the data to be signed.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int any_sign_add(algorithm_context_t *context,
                        const uint8_t *data, size_t data_size)
{
	assert(context);
	assert(data);

	if (!EVP_SignUpdate(context->digest_context, data, data_size))
		return KNOT_DNSSEC_ESIGN;

	return KNOT_EOK;
}

/*!
 * \brief Finish the signing and write out the signature.
 *
 * \param context	Algorithm context.
 * \param signature	Output buffer with signature.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int any_sign_finish(algorithm_context_t *context, uint8_t *signature)
{
	assert(context);
	assert(signature);

	int result;
	unsigned int signature_size;

	result = EVP_SignFinal(context->digest_context, signature,
			       &signature_size, context->private_key);

	if (!result)
		return KNOT_DNSSEC_ESIGN;

	//! \todo EVP_PKEY_size() can be actually larger, not for RSA and DSA
	assert(signature_size == context->functions->signature_size(context));

	return KNOT_EOK;
}


/*- RSA specific -------------------------------------------------------------*/

/*!
 * \brief Create RSA private key from key parameters.
 *
 * \param params	Key parameters.
 * \param key		Output private key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int rsa_create_pkey(const knot_key_params_t *params, EVP_PKEY *key)
{
	assert(key);

	RSA *rsa = RSA_new();
	if (rsa == NULL)
		return KNOT_ENOMEM;

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
	assert(key);

	DSA *dsa = DSA_new();
	if (dsa == NULL)
		return KNOT_ENOMEM;

	dsa->p        = knot_b64_to_bignum(params->prime);
	dsa->q        = knot_b64_to_bignum(params->subprime);
	dsa->g        = knot_b64_to_bignum(params->base);
	dsa->priv_key = knot_b64_to_bignum(params->private_value);
	dsa->pub_key  = knot_b64_to_bignum(params->public_value);

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
static size_t dsa_sign_size(algorithm_context_t *context)
{
	// RFC 2536 (section 3 - DSA SIG Resource Record)
	return 41;
}

/*!
 * \brief Finish the signing and write out the DSA signature.
 * \see any_sign_finish
 */
static int dsa_sign_finish(algorithm_context_t *context, uint8_t *signature)
{
	assert(context);
	assert(signature);

	size_t digest_size = (size_t)EVP_PKEY_size(context->private_key);
	uint8_t *digest = calloc(1, digest_size);
	if (!digest) {
		return KNOT_ENOMEM;
	}

	int result = EVP_SignFinal(context->digest_context, digest,
				   (unsigned int *)&digest_size,
				   context->private_key);
	if (!result) {
		free(digest);
		return KNOT_DNSSEC_ESIGN;
	}

	// decode signature using Dss-Sig-Value structure (RFC2459)

	DSA_SIG *dsa_signature = DSA_SIG_new();
	if (!dsa_signature) {
		free(digest);
		return KNOT_ENOMEM;
	}

	const uint8_t *digest_scan = digest;
	if (d2i_DSA_SIG(&dsa_signature, &digest_scan, (long)digest_size) == NULL) {
		DSA_SIG_free(dsa_signature);
		free(digest);
		return KNOT_DNSSEC_ESIGN;
	}

	// convert to format defined by RFC 2536 (DSA keys and SIGs in DNS)

	// T (1 byte), R (20 bytes), S (20 bytes)
	// int8_t *signature_t = signature; // Unused variable
	uint8_t *signature_r = signature + 21 - BN_num_bytes(dsa_signature->r);
	uint8_t *signature_s = signature + 41 - BN_num_bytes(dsa_signature->s);

	// signature_t = 0x00; //! \todo How to compute T? (Only recommended.)
	BN_bn2bin(dsa_signature->r, signature_r);
	BN_bn2bin(dsa_signature->s, signature_s);

	DSA_SIG_free(dsa_signature);
	free(digest);

	return KNOT_EOK;
}

/*- Algorithm specifications -------------------------------------------------*/

static const algorithm_functions_t rsa_functions = {
        rsa_create_pkey,
        any_sign_size,
        any_sign_add,
        any_sign_finish
};

static const algorithm_functions_t dsa_functions = {
        dsa_create_pkey,
        dsa_sign_size,
        any_sign_add,
        dsa_sign_finish
};

/*!
 * \brief Get implementation specific callbacks for a given algorithm.
 *
 * \param algorithm	Algorithm number.
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
	default:
		return NULL;
	}
}

/*!
 * \brief Get message digest type for a given algorithm.
 *
 * \param algorithm	Algorithm number.
 *
 * \return Pointer to digest type specification, NULL if not implemented.
 */
static const EVP_MD *get_digest_type(knot_dnssec_algorithm_t algorithm)
{
	// EVP_<digest>() functions should not fail

	switch (algorithm) {
	case KNOT_DNSSEC_ALG_RSASHA1:
	case KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1:
	case KNOT_DNSSEC_ALG_DSA:
	case KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1:
		return EVP_sha1();
	case KNOT_DNSSEC_ALG_RSAMD5:
		return EVP_md5();
	case KNOT_DNSSEC_ALG_RSASHA256:
		return EVP_sha256();
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
 * \param params	Key parameters.
 * \param functions	Algorithm specific callbacks.
 * \param result_key	Output private key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_pkey(const knot_key_params_t *params,
                       const algorithm_functions_t *functions,
                       EVP_PKEY **result_key)
{
        assert(result_key);

	EVP_PKEY *private_key = EVP_PKEY_new();
	if (!private_key)
		return KNOT_ENOMEM;

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
 * \param params	  Key parameters.
 * \param result_context  Output message digest context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_digest_context(const knot_key_params_t *params,
				 EVP_MD_CTX **result_context)
{
	assert(result_context);

	const EVP_MD *digest_type = get_digest_type(params->algorithm);
	if (digest_type == NULL)
		return KNOT_DNSSEC_ENOTSUP;

	EVP_MD_CTX *context = EVP_MD_CTX_create();
	if (!context)
		return KNOT_ENOMEM;

	if (!EVP_SignInit_ex(context, digest_type, NULL)) {
		EVP_MD_CTX_destroy(context);
		return KNOT_DNSSEC_ECREATE_DIGEST_CONTEXT;
	}

	*result_context = context;
	return KNOT_EOK;
}

/*!
 * \brief Free algoritm context data.
 *
 * \param context	  Algorithm context.
 *
 * \return Error code, always KNOT_EOK.
 */
static int clean_algorithm_context(algorithm_context_t *context)
{
	assert(context);

	if (context->private_key) {
		EVP_PKEY_free(context->private_key);
		context->private_key = NULL;
	}

	if (context->digest_context) {
		EVP_MD_CTX_destroy(context->digest_context);
		context->digest_context = NULL;
	}

	return KNOT_EOK;
}

/*!
 * \brief Initialize algorithm context.
 *
 * \param params	Key parameters.
 * \param context	Algorithm context to be initialized.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int init_algorithm_context(const knot_key_params_t *params,
                                  algorithm_context_t *context)
{
	assert(params);
	assert(context);

	context->functions = get_implementation(params->algorithm);
	if (!context->functions)
		return KNOT_DNSSEC_ENOTSUP;

	int result = create_digest_context(params, &context->digest_context);
	if (result != KNOT_EOK) {
		clean_algorithm_context(context);
		return result;
	}

	result = create_pkey(params, context->functions, &context->private_key);
	if (result != KNOT_EOK) {
		clean_algorithm_context(context);
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
	if (!key || !params)
		return KNOT_EINVAL;

	knot_dname_t *name = knot_dname_deep_copy(params->name);
	if (!name)
		return KNOT_ENOMEM;

	algorithm_context_t *context = calloc(1, sizeof(algorithm_context_t));
	if (!context) {
		knot_dname_release(name);
		return KNOT_ENOMEM;
	}

	int result = init_algorithm_context(params, context);
	if (result != KNOT_EOK) {
		knot_dname_release(name);
		free(context);
		return result;
	}

	key->name = name;
	key->keytag = params->keytag;
	key->algorithm = params->algorithm;
	key->context = context;

	return KNOT_EOK;
}

/*!
 * \brief Free DNSSEC key structure content.
 */
int knot_dnssec_key_free(knot_dnssec_key_t *key)
{
	if (!key)
		return KNOT_EINVAL;

	if (key->name)
		knot_dname_release(key->name);

	if (key->context) {
		clean_algorithm_context(key->context);
		free(key->context);
	}

	memset(key, '\0', sizeof(knot_dnssec_key_t));

	return KNOT_EOK;
}

/*- SIG(0) internals ---------------------------------------------------------*/

/*!
 * \brief Create and initialize SIG(0) RR set.
 *
 * \return SIG(0) RR set.
 */
static knot_rrset_t *sig0_create_rrset(void)
{
	knot_dname_t *root = knot_dname_new_from_str(".", 1, NULL);
	uint32_t ttl = 0;
	knot_rrset_t *sig_record = knot_rrset_new(root, KNOT_RRTYPE_SIG,
						  KNOT_CLASS_ANY, ttl);
	knot_dname_release(root);

	return sig_record;
}

/*!
 * \brief Get size of SIG(0) rdata.
 *
 * \param key		Signing key.
 *
 * \return Size of the SIG(0) record in bytes.
 */
static size_t sig0_rdata_size(knot_dnssec_key_t *key)
{
	assert(key);

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

	size += sizeof(knot_dname_t *); // pointer to signer
	size += key->context->functions->signature_size(key->context);

	return size;
}

/*!
 * \brief Create and zero SIG(0) RDATA section.
 *
 * \param rrset		SIG(0) RR set.
 * \param key		Signing key.
 *
 * \return SIG(0) RDATA.
 */
static uint8_t *sig0_create_rdata(knot_rrset_t *rrset, knot_dnssec_key_t *key)
{
	assert(rrset);
	assert(key);

	size_t rdata_size = sig0_rdata_size(key);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
	if (!rdata)
		return NULL;

	memset(rdata, '\0', rdata_size);

	return rdata;
}

/*!
 * \brief Fill SIG(0) RDATA section except the signature field.
 *
 * \param key		Signing key.
 * \param rdata		RDATA to be filled.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sig0_write_rdata(knot_dnssec_key_t *key, uint8_t *rdata)
{
	assert(key);
	assert(rdata);

	uint32_t incepted = (uint32_t)time(NULL) - SIG0_LIFETIME_FUDGE_SECONDS;
	uint32_t expires = incepted + 2 * SIG0_LIFETIME_FUDGE_SECONDS;

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
	knot_wire_write_u16(w, key->keytag);	// key footprint
	w += sizeof(uint16_t);

	assert(w == rdata + 18);
	memcpy(w, &key->name, sizeof(knot_dname_t *)); // pointer to signer

	return KNOT_EOK;
}

/*!
 * \brief Write SIG(0) signature to a given binary wire.
 *
 * The signature covers SIG(0) RDATA section without signature field. And the
 * whole preceeding request before the SIG(0) record was added (i.e. before the
 * AR count in header was increased).
 *
 * \param wire		Output wire to be signed.
 * \param request_size	Size of the request in the wire.
 * \param sig_rr_size	Size of the SIG(0) RR in the wire.
 * \param key		Signing key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sig0_write_signature(uint8_t* wire, size_t request_size,
				size_t sig_rr_size, knot_dnssec_key_t *key)
{
	algorithm_context_t *context = key->context;
	const algorithm_functions_t *functions = context->functions;

	size_t signature_size = functions->signature_size(context);
	size_t sig_rr_header_size = 11; // owner (== root), type, class, TTL
	size_t sig_rdata_size = sig_rr_size - sig_rr_header_size;

	uint8_t *sig_rdata = wire + request_size + sig_rr_header_size;
	uint8_t *signature = wire + request_size + sig_rr_size - signature_size;

	functions->sign_add(context, sig_rdata, sig_rdata_size - signature_size);
	functions->sign_add(context, wire, request_size);

	return functions->sign_finish(context, signature);
}

/*- SIG(0) public ------------------------------------------------------------*/


/*!
 * \brief Sign a packet using SIG(0) mechanism.
 */
int knot_sig0_sign(uint8_t *wire, size_t *wire_size, size_t wire_max_size,
		   knot_dnssec_key_t *key)
{
	knot_rrset_t *sig_rrset = sig0_create_rrset();
	if (!sig_rrset) {
		return KNOT_ENOMEM;
	}

	uint8_t *sig_rdata = sig0_create_rdata(sig_rrset, key);
	if (!sig_rdata) {
		knot_rrset_deep_free(&sig_rrset, 1, 1);
		return KNOT_ENOMEM;
	}

	sig0_write_rdata(key, sig_rdata);

	// convert to wire

	uint8_t *wire_end = wire + *wire_size;
	size_t wire_avail_size = wire_max_size - *wire_size;
	size_t wire_sig_size = 0;
	uint16_t written_rr_count = 0;

	int result = knot_rrset_to_wire(sig_rrset, wire_end, &wire_sig_size,
					wire_avail_size, &written_rr_count,
					NULL);
	knot_rrset_deep_free(&sig_rrset, 1, 1);
	if (result != KNOT_EOK) {
		return result;
	}

	assert(written_rr_count == 1);

	// create signature

	result = sig0_write_signature(wire, *wire_size, wire_sig_size, key);
	if (result != KNOT_EOK) {
		return result;
	}

	uint16_t wire_arcount = knot_wire_get_arcount(wire);
	knot_wire_set_arcount(wire, wire_arcount + written_rr_count);

	*wire_size += wire_sig_size;

	return KNOT_EOK;
}
