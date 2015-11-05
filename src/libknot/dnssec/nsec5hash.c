/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 
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
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/opensslconf.h>
#include <openssl/rsa.h>

#include <pthread.h>
#include "libknot/descriptor.h"
#include "libknot/errcode.h"
#include "libknot/common.h"

#include "libknot/rrtype/nsec5.h"
#include "libknot/util/tolower.h"
#include "libknot/errcode.h"

#include "libknot/dnssec/config.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/nsec5hash.h"

#include "common/base32hex.h"
#include "common/base64.h"



//#define NSEC5KEY_RDATA_PUBKEY_OFFSET 1

struct nsec5_algorithm_functions;
typedef struct nsec5_algorithm_functions nsec5_algorithm_functions_t;

//! \brief Algorithm private key data and algorithm implementation.
struct knot_nsec5_key_data {
    const nsec5_algorithm_functions_t *functions; //!< Implementation specific.
    EVP_PKEY *private_key;                  //!< Private key.
    //RSA *public_key; //TEMPORARY!!!
};

//! \brief NSEC5 hash contextual data.
struct knot_nsec5_hash_context {
    const knot_nsec5_key_t *key; //!< Associated key.
    const knot_dname_t *digest_ctx;   //!< Digest computation context.
};

/*!
 * \brief Algorithm implementation specific functions.
 */
struct nsec5_algorithm_functions {
    //! \brief Callback: function called before creating any keys/contexts
    int (*algorithm_init)(void);
    //! \brief Callback: create private key from key parameters.
    int (*create_pkey)(const knot_key_params_t *, EVP_PKEY *);
    //! \brief Callback: get hash size in bytes.
    size_t (*hash_size)(const knot_nsec5_key_t *);
    //! \brief Callback: cover supplied data with the hash.
    int (*hash_add)(knot_nsec5_hash_context_t *, const knot_dname_t *);
    //! \brief Callback: finish the hashing and write out the hashing.
    int (*hash_write)(const knot_nsec5_hash_context_t *, uint8_t *, size_t);
    //! \brief Callback: finish the hashing and validate the hash.
    int (*hash_verify)(const knot_nsec5_hash_context_t *, const uint8_t *, size_t);
};

/**
 * \brief Convert binary data to OpenSSL BIGNUM format.
 */
static BIGNUM *binary_to_bn(const knot_binary_t *bin)
{
    return BN_bin2bn((unsigned char *)bin->data, (int)bin->size, NULL);
}

/*- Final hash step ----------------------------------------------------------*/

int knot_nsec5_sha256(const uint8_t *data,
                      size_t data_size, uint8_t **digest, size_t *digest_size)
{
    assert(data);
    assert(digest);
    assert(digest_size);
    
    
    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);
    
    unsigned int result_size = 0;
    uint8_t *result = (uint8_t *)malloc(EVP_MD_size(EVP_sha256()));
    if (result == NULL) {
        EVP_MD_CTX_cleanup(&mdctx);
        return KNOT_ENOMEM;
    }
    
    uint8_t *data_low = knot_strtolower(data, data_size);
    if (data_low == NULL) {
        free(result);
        EVP_MD_CTX_cleanup(&mdctx);
        return KNOT_ENOMEM;
    }
    
    const uint8_t *in = data_low;
    unsigned int in_size = data_size;
    
    EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL);
    
    int success_ops =
    EVP_DigestUpdate(&mdctx, in, in_size) +
    EVP_DigestFinal_ex(&mdctx, result, &result_size);
    
    if (success_ops != 2) {
        EVP_MD_CTX_cleanup(&mdctx);
        free(result);
        free(data_low);
        return KNOT_NSEC5_ECOMPUTE_HASH;
    }
    
    EVP_MD_CTX_cleanup(&mdctx);
    free(data_low);
    
    *digest = result;
    *digest_size = (size_t)result_size;
    
    return KNOT_EOK;
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
 * \brief Get size of the resulting hash.
 *
 * \param key  NSEC5 key.
 *
 * \return hash size in bytes.
 */
static size_t any_hash_size(const knot_nsec5_key_t *key)
{
    assert(key);
    
    return (size_t)EVP_PKEY_size(key->data->private_key);
}

/*!
 * \brief Add data to be covered by the hash.
 *
 * \param context    NSEC5 hash context.
 * \param data       Data to be hashed.
 * \param data_size  Size of the data to be hashed.
 *
 * \return Error code, KNOT_EOK if successful.
 */

int any_hash_add(knot_nsec5_hash_context_t *context,
                  const knot_dname_t *data)
{
    assert(context);
    assert(data);
    
    context->digest_ctx = data;
    if (!(context->digest_ctx)) {
        return KNOT_NSEC5_ESIGN;
    }
    
    return KNOT_EOK;
}

/*!
 * \brief Finish the hashing and write the hash while checking boundaries.
 *
 * \param context    NSEC5 signing context.
 * \param hash  Pointer to hash to be written.
 * \param max_size   Maximal size of the hash.
 * \param size       Actual size of written hash.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int hash_safe_write(const knot_nsec5_hash_context_t *context,
                           uint8_t *hash, size_t max_size, size_t *size)
{
    //OpenSSL_add_all_digests();
    assert(context);
    assert(hash);
    assert(size);
    
    // Ugly hack: fix algorithm to sha256 for now;
    const EVP_MD *hash_alg = EVP_sha256();//EVP_get_digestbyname("sha256");
    
    //EVP_MD_CTX *digest_ctx = context->digest_context;
    EVP_PKEY *private_key = context->key->data->private_key;
    
    // check target size
    unsigned int max_write = EVP_PKEY_size(private_key);
    //printf("max_write: %u\n", max_write);
    if (max_write > max_size) {
        return KNOT_NSEC5_EUNEXPECTED_SIGNATURE_SIZE;
    }
    
    // write hash
    //unsigned int written = 0;
    //int result = EVP_SignFinal(digest_ctx, signature, &written, private_key);
    //if (!result) {
    //    return KNOT_DNSSEC_ESIGN;
    //}
    
    RSA *key = EVP_PKEY_get1_RSA(private_key);
    uint8_t mask[BN_num_bytes(key->n)];
    mask[0] = 0;
    int test = PKCS1_MGF1(mask + 1, sizeof(mask) - 1, context->digest_ctx, knot_dname_size(context->digest_ctx) , hash_alg);
    //int o = EVP_MD_type(hash);
    //printf("sizeofmask: %zu , data: %s , data_len: %zu , hash: %s , test %d \n", sizeof(mask), context->digest_ctx, knot_dname_size(context->digest_ctx),hash_alg, test);
    if (test != 0) {
        printf("Problem with MGF\n");
        return 0;
    }
    
    //if (PKCS1_MGF1(mask + 1, sizeof(mask) - 1, context->digest_ctx, knot_dname_size(context->digest_ctx), hash_alg) != 0) {
    //    printf("Problem with MGF\n");
    //    return 0;
    //}
    //unsigned int written = 0;
    int r = RSA_private_encrypt(sizeof(mask), mask, hash, key, RSA_NO_PADDING);
    if (r < 0) {
        return 0;
        printf("Done with RSA\n");
    }
    
    //assert(*hash <= max_write);
    printf("hash = %ui\n", hash);
    printf("max_write = %u\n", max_write);
    *size = r;
    //printf("Assigned to written: %d\n", r);

    return KNOT_EOK;
}

/*!
 * \brief Finish the hashing and write out the hash.
 *
 * \note Expects algorithm whose hash size is constant.
 *
 * \param context    NSEC5 hashing context.
 * \param hash       Pointer to memory where the hash will be written.
 * \param hash_size  Expected size of the hash.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int any_hash_write(const knot_nsec5_hash_context_t *context,
                          uint8_t *hash, size_t hash_size)
{
    assert(context);
    assert(hash);
    
    size_t written_size = 0;
    int result = hash_safe_write(context, hash,
                                 hash_size, &written_size);
    //printf("OUT: %d\n",result);
    //printf("written_size: %zu\n",written_size);
    assert(written_size == hash_size);
    
    return result;
}

/*!
 * \brief Verify the NSEC5 hash for supplied data.
 *
 * \param context         NSEC5 hash context.
 * \param hash            Pointer to hash.
 * \param hash_size       Size of the hash.
 *
 * \return Error code.
 * \retval KNOT_EOK                        The hash is valid.
 * \retval KNOT_NSEC5_EINVALID_SIGNATURE   The hash is invalid.
 * \retval KNOT_NSEC5_ESIGN                Some error occured.
 */
static int any_hash_verify(const knot_nsec5_hash_context_t *context,
                           const uint8_t *hash, size_t hash_size)
{
    const EVP_MD *hash_alg = EVP_sha256();
    //const EVP_MD *hash_alg = EVP_get_digestbyname("sha256");
    EVP_PKEY *private_key = context->key->data->private_key;
    
    RSA *key = EVP_PKEY_get1_RSA(private_key);
    if(!key) {
        fprintf(stderr, "Error with RSA public key from context.");
        return 0;
    }
    
    //        bool valid = fdh_verify(data, data_len, sign, sign_len, pubkey, hash);
    
    uint8_t mask[BN_num_bytes(key->n)];
    mask[0] = 0;
    if (PKCS1_MGF1(mask + 1, sizeof(mask) - 1, context->digest_ctx, knot_dname_size(context->digest_ctx), hash_alg) != 0) {
        return 0;
    }
    
    uint8_t decrypted[hash_size];
    int r = RSA_public_decrypt(hash_size, hash, decrypted, key, RSA_NO_PADDING);
    if (r < 0 || r != hash_size) {
        return 0;
    }
    //printf("sizeofmask = %zu , sizeofdecrypted = %zu\n", sizeof(mask), sizeof(decrypted));
    //printf("compare: %d\n", memcmp(mask, decrypted, sizeof(mask)));
    return sizeof(mask) == sizeof(decrypted) &&
    memcmp(mask, decrypted, sizeof(mask)) == 0;
    
    //return KNOT_EOK;
    
}

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
        return KNOT_NSEC5_EINVALID_KEY;
    }
    
    if (!EVP_PKEY_assign_RSA(key, rsa)) {
        RSA_free(rsa);
        return KNOT_NSEC5_EASSIGN_KEY;
    }
    
    return KNOT_EOK;
}

static const nsec5_algorithm_functions_t rsa_functions = {
    any_algorithm_init,
    rsa_create_pkey,
    any_hash_size,
    any_hash_add,
    any_hash_write,
    any_hash_verify
};

/*!
 * \brief Get implementation specific callbacks for a given algorithm.
 *
 * \param algorithm  Algorithm number.
 *
 * \return Pointer to structure with functions, NULL if not implemented.
 */
static const nsec5_algorithm_functions_t *get_implementation(int algorithm)
{
    switch (algorithm) {
        case KNOT_NSEC5_ALGORITHM_FDH_SHA256_SHA256:
            return &rsa_functions;
        default:
            return NULL;
    }
}

/*!
 * \brief Get message digest type for a given algorithm. Currently only SHA256 output
 *
 * \param algorithm  Algorithm number.
 *
 * \return Pointer to digest type specification, NULL if not implemented.
 */
/*
 static const EVP_MD *get_digest_type(knot_nsec5_hash_algorithm_t algorithm)
 {
 // EVP_<digest>() functions should not fail (return NULL)
 
 switch (algorithm) {
 case KNOT_NSEC5_ALGORITHM_FDH_SHA256_SHA256:
 return EVP_sha256();
 default:
 return NULL;
 }
 }
 */

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
                       const nsec5_algorithm_functions_t *functions,
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
 * \param key             NSEC5 key.
 * \param result_context  Output message digest context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_digest_context(const knot_nsec5_key_t *key,
                                  const knot_dname_t **result_context)
{
    assert(key);
    assert(result_context);
    
    /*
     const EVP_MD *digest_type = get_digest_type(key->algorithm);
     if (digest_type == NULL) {
     return KNOT_NSEC5_ENOTSUP;
     }
     
     EVP_MD_CTX *context = EVP_MD_CTX_create();
     if (!context) {
     return KNOT_ENOMEM;
     }
     
     if (!EVP_DigestInit_ex(context, digest_type, NULL)) {
     EVP_MD_CTX_destroy(context);
     return KNOT_NSEC5_ECREATE_DIGEST_CONTEXT;
     }
     */
    
    
    *result_context = NULL;
    return KNOT_EOK;
}

/*!
 * \brief Destroy message digest context.
 *
 * \param context  Context to be freed.
 *
 * \return Always KNOT_EOK.
 */
static int destroy_digest_context(const knot_dname_t **context)
{
    assert(context);
    
    if (*context) {
        knot_dname_free((knot_dname_t **)context,NULL);
        //*context = NULL;
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
static int init_algorithm(const nsec5_algorithm_functions_t *functions)
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
static int clean_algorithm_data(knot_nsec5_key_data_t *data)
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
                               knot_nsec5_key_data_t *data)
{
    assert(params);
    assert(data);
    
    knot_nsec5_key_data_t result = { 0 };
    
    result.functions = get_implementation(params->algorithm);
    if (!result.functions) {
        return KNOT_NSEC5_ENOTSUP;
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
 * \brief Fill NSEC5 key structure according to key parameters.
 */
int knot_nsec5_key_from_params(const knot_key_params_t *params,
                               knot_nsec5_key_t *key)
{
    if (!key || !params) {
        return KNOT_EINVAL;
    }
    
    if (!params->nsec5) {
        printf("Not NSEC5 Key\n");
        return KNOT_NSEC5_EINVALID_KEY;

    }
    
    knot_dname_t *name = knot_dname_copy(params->name, NULL);
    if (!name) {
        return KNOT_ENOMEM;
    }
    
    knot_nsec5_key_data_t *data;
    data = calloc(1, sizeof(knot_nsec5_key_data_t));
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
    
    result = init_algorithm_data(params, data); //bring this in
    if (result != KNOT_EOK) {
        knot_dname_free(&name, NULL);
        free(data);
        knot_binary_free(&rdata_copy);
        return result;
    }
    
    key->name = name;
    key->keytag = params->keytag;
    key->algorithm =  params->algorithm;
    //printf("VATHEIA STI ZOUGKLA NSEC5KEY --> key_alg= %d, param_alg= %d\n",key->algorithm, params->algorithm);

    key->data = data;
    key->nsec5key_rdata = rdata_copy;
    
    return KNOT_EOK;
}

/*!
 * \brief Free NSEC5 key structure content.
 */
int knot_nsec5_key_free(knot_nsec5_key_t *key)
{
    if (!key) {
        return KNOT_EINVAL;
    }
    
    knot_dname_free(&key->name, NULL);
    
    if (key->data) {
        clean_algorithm_data(key->data);
        free(key->data);
    }
    
    knot_binary_free(&key->nsec5key_rdata);
    
    memset(key, '\0', sizeof(knot_nsec5_key_t));
    
    return KNOT_EOK;
}

/*- Public low level hashing interface ---------------------------------------*/

/*!
 * \brief Initialize NSEC5 hashing context.
 */
knot_nsec5_hash_context_t *knot_nsec5_hash_init(const knot_nsec5_key_t *key)
{
    if (!key) {
        return NULL;
    }
    
    knot_nsec5_hash_context_t *context = malloc(sizeof(*context));
    if (!context) {
        return NULL;
    }
    
    context->key = key;
    
    if (create_digest_context(key, &context->digest_ctx) != KNOT_EOK) {
        free(context);
        return NULL;
    }
    
    return context;
}

/*!
 * \brief Free NSEC5 hashing context.
 */
void knot_nsec5_hash_free(knot_nsec5_hash_context_t *context)
{
    if (!context) {
        return;
    }
    
    context->key = NULL;
    destroy_digest_context(&context->digest_ctx);
    free(context);
}

/*!
 * \brief Get NSEC5 hash size.
 */
size_t knot_nsec5_hash_size(const knot_nsec5_key_t *key)
{
    if (!key) {
        return 0;
    }
    
    return key->data->functions->hash_size(key);
}

/**
 * \brief Clean NSEC5 hash context to start a new hash.
 */
int knot_nsec5_hash_new(knot_nsec5_hash_context_t *context)
{
    if (!context) {
        return KNOT_EINVAL;
    }
    
    destroy_digest_context(&context->digest_ctx);
    return create_digest_context(context->key, &context->digest_ctx);
}

/*!
 * \brief Add data to be covered by NSEC5 hash.
 */
int knot_nsec5_hash_add(knot_nsec5_hash_context_t *context,
                         const knot_dname_t *data)
{
    if (!context || !context->key || !data) {
        return KNOT_EINVAL;
    }
    
    return context->key->data->functions->hash_add(context, data);
}


/**
 * \brief Write down the NSEC5 hash for supplied data.
 */
int knot_nsec5_hash_write(knot_nsec5_hash_context_t *context,
                          uint8_t *hash, size_t hash_size)
{
    if (!context || !context->key || !hash || hash_size == 0) {
        return KNOT_EINVAL;
    }
    
    return context->key->data->functions->hash_write(context, hash,
                                                          hash_size);
}

/**
 * \brief Verify the NSEC5 hash for supplied data.
 */
int knot_nsec5_hash_verify(knot_nsec5_hash_context_t *context,
                           const uint8_t *hash, size_t hash_size)
{
    if (!context || !context->key || !hash) {
        return KNOT_EINVAL;
    }
    
    return context->key->data->functions->hash_verify(context, hash,
                                                      hash_size);
}


/**
 * \brief Write down the FINAL NSEC5 hash for supplied data.
 */
int knot_nsec5_hash(knot_nsec5_hash_context_t *context,
                          uint8_t **digest, size_t *digest_size)
{
    if (!context ) {
        printf("den yparxei context\n");
        return KNOT_EINVAL;
    }
    if (!context->key) {
        printf("den yparxei context=>key\n");
        return KNOT_EINVAL;
    }
    //printf("perasa apo to prwto test\n");
    assert(digest);
    assert(digest_size);
    
    size_t hash_len = knot_nsec5_hash_size(context->key); //fix to work for any key length
    //printf("FDH_len (internal): %zu\n", hash_len);
    uint8_t hash[hash_len];
    
    int ret = knot_nsec5_hash_write(context, hash,hash_len);
    if (ret != KNOT_EOK) {
        printf("Cannot compute fhd sign (internal): %s\n",
                knot_strerror(ret));
        return KNOT_DNSSEC_ESIGN;
    }
    /*
    uint8_t *b32_digest = NULL;
    printf("*********************************\n");
    int32_t b32_length = base64_encode_alloc(hash, hash_len, &b32_digest);
    printf("NSEC5PROOF:\n%.*s \n", b32_length,
           b32_digest);
    printf("*********************************\n");
*/
    
    //printf("eftasa sto teleytaio step\n");
    return knot_nsec5_sha256(hash,hash_len,digest,digest_size);
}


/**
 * \brief Write down the both the final NSEC5 hash and the intermediate FDH for supplied data.
 *          (this is implementation specific :FDH with RSA....
 */
int knot_nsec5_hash_full(knot_nsec5_hash_context_t *context,
                    uint8_t **digest, size_t *digest_size, uint8_t **sign, size_t *sign_size)
{
    if (!context ) {
        printf("den yparxei context\n");
        return KNOT_EINVAL;
    }
    if (!context->key) {
        printf("den yparxei context=>key\n");
        return KNOT_EINVAL;
    }
    //printf("perasa apo to prwto test\n");
    assert(digest);
    assert(digest_size);
    assert(sign);
    assert(sign_size);
    
    size_t temp_sign_size = knot_nsec5_hash_size(context->key); //fix to work for any key length
    //printf("temp_sign_size : %zu\n", temp_sign_size);
    //printf("FDH_len (internal): %zu\n", hash_len);
    //uint8_t temp_sign[temp_sign_size];
    uint8_t *temp_sign = (uint8_t *)malloc(sizeof(uint8_t)*temp_sign_size);

    
    int ret = knot_nsec5_hash_write(context, temp_sign,temp_sign_size);
    if (ret != KNOT_EOK) {
        printf("Cannot compute fhd sign (internal): %s\n",
               knot_strerror(ret));
        return KNOT_DNSSEC_ESIGN;
    }
    
    //uint8_t *b32_digest = NULL;
    //printf("*********************************\n");
    //int32_t b32_length = base32hex_encode_alloc(temp_sign, temp_sign_size, &b32_digest);
    //printf("NSEC5PROOF:\n%.*s \n", b32_length,
     //      b32_digest);
    //printf("*********************************\n");
    
    *sign_size = temp_sign_size;
    *sign = temp_sign;
    
    //printf("*********************************\n");
    //b32_length = base32hex_encode_alloc(*sign, *sign_size, &b32_digest);
    //printf("NSEC5PROOF:\n%.*s \n", b32_length,
    //       b32_digest);
    //printf("*********************************\n");
    
    //printf("eftasa sto teleytaio step\n");
    ret = knot_nsec5_sha256(*sign,*sign_size,digest,digest_size);
    
    /*uint8_t *b32_digest = NULL;
    printf("************nsec5hash.c*************\n");
    int32_t b32_length = base64_encode_alloc(*sign, *sign_size, &b32_digest);
    printf("NSEC5PROOF:\n%.*s \n", b32_length,
           b32_digest);
    printf("*********************************\n");
    */
    return ret;
}


