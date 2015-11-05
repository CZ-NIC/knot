//
//  knsec5hash.c
//  
//
//  Created by Papadopoulos, Dimitrios on 7/6/15.
//
//

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
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <locale.h>

#include "utils/common/params.h"
#include "common/base32hex.h"
#include "libknot/errcode.h"
#include "common-knot/hex.h"
#include "common-knot/strtonum.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/nsec5hash.h"
#include "common/base64.h"


//dpapadop includes
#include <string.h>
#include <openssl/pem.h> //
#include <sys/time.h>

#define PROGRAM_NAME "knsec5hash"

/*!
 * \brief Print program usage (and example).
 */
static void usage(FILE *stream)
{
    fprintf(stream, "usage:   " PROGRAM_NAME " "
            "<hash> <keyfile> <input-string> <validate>\nexample:            sha256 testkey.pem www.example.com 1\n only accepts with sha256\n");
    //fprintf(stream, "example: " PROGRAM_NAME " "
    //       "c01dcafe 1 10 knot-dns.cz\n");
}

/*!
 * \brief Compute Full Domain Hash. UNUSED
 */

size_t fdh_sign(const uint8_t *data, size_t data_len,
                        uint8_t *sign, size_t sign_len,
                        RSA *key, const EVP_MD *hash)
{
    if (!data || !key || !sign || !hash || sign_len < RSA_size(key)) {
        return 0;
    }
    
    // compute MGF1 mask
    
    uint8_t mask[BN_num_bytes(key->n)];
    mask[0] = 0;
    int test = PKCS1_MGF1(mask + 1, sizeof(mask) - 1, data, data_len, hash);
    //int o = EVP_MD_type(hash);
    //printf("sizeofmask: %zu , data: %s , data_len: %zu , hash: %s , test %d \n", sizeof(mask), data, data_len,hash, test);
    if (test != 0) {
        return 0;
    }
    
    // compute raw RSA signature
    
    int r = RSA_private_encrypt(sizeof(mask), mask, sign, key, RSA_NO_PADDING);
    if (r < 0) {
        return 0;
    }
    
    return r;
}

/*!
 * \brief Verify Full Domain Hash. UNUSED */

bool fdh_verify(const uint8_t *data, size_t data_len,
                        const uint8_t *sign, size_t sign_len,
                        RSA *key, const EVP_MD *hash)
{
    if (!data || !key || !sign || !hash || sign_len != RSA_size(key)) {
        return false;
    }
    
    // compute MGF1 mask
    
    uint8_t mask[BN_num_bytes(key->n)];
    mask[0] = 0;
    if (PKCS1_MGF1(mask + 1, sizeof(mask) - 1, data, data_len, hash) != 0) {
        return false;
    }
    
    // reverse RSA signature
    
    uint8_t decrypted[sign_len];
    int r = RSA_public_decrypt(sign_len, sign, decrypted, key, RSA_NO_PADDING);
    if (r < 0 || r != sign_len) {
        return false;
    }
    
    // compare the result
    
    return sizeof(mask) == sizeof(decrypted) &&
    memcmp(mask, decrypted, sizeof(mask)) == 0;
}

int main(int argc, char *argv[])
{
    bool enable_idn = true;
    
    struct option options[] = {
        { "version", no_argument, 0, 'V' },
        { "help",    no_argument, 0, 'h' },
        { NULL }
    };
    
#ifdef LIBIDN
    // Set up localization.
    if (setlocale(LC_CTYPE, "") == NULL) {
        enable_idn = false;
    }
#endif
    
    int opt = 0;
    int li = 0;

    while ((opt = getopt_long(argc, argv, "hV", options, &li)) != -1) {
        switch(opt) {
            case 'V':
                fprintf(stdout, PROGRAM_NAME " version " PACKAGE_VERSION "\n");
                return 0;
            case 'h':
                usage(stdout);
                return 0;
            default:
                usage(stderr);
                return 1;
        }
    }
    
    if (argc != 5) {
        usage(stderr);
        return 1;
    }
    
    atexit(knot_crypto_cleanup);
    
    int exit_code = 1;
    
    const char *hash_name = argv[1];
    (void) hash_name;
    const char *filename   = argv[2];
    knot_dname_t *dname = NULL;
    uint8_t *hash = NULL;
    size_t hash_size = 0;
    uint8_t *sign = NULL;
    size_t sign_size = 0;
    knot_key_params_t params = { 0 };
    knot_nsec5_key_t *key = malloc(sizeof(*key));
    knot_nsec5_hash_context_t *context = NULL;
    
    uint8_t b32_digest[255];
    uint8_t *b32_digest2 = NULL;

    int32_t b32_length = 0;
    
    if (enable_idn) {
    char *ascii_name = name_from_idn(argv[3]);
        if (ascii_name == NULL) {
            fprintf(stderr, "Cannot transform IDN domain name.\n");
            goto fail;
        }
        dname = knot_dname_from_str_alloc(ascii_name);
        free(ascii_name);
    } else {
        dname = knot_dname_from_str_alloc(argv[4]);
    }
    if (dname == NULL) {
        fprintf(stderr, "Cannot parse domain name.\n");
        goto fail;
    }

    const char *ver = argv[4]; //change it from char?
 
    
    int re = knot_load_key_params(filename, &params);
    
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot load params: %s\n",
                knot_strerror(re));
        goto fail;
    }
    
    if (!key) {
        re = KNOT_ENOMEM;
        fprintf(stderr, "Cannot assign key mem: %s\n",
                                 knot_strerror(re));
        goto fail;
    }
    memset(key, '\0', sizeof(*key));
    
    re = knot_nsec5_key_from_params(&params,key);
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot load key: %s\n",
                knot_strerror(re));
        goto fail;
    }
    /*
    context = knot_nsec5_hash_init(key);

    if (!context) {
        fprintf(stderr, "Cannot init context key\n");
        goto fail;
       }
    
    re = knot_nsec5_hash_add(context,dname);
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot load dname: %s\n",
                knot_strerror(re));
        goto fail;
    }

    re = knot_nsec5_hash_write(context,sign,sign_len);
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot compute sign: %s\n",
                knot_strerror(re));
        goto fail;
    }
   
    re = knot_nsec5_sha256(sign, sign_len,&hash,&hash_size);
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot compute final hash: %s\n",
                knot_strerror(re));
        goto fail;
    }

    */
    /*
    printf("TWO-STEP CALCULATION\n");
    printf("--------------------\n");
    b32_length = base32hex_encode_alloc(hash, hash_size, &b32_digest);
    if (b32_length < 0) {
        fprintf(stderr, "Cannot encode computed hash: %s\n",
                knot_strerror(b32_length));
    }
    //b32_length = b32_length -4;
    printf("NSEC5:\n%.*s \n", b32_length,
           b32_digest);
    printf("Digest size: %zu,  Base32 size: %d\n", hash_size, b32_length);

    uint8_t b32_digest3[255];
    b32_length = base32hex_encode_no_padding(hash, hash_size, b32_digest3, sizeof(b32_digest3));
    if (b32_length < 0) {
        fprintf(stderr, "Cannot encode computed hash: %s\n",
                knot_strerror(b32_length));
    }
    printf("NSEC5 NO-PADDING:\n%.*s \n", b32_length,
           b32_digest3);
    printf("Digest size: %zu,  Base32 size: %d\n", hash_size, b32_length);
    
    b32_length = base64_encode_alloc(sign, sign_len, &b32_digest2);
    if (b32_length < 0) {
        fprintf(stderr, "Cannot encode computed signature: %s\n",
                knot_strerror(b32_length));
    }
    printf("NSEC5PROOF:\n%.*s \n", b32_length,
           b32_digest2);
    printf("Sign size: %zu,  Base32 size: %d\n", sign_len, b32_length);
    printf("==========================\n");
    
    //For validation purposes!
    knot_nsec5_hash_context_t *context2 = NULL;
    context2 = knot_nsec5_hash_init(key);
    
    if (!context2) {
        fprintf(stderr, "Cannot init context2 key\n");
        goto fail;
    }
    re = knot_nsec5_hash_add(context2,dname);
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot load dname2: %s\n",
                knot_strerror(re));
        goto fail;
    }
    uint8_t *hash2 = NULL;
    size_t hash_size2 = 0;
    re = knot_nsec5_hash(context2,&hash2,&hash_size2);
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot compute final hash2: %s\n",
                knot_strerror(re));
        goto fail;
    }
    
    printf("ONE-STEP CALCULATION\n");
    printf("--------------------\n");
    //uint8_t *b32_digest2 = NULL;

    b32_length = base32hex_encode_alloc(hash2, hash_size2, &b32_digest2);
    if (b32_length < 0) {
        fprintf(stderr, "Cannot encode computed hash: %s\n",
                knot_strerror(b32_length));
    }
    printf("NSEC5:\n%.*s \n", b32_length,
           b32_digest2);
    printf("Digest size: %zu,  Base32 size: %d\n", hash_size2, b32_length);
    
    uint8_t b32_digest4[255];
    b32_length = base32hex_encode_no_padding(hash2, hash_size2, b32_digest4, sizeof(b32_digest4));
    if (b32_length < 0) {
        fprintf(stderr, "Cannot encode computed hash: %s\n",
                knot_strerror(b32_length));
    }
    printf("NSEC5 NO-PADDING:\n%.*s \n", b32_length,
           b32_digest4);
    printf("Digest size: %zu,  Base32 size: %d\n", hash_size2, b32_length);
    printf("==========================\n");
    */
    
    //printf("QUERY-RESOLUTION COMPUTATION\n");
    //printf("--------------------\n");
    
   
    context = knot_nsec5_hash_init(key);
    
    if (!context) {
        fprintf(stderr, "Cannot init context key\n");
        goto fail;
    }
    
    struct timeval tval_before, tval_after, tval_result;
    gettimeofday(&tval_before, NULL);
    
    re = knot_nsec5_hash_add(context,dname);
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot load dname: %s\n",
                knot_strerror(re));
        goto fail;
    }
    
    re = knot_nsec5_hash_full(context,&hash,&hash_size,&sign,&sign_size);
    if (re != KNOT_EOK) {
        fprintf(stderr, "Cannot compute hash: %s\n",
                knot_strerror(re));
        goto fail;
    }
    
    b32_length = base32hex_encode_no_padding(hash, hash_size, b32_digest, sizeof(b32_digest));
    if (b32_length < 0) {
        fprintf(stderr, "Cannot encode computed hash: %s\n",
                knot_strerror(b32_length));
    }
    printf("NSEC5 (NO-PADDING):\n%.*s \n", b32_length,
           b32_digest);
    printf("Digest size: %zu,  Base32 size: %d\n", hash_size, b32_length);

    b32_length = base64_encode_alloc(sign, sign_size, &b32_digest2);
    if (b32_length < 0) {
        fprintf(stderr, "Cannot encode computed signature: %s\n",
                knot_strerror(b32_length));
    }
    printf("NSEC5PROOF:\n%.*s \n", b32_length, b32_digest2);
    printf("Sign size: %zu,  Base32 size: %d\n", sign_size, b32_length);
    printf("==========================\n");
    
    gettimeofday(&tval_after, NULL);
    
    timersub(&tval_after, &tval_before, &tval_result);
    
    printf("Time elapsed: %ld.%06ld\n", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);
    
    if(*ver=='1'){
        re = knot_nsec5_hash_verify(context,sign,sign_size);
        printf("==========================\n");
        if (re ==1) printf("Verification Succeeded\n");
        else printf("Verification Failed\n");
        printf("==========================\n");
    }
    
    
    exit_code = 0;
    
    fail:
    knot_nsec5_key_free(key);
    knot_nsec5_hash_free(context);
    knot_free_key_params(&params);
    free(hash);
    free(sign);
    free(b32_digest2);
    
    
    return exit_code;
}



