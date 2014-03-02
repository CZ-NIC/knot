#pragma once

#include "../binary.h"
#include "../key.h"

int dnssec_key_from_rsa_params(dnssec_key_t *key,
			       dnssec_key_algorithm_t algorithm,
			       const dnssec_binary_t *modulus,
			       const dnssec_binary_t *public_exponent,
			       const dnssec_binary_t *private_exponent,
			       const dnssec_binary_t *prime_one,
			       const dnssec_binary_t *prime_two,
			       const dnssec_binary_t *coefficient);

int dnssec_key_from_dsa_params(dnssec_key_t *key,
			       dnssec_key_algorithm_t algorithm,
			       const dnssec_binary_t *prime,
			       const dnssec_binary_t *subprime,
			       const dnssec_binary_t *base,
			       const dnssec_binary_t *private_x,
			       const dnssec_binary_t *private_y);

int dnssec_key_from_ecdsa_params(dnssec_key_t *key,
                                 dnssec_key_algorithm_t algorithm,
			         const dnssec_binary_t *x_coordinate,
			         const dnssec_binary_t *y_coordinate,
			         const dnssec_binary_t *private_key);
