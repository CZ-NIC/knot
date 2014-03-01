#pragma once

#include <binary.h>

typedef struct key_parameters {
	// DNSSEC fields
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
	dnssec_binary_t public_key;

	// DNSSEC wire format
	dnssec_binary_t rdata;

	// Hashes
	char *id;
	uint16_t keytag;

	// Key information
	size_t bit_size;

} key_parameters_t;

/*

rsa.    IN      DNSKEY  256 3 8 AwEAAa2gJM9Fe8Nsm5Fxxj+O040= ;{id = 726 (zsk), size = 128b}
rsa.    IN      DS      726 8 2 cec25bd6fd28602c73f340ae6e0515d393848708a53fe1c556efa011a1b88048

Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: raAkz0V7w2ybkXHGP47TjQ==
PublicExponent: AQAB
PrivateExponent: dZynkqg0wBlyGDXgC0N1wQ==
Prime1: 3Fb4jMwlb3U=
Prime2: ybm61a7bKLk=
Exponent1: 0up1teFdHFk=
Exponent2: RriWh9OFggE=
Coefficient: A3rKPJSlKlA=

*/

static const key_parameters_t SAMPLE_RSA_KEY = {
	.flags = 256,
	.protocol = 3,
	.algorithm = 8,
	.public_key = { .size = 20, .data = (uint8_t []) {
		0x03, 0x01, 0x00, 0x01, 0xad, 0xa0, 0x24, 0xcf, 0x45, 0x7b,
		0xc3, 0x6c, 0x9b, 0x91, 0x71, 0xc6, 0x3f, 0x8e, 0xd3, 0x8d,
	}},
	.rdata = { .size = 24, .data = (uint8_t []) {
		0x01, 0x00, 0x03, 0x08,
		0x03, 0x01, 0x00, 0x01, 0xad, 0xa0, 0x24, 0xcf, 0x45, 0x7b,
		0xc3, 0x6c, 0x9b, 0x91, 0x71, 0xc6, 0x3f, 0x8e, 0xd3, 0x8d,
	}},
	.keytag = 726,
	.bit_size = 128,
};
