#pragma once

#include <gnutls/abstract.h>
#include "binary.h"

int rsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata);
int dsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata);
int ecdsa_pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata);

int rsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key);
int dsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key);
int ecdsa_rdata_to_pubkey(const dnssec_binary_t *rdata, gnutls_pubkey_t key);

int pubkey_to_rdata(gnutls_pubkey_t key, dnssec_binary_t *rdata);
int rdata_to_pubkey(uint8_t algorithm, const dnssec_binary_t *rdata, gnutls_pubkey_t key);
