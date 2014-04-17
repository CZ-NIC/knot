#pragma once

#include "dnssec/key.h"

/*!
 * Parse public key in legacy format.
 */
int legacy_pubkey_parse(const char *filename, dnssec_key_t **key_ptr);
