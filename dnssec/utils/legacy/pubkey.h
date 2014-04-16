#pragma once

#include "dnssec/key.h"

/*!
 * Parse public key in legacy (actually zone) format.
 */
dnssec_key_t *legacy_pubkey_parse(const char *filename);
