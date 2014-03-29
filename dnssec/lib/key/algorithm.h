#pragma once

#include <gnutls/gnutls.h>

#include "key.h"

/*!
 * Convert DNSKEY algorithm identifier to GnuTLS identifier.
 *
 * \param dnssec  DNSSEC DNSKEY algorithm identifier.
 *
 * \return GnuTLS private key algorithm identifier, GNUTLS_PK_UNKNOWN on error.
 */
gnutls_pk_algorithm_t algorithm_to_gnutls(dnssec_key_algorithm_t dnssec);
