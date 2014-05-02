/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "dnssec/binary.h"
#include "dnssec/error.h"
#include "shared.h"

/** -- **/

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

static gnutls_datum_t binary2datum(const dnssec_binary_t *from)
{
	gnutls_datum_t to = { .size = from->size, .data = from->data };
	return to;
}

static int rsa_params_to_pem(const key_params_t *params)
{
	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int result = gnutls_x509_privkey_init(&key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	gnutls_datum_t m = binary2datum(&params->modulus);
	gnutls_datum_t e = binary2datum(&params->public_exponent);
	gnutls_datum_t d = binary2datum(&params->private_exponent);
	gnutls_datum_t p = binary2datum(&params->prime_one);
	gnutls_datum_t q = binary2datum(&params->prime_two);
	gnutls_datum_t u = binary2datum(&params->coefficient);

	result = gnutls_x509_privkey_import_rsa_raw(key, &m, &e, &d, &p, &q, &u);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	//result = gnutls_x509_privkey_export_pkcs8(key, pem, NULL, pain

	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int params_to_pem(const key_params_t *params, dnssec_binary_t *pem)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}
