/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <gnutls/x509.h>
#include <stdint.h>
#include <stdlib.h>

#define CERT_PIN_LEN 32

/*!
 * \brief Get certificate pin value.
 *
 * The pin is a SHA-256 hash of the X.509 SubjectPublicKeyInfo.
 *
 * \param[in]  crt   Certificate.
 * \param[out] pin   Pin.
 * \param[in]  size  Length of the pin, must be CERT_PIN_LEN.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int cert_get_pin(gnutls_x509_crt_t crt, uint8_t *pin, size_t size);
