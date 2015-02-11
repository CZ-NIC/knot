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
/*!
 * \file key.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Interface for loading of DNSSEC keys.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include "libknot/dname.h"
#include "libknot/binary.h"
#include "libknot/rrtype/tsig.h"

/*!
 * \brief Key attributes loaded from keyfile.
 */
typedef struct knot_key_params {
	knot_dname_t *name;
	int algorithm;
	dnssec_binary_t secret;
} knot_key_params_t;

/*!
 * \brief Copy key parameters.
 */
int knot_copy_key_params(const knot_key_params_t *src, knot_key_params_t *dst);

/*!
 * \brief Free key parameters.
 */
int knot_free_key_params(knot_key_params_t *key_params);

/*!
 * \brief Creates TSIG key.
 *
 * \param name       Key name (aka owner name).
 * \param algorithm  Algorithm number.
 * \param b64secret  Shared secret encoded in Base64.
 * \param key        Output TSIG key.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_tsig_create_key(const char *name, dnssec_tsig_algorithm_t algorithm,
                         const char *b64secret, knot_tsig_key_t *key);

/*!
 * \brief Copies key params structure content.
 *
 * \param src  Source structure.
 * \param dst  Destination structure.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_copy_key_params(const knot_key_params_t *src, knot_key_params_t *dst);

/*!
 * \brief Frees TSIG key.
 *
 * The structure itself is not freed.
 *
 * \param key  TSIG key structure to be freed.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_tsig_key_free(knot_tsig_key_t *key);

/*!
 * \brief Creates TSIG key from key parameters.
 *
 * \param params  Structure with key parameters.
 * \param key     Output TSIG key.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_tsig_key_from_params(const knot_key_params_t *params,
                              knot_tsig_key_t *key);

/*! @} */
