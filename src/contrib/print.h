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
 * \file
 *
 * \brief Custom printing functions.
 *
 * \addtogroup contrib
 * @{
 */

#pragma once

#include <stdint.h>

/*!
 * \brief Prints the given data as hexadecimal character string. Each hexa-pair
 *        contains leading 0x string.
 *
 * \param data		Data to print.
 * \param length	Size of the \a data array.
 */
void hex_print(const uint8_t *data, unsigned length);

/*!
 * \brief Prints the given data as hexadecimal character string.
 *
 * \param data		Data to print.
 * \param length	Size of the \a data array.
 */
void short_hex_print(const uint8_t *data, unsigned length);

/*!
 * \brief Prints the given data as text character string. Unprintable characters
 *        are replaced with a space.
 *
 * \param data		Data to print.
 * \param length	Size of the \a data array.
 */
void txt_print(const uint8_t *data, unsigned length);

/*! @} */
