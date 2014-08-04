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
 * \file print.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Custom printing functions.
 *
 * Downloaded hex_print, bit_print from http://www.digitalpeer.com/id/print
 * Updated with generic printf handler.
 *
 * \addtogroup common_lib
 * @{
 */

#pragma once

#include <sys/time.h>
#include <stdint.h>

typedef int (*printf_t)(const char *fmt, ...);

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

/*!
 * \brief Prints the given data array as a specified character string using
 *        the given handler.
 *
 * \param data		Data to print.
 * \param length	Size of the \a data array.
 * \param print_handler	Handler for printing.
 * \param type		Character type ('x': hex, 't': txt, otherwise: 0xXX).
 */
void array_printf(const uint8_t *data, const unsigned length,
                  printf_t print_handler, const char type);

/*!
 * \brief Prints the given data as a bitmap.
 *
 * \param data		Data to print.
 * \param length	Size of the \a data array.
 */
void bit_print(const uint8_t *data, unsigned length);

/*!
 * \brief Prints the given data as a bitmap using the given handler.
 *
 * \param data		Data to print.
 * \param length	Size of the \a data array.
 * \param print_handler	Handler for printing.
 */
void bit_printf(const uint8_t *data, unsigned length, printf_t print_handler);

/*!
 * \brief Get time diff in miliseconds.
 *
 * \param begin
 * \param end
 *
 * \return time diff
 */
float time_diff(struct timeval *begin, struct timeval *end);

/*! @} */
