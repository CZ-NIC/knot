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

#ifndef _KNOTD_COMMON_PRINT_H_
#define _KNOTD_COMMON_PRINT_H_

typedef int (*printf_t)(const char *fmt, ...);

/*!
 * \brief Prints the given data as hexadecimal characters.
 *
 * \param data Data to print.
 * \param length Size of the \a data array.
 */
void hex_print(const char *data, int length);

/*!
 * \brief Prints the given data as hexadecimal characters using the given
 *        handler.
 *
 * \param data Data to print.
 * \param length Size of the \a data array.
 * \param print_handler Handler for printing.
 */
void hex_printf(const char *data, int length, printf_t print_handler);

/*!
 * \brief Prints the given data as a bitmap.
 *
 * \param data Data to print.
 * \param length Size of the \a data array.
 */
void bit_print(const char *data, int length);

/*!
 * \brief Prints the given data as a bitmap using the given handler.
 *
 * \param data Data to print.
 * \param length Size of the \a data array.
 * \param print_handler Handler for printing.
 */
void bit_printf(const char *data, int length, printf_t print_handler);

#endif /* _KNOTD_COMMON_PRINT_H_ */

/*! @} */
