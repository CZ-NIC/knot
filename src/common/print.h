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

#ifndef _KNOT_COMMON_PRINT_H_
#define _KNOT_COMMON_PRINT_H_

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
 * \param printf_t Handler for printing.
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
 * \param printf_t Handler for printing.
 */
void bit_printf(const char *data, int length, printf_t print_handler);

#endif /* _KNOT_COMMON_PRINT_H_ */

/*! @} */
