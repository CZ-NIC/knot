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
 * \addtogroup utils
 * @{
 */

#ifndef _CUTEDNS_PRINT_H_
#define _CUTEDNS_PRINT_H_

typedef int (*printf_t)(const char *fmt, ...);

/* Hex-value printing.
 */

void hex_print(const char *data, int length);
void hex_printf(const char *data, int length, printf_t print_handler);

/* Bit-value printing.
 */

void bit_print(const char *data, int length);
void bit_printf(const char *data, int length, printf_t print_handler);

#endif  /* _CUTEDNS_PRINT_H_ */

/*! @} */
