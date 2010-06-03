#ifndef __print_h__
#define __print_h__

/*----------------------------------------------------------------------------*/
/* Downloaded hex_print, bit_print from http://www.digitalpeer.com/id/print   */
/* Updated with generic printf handler.                                       */
/*----------------------------------------------------------------------------*/

typedef int (*printf_t)(const char* fmt, ...);

/* Hex-value printing.
 */

void hex_print( const char *data, int length );
void hex_printf( const char *data, int length, printf_t print_handler );

/* Bit-value printing.
 */

void bit_print( const char *data, int length );
void bit_printf( const char *data, int length, printf_t print_handler );

#endif  // __print_h__
