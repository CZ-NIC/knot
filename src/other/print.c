#include <config.h>
#include <stdio.h>

#include "common.h"
#include "print.h"

void hex_printf(const char *data, int length, printf_t print_handler)
{
	int ptr = 0;
	for (; ptr < length; ptr++) {
		print_handler("0x%02x ", (unsigned char)*(data + ptr));
	}
	print_handler("\n");
}

void hex_print(const char *data, int length)
{
	hex_printf(data, length, &printf);
}

void bit_printf(const char *data, int length, printf_t print_handler)
{
	unsigned char mask = 0x01;
	int ptr = 0;
	int bit = 0;
	for (; ptr < length; ptr++) {
		for (bit = 7; bit >= 0; bit--) {
			if ((mask << bit) & (unsigned char)*(data + ptr)) {
				print_handler("1");
			} else {
				print_handler("0");
			}
		}
		print_handler(" ");
	}
	print_handler("\n");
}

void bit_print(const char *data, int length)
{
	bit_printf(data, length, &printf);
}
