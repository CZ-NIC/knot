#include <assert.h>
#include <ctype.h>
#include <string.h>

#include "binary.h"
#include "error.h"

static const char BIN_TO_HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

int bin_to_hex(const dnssec_binary_t *bin, char **hex_ptr)
{
	assert(bin);
	assert(hex_ptr);

	char *hex = malloc(bin->size * 2 + 1);
	if (!hex) {
		return DNSSEC_ENOMEM;
	}

	for (size_t i = 0; i < bin->size; i++) {
		hex[2*i]   = BIN_TO_HEX[bin->data[i] >> 4];
		hex[2*i+1] = BIN_TO_HEX[bin->data[i] & 0x0f];
	}
	hex[2 * bin->size] = '\0';

	*hex_ptr = hex;

	return DNSSEC_EOK;
}

/*!
 * Convert HEX character to numeric value (assumes valid and lowercase input).
 */
static uint8_t hex_to_number(const char hex)
{
	if (hex >= '0' && hex <= '9') {
		return hex - '0';
	} else {
		return hex - 'a' + 10;
	}
}

int hex_to_bin(const char *hex, dnssec_binary_t *bin)
{
	assert(hex);
	assert(bin);

	// validate input

	size_t hex_size = strlen(hex);

	if (hex_size % 2 != 0) {
		return DNSSEC_MALFORMED_DATA;
	}

	for (int i = 0; i < hex_size; i++) {
		if (!isxdigit(hex[i])) {
			return DNSSEC_MALFORMED_DATA;
		}
	}

	// build output

	size_t bin_size = hex_size / 2;
	if (bin_size == 0) {
		bin->size = 0;
		bin->data = NULL;
		return DNSSEC_EOK;
	}

	int result = dnssec_binary_alloc(bin, bin_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	for (size_t i = 0; i < bin_size; i++) {
		uint8_t high = hex_to_number(tolower(hex[2 * i]));
		uint8_t low  = hex_to_number(tolower(hex[2 * i + 1]));
		bin->data[i] = high << 4 | low;
	}

	return DNSSEC_EOK;
}
