#include "binary.h"

static const char BIN_TO_HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

char *hex_to_string(const dnssec_binary_t *data)
{
	char *str = malloc(data->size * 2 + 1);
	if (!str) {
		return NULL;
	}

	for (size_t i = 0; i < data->size; i++) {
		str[2*i]   = BIN_TO_HEX[data->data[i] >> 4];
		str[2*i+1] = BIN_TO_HEX[data->data[i] & 0x0f];
	}
	str[2 * data->size] = '\0';

	return str;
}
