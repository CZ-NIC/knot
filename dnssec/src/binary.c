#include <assert.h>
#include <nettle/base64.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "shared.h"

static size_t base64_decode_raw(const uint8_t *src, size_t src_len,
				uint8_t *dst, size_t dst_max_size)
{
	assert(src);
	assert(dst);

	struct base64_decode_ctx ctx;
	base64_decode_init(&ctx);

	unsigned dst_size = dst_max_size;
	int result = base64_decode_update(&ctx, &dst_size, dst, src_len, src);
	if (result != 1) {
		return 0;
	}

	return (size_t) dst_size;
}

/* -- public API ----------------------------------------------------------- */

int dnssec_binary_from_base64(const dnssec_binary_t *base64,
			      dnssec_binary_t *binary)
{
	if (!base64 || !binary) {
		return DNSSEC_EINVAL;
	}

	if (base64->size == 0) {
		clear_struct(binary);
		return DNSSEC_EOK;
	}

	size_t raw_size = BASE64_DECODE_LENGTH(base64->size);
	uint8_t *raw = malloc(raw_size);
	if (raw == NULL) {
		return DNSSEC_ENOMEM;
	}

	size_t real_size = base64_decode_raw(base64->data, base64->size,
					     raw, raw_size);
	if (real_size == 0) {
		free(raw);
		return DNSSEC_EINVAL;
	}

	if (real_size < raw_size) {
		raw = realloc(raw, real_size);
	}

	binary->data = raw;
	binary->size = real_size;

	return DNSSEC_EOK;
}

void dnssec_binary_free(dnssec_binary_t *binary)
{
	if (!binary) {
		return;
	}

	free(binary->data);
	clear_struct(binary);
}

int dnssec_binary_dup(const dnssec_binary_t *from, dnssec_binary_t *to)
{
	if (!from || !to) {
		return DNSSEC_EINVAL;
	}

	uint8_t *copy = malloc(from->size);
	if (copy == NULL) {
		return DNSSEC_ENOMEM;
	}

	memcpy(copy, from->data, from->size);

	to->size = from->size;
	to->data = copy;

	return DNSSEC_EOK;
}

int dnssec_binary_resize(dnssec_binary_t *data, size_t new_size)
{
	if (!data) {
		return DNSSEC_EINVAL;
	}

	uint8_t *new_data = realloc(data->data, new_size);
	if (new_size > 0 && new_data == NULL) {
		return DNSSEC_ENOMEM;
	}

	data->data = new_data;
	data->size = new_size;

	return DNSSEC_EOK;
}
