#include <assert.h>
#include <nettle/base64.h>
#include <string.h>

#include "binary.h"
#include "error.h"

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

int dnssec_binary_from_base64(dnssec_binary_t *binary, const uint8_t *base64, size_t base64_size)
{
	if (!binary || !base64) {
		return DNSSEC_EINVAL;
	}

	size_t raw_size = BASE64_DECODE_LENGTH(base64_size);
	uint8_t *raw = malloc(raw_size);
	if (raw == NULL) {
		return DNSSEC_ENOMEM;
	}

	size_t real_size = base64_decode_raw(base64, base64_size, raw, raw_size);
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

	binary->data = NULL;
	binary->size = 0;
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
	if (new_data == NULL) {
		return DNSSEC_ENOMEM;
	}

	data->data = new_data;
	data->size = new_size;

	return DNSSEC_EOK;
}
