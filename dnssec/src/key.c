#include <assert.h>
#include <gnutls/abstract.h>
#include <stdbool.h>
#include <string.h>

#include "key.h"
#include "error.h"
#include "keytag.h"
#include "wire.h"

static const char BIN_TO_HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

char *dnssec_key_id_to_string(const dnssec_key_id_t key_id)
{
	char *str = malloc(DNSSEC_KEY_ID_STRING_SIZE + 1);
	if (!str) {
		return NULL;
	}

	for (int i = 0; i < DNSSEC_KEY_ID_SIZE; i++) {
		str[2*i]   = BIN_TO_HEX[key_id[i] >> 4];
		str[2*i+1] = BIN_TO_HEX[key_id[i] & 0x0f];
	}
	str[DNSSEC_KEY_ID_STRING_SIZE] = '\0';

	return str;
}

static bool key_is_valid(const dnssec_key_t *key)
{
	/*
	 * 2 bytes: flags
	 * 1 byte:  protocol
	 * 1 byte:  algorithm
	 * rest:    public key
	 */

	return key && key->rdata.size > 4;
}

static void update_keytag(dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return;
	}

	key->keytag = keytag(&key->rdata);
}

static void update_key_id(dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return;
	}

	strncpy((char *)key->id, "ahoj", 5);
}

int dnssec_key_new(dnssec_key_t **key_ptr)
{
	if (!key_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_key_t *key = malloc(sizeof(dnssec_key_t));
	if (!key) {
		return DNSSEC_ENOMEM;
	}

	memset(key, 0, sizeof(dnssec_key_t));
	*key_ptr = key;

	return DNSSEC_EOK;
}

void dnssec_key_clear(dnssec_key_t *key)
{
	if (!key) {
		return;
	}

	dnssec_binary_free(&key->rdata);
	gnutls_privkey_deinit(key->private_key);
	gnutls_pubkey_deinit(key->public_key);

	memset(key, 0, sizeof(dnssec_key_t));
}

void dnssec_key_free(dnssec_key_t **key_ptr)
{
	if (!key_ptr || !*key_ptr) {
		return;
	}

	dnssec_key_clear(*key_ptr);

	free(*key_ptr);
	*key_ptr = NULL;
}

uint16_t dnssec_key_get_flags(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);

	return wire_read_u16(&ctx);
}

uint8_t dnssec_key_get_protocol(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, 2);

	return wire_read_u8(&ctx);
}

uint8_t dnssec_key_get_algorithm(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	wire_ctx_t ctx;
	wire_init_binary(&ctx, &key->rdata);
	wire_seek(&ctx, 3);

	return wire_read_u8(&ctx);
}

uint16_t dnssec_key_get_keytag(const dnssec_key_t *key)
{
	if (!key_is_valid(key)) {
		return 0;
	}

	return key->keytag;
}

int dnssec_key_get_id(const dnssec_key_t *key, dnssec_key_id_t id)
{
	if (!key || !id) {
		return DNSSEC_EINVAL;
	}

	memcpy(id, key->id, DNSSEC_KEY_ID_SIZE);

	return DNSSEC_EOK;
}

int dnssec_key_from_params(dnssec_key_t *key, uint16_t flags, uint8_t protocol,
			   uint8_t algorithm, const dnssec_binary_t *public_key)
{
	if (!key || !public_key) {
		return DNSSEC_EINVAL;
	}

	size_t rdata_size = 4 + public_key->size;
	uint8_t *rdata = malloc(rdata_size);
	if (!rdata) {
		return DNSSEC_ENOMEM;
	}

	key->rdata.data = rdata;
	key->rdata.size = rdata_size;

	wire_ctx_t wc;
	wire_init(&wc, key->rdata.data, key->rdata.size);

	wire_write_u16(&wc, flags);
	wire_write_u8(&wc, protocol);
	wire_write_u8(&wc, algorithm);
	wire_write_binary(&wc, public_key);

	assert(wire_tell(&wc) == key->rdata.size);

	update_keytag(key);
	update_key_id(key);

	return DNSSEC_EOK;
}

int dnssec_key_from_dnskey(dnssec_key_t *key, const dnssec_binary_t *rdata)
{
	if (!key || !rdata) {
		return DNSSEC_EINVAL;
	}

	int result = dnssec_binary_dup(rdata, &key->rdata);
	if (result != DNSSEC_EOK) {
		return result;
	}

	update_keytag(key);
	update_key_id(key);

	return DNSSEC_EOK;
}

int dnssec_key_get_dnskey(const dnssec_key_t *key, dnssec_binary_t *rdata)
{
	if (!key_is_valid(key)) {
		return DNSSEC_EINVAL;
	}

	dnssec_binary_t copy = { 0 };
	int result = dnssec_binary_dup(&key->rdata, &copy);
	if (result != DNSSEC_EOK) {
		return result;
	}

	*rdata = copy;
	return DNSSEC_EOK;
}

int dnssec_key_get_ds(const dnssec_key_t *key, dnssec_key_digest_t digest,
		      dnssec_binary_t *rdata)
{
	return DNSSEC_ERROR;
}
