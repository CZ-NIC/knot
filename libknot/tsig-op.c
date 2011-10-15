#include <assert.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include "common.h"
#include "tsig.h"
#include "tsig-op.h"
#include "util/error.h"

static int knot_tsig_copy_tsig_variables(uint8_t *wire, size_t *size,
                                         const knot_rrset_t *tsig_rr)
{
	/* Copy TSIG variables - starting with key name. */
	const knot_dname_t *tsig_owner = knot_rrset_owner(tsig_rr);
	if (!tsig_owner) {
		/* TODO cleanup. */
		return KNOT_EBADARG;
	}

	int offset = 0;

	memcpy(wire + offset, knot_dname_name(tsig_owner),
	       sizeof(uint8_t) * knot_dname_size(tsig_owner));
	offset += knot_dname_size(tsig_owner);

	/* Copy class. */
	memcpy(wire + offset, &tsig_rr->rclass, sizeof(uint16_t));
	offset += sizeof(uint32_t);

	/* Copy TTL - always 0. */
	memcpy(wire + offset, &tsig_rr->rclass, sizeof(uint32_t));
	offset += sizeof(uint32_t);

	/* Copy alg name. */
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EBADARG;
	}

	memcpy(wire + offset, knot_dname_name(alg_name),
	       sizeof(uint8_t) * knot_dname_size(alg_name));
	offset += knot_dname_size(alg_name);

	/* Following data are written in network order. */
	/* Time signed. */
	knot_wire_write_u48(wire + offset, tsig_rdata_time_signed(tsig_rr));
	offset += 6;
	/* Fudge. */
	knot_wire_write_u16(wire + offset, tsig_rdata_fudge(tsig_rr));
	offset += sizeof(uint16_t);
	/* TSIG error. */
	knot_wire_write_u16(wire + offset, tsig_rdata_error(tsig_rr));
	offset += sizeof(uint16_t);
	/* Get other data - contains its length. */
	const uint16_t *other_data = tsig_rdata_other_data(tsig_rr);
	if (!other_data) {
		return KNOT_EBADARG;
	}

	uint16_t other_data_length = other_data[0];

	knot_wire_write_u16(wire + offset, other_data_length);

	/* Skip the length. */
	other_data++;
	memcpy(wire + offset, other_data, other_data_length);
	offset += sizeof(uint16_t);

	return KNOT_EOK;
}

static int knot_tsig_write_std_digest_data(uint8_t *wire, size_t *size,
                                           const knot_rrset_t *tsig_rr)
{
	uint8_t *orig_wire = wire;
	size_t orig_size = *size;
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EBADARG;
	}

	void *tmp = realloc(wire, sizeof(uint8_t) *
	      (*size + KNOT_TSIG_VARIABLES_LENGTH +
	      knot_dname_size(alg_name)));
	if (!wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	wire = tmp;
	*size += KNOT_TSIG_VARIABLES_LENGTH + knot_dname_size(alg_name);

	/* TODO boundary checks. */

	int offset = 0;

	/* Copy the original message back. */
	memcpy(wire + offset, orig_wire, sizeof(uint8_t) * orig_size);
	offset += *size;

	/* Space for TSIG variables is already allocated. TODO maybe change. */
	if (knot_tsig_copy_tsig_variables(wire, size, tsig_rr) != KNOT_EOK) {
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

static int knot_tsig_wire_write_timers(uint8_t *wire, size_t size,
                                       const knot_rrset_t *tsig_rr)
{
	uint64_t time_signed = tsig_rdata_time_signed(tsig_rr);
	memcpy(wire, &time_signed, 6);

	uint16_t fudge = tsig_rdata_fudge(tsig_rr);
	memcpy(wire, &fudge, sizeof(uint16_t));

	return KNOT_EOK;
}

int knot_tsig_sign(uint8_t *msg, size_t *msg_len,
                   size_t msg_max_len, const uint8_t *request_mac,
                   size_t request_mac_len,
                   const knot_rrset_t *tsig_rr, const knot_key_t *key,
                   uint8_t **digest, size_t *digest_len)
{
	if (!msg || !msg_len || !tsig_rr) {
		return KNOT_EBADARG;
	}

	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		/* TODO double check. */
		return KNOT_TSIG_EBADSIG;
	}

	tsig_algorithm_t tsig_alg = tsig_alg_from_name(alg_name);

//	uint8_t *orig_msg = msg;
//	size_t orig_len = *msg_len;

	void *tmp = realloc(msg, sizeof(uint8_t) * *msg_len + request_mac_len);
	if (tmp == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	msg = tmp;
	*msg_len += request_mac_len;

	/* Copy the request MAC - should work even if NULL. */
	memcpy(msg, request_mac, sizeof(uint8_t) * request_mac_len);

	knot_tsig_write_std_digest_data(msg + request_mac_len,
	                                msg_len, tsig_rr);

	/* Create digest wire - is this needed?. */

	*digest =
		malloc(sizeof(uint8_t) * tsig_alg_digest_length(tsig_alg));
	if (!digest) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	HMAC_CTX ctx;
	HMAC_Init(&ctx, key->secret, strlen(key->secret), EVP_md5());
	HMAC_Update(&ctx, msg, *msg_len);
	HMAC_Final(&ctx, *digest, digest_len);

	return KNOT_EOK;
}

int knot_tsig_sign_next(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                        const uint8_t *prev_digest, size_t prev_digest_len,
                        const knot_rrset_t *tsig_rr, const knot_key_t *key,
                        uint8_t **digest, size_t *digest_len)
{
	/* TODO checks */
	knot_tsig_write_std_digest_data(msg, msg_len, tsig_rr);
	uint8_t *tmp_msg = msg;
	void *tmp =
		realloc(msg, sizeof(uint8_t) *
	                (*msg_len + prev_digest_len + KNOT_TSIG_TIMERS_LENGTH));
	if (!tmp) {
		return KNOT_ENOMEM;
	}
	msg = tmp;
	*msg_len += prev_digest_len + KNOT_TSIG_TIMERS_LENGTH;

	memcpy(msg, prev_digest, sizeof(uint8_t) * prev_digest_len);
	memcpy(msg + prev_digest_len, tmp_msg, *msg_len);
	knot_tsig_wire_write_timers(msg + prev_digest_len + *msg_len,
	                            *msg_len, tsig_rr);
	return KNOT_EOK;
}

int knot_tsig_server_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const knot_key_t *tsig_key)
{
	if (!tsig_rr || !wire) {
		return KNOT_EBADARG;
	}

	/* First, check that key is valid, ie. the same as given in args. */
	/* Check that libknot knows the key algorithm. */

	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EMALF;
	}

	tsig_algorithm_t alg = tsig_alg_from_name(alg_name);
	if (alg == 0) {
		/*!< \todo is this error OK? */
		return KNOT_TSIG_EBADSIG;
	}

	/* Algorithm name OK. */
	const knot_dname_t *tsig_name = knot_rrset_owner(tsig_rr);
	if (!tsig_name) {
		return KNOT_EMALF;
	}

	const char *name = knot_dname_to_str(tsig_name);
	if (!name) {
		return KNOT_EMALF;
	}

	if (strncasecmp(name, tsig_key->name,
	                knot_dname_size(tsig_name)) != 0) {
		/*!< \todo which error. */
		return KNOT_TSIG_EBADKEY;
	}

	/* TODO just one alg! */

	/* Algorithm OK, key name OK - do digest. */
	HMAC_CTX ctx;
	HMAC_Init(&ctx, tsig_key->secret, tsig_key->secret_size, EVP_MD5());
	HMAC_Update(&ctx, wire, size);

	size_t digest_size = tsig_alg_digest_length(alg);
	uint8_t *digest = malloc(sizeof(uint8_t) * digest_size);
	if (!digest) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	HMAC_Final(&ctx, digest, &digest_size);

	/* Compare MAC from TSIG RR RDATA with just computed digest. */

	const uint16_t *tsig_mac = tsig_rdata_mac(tsig_rr);
	if (!tsig_mac) {
		return KNOT_EMALF;
	}

	uint16_t mac_length = tsig_mac[0];
	/* TODO all the algs! */
	if (mac_length != tsig_alg_digest_length(alg)) {
		return KNOT_TSIG_EBADSIG;
	}

	if (strncasecmp((char *)(tsig_mac + 1), (char *)digest,
	                tsig_alg_digest_length(alg)) != 0) {
		return KNOT_TSIG_EBADSIG;
	}

	/* TODO CHECK TIME + FUDGE. */

	return KNOT_EOK;
}

int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len,
                           const knot_key_t *tsig_key)
{
	uint8_t *tmp_wire = malloc(sizeof(uint8_t) * (size + request_mac_len));
	if (!tmp_wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Prepend the request MAC. */
	memcpy(tmp_wire, request_mac, request_mac_len);
	/* Add original message. */
	memcpy(tmp_wire + request_mac_len, wire, size);
	return knot_tsig_server_check(tsig_rr, tmp_wire,
	                              request_mac_len + size, tsig_key);
}

int knot_tsig_client_check_next(const knot_rrset_t *tsig_rr,
                                const uint8_t *wire, size_t size,
                                const uint8_t *prev_digest,
                                size_t prev_digest_len,
                                const knot_key_t *tsig_key)
{
	uint8_t *tmp_wire = malloc(sizeof(uint8_t) * (size + prev_digest_len));
	if (!tmp_wire) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Prepend the previous digest. */
	memcpy(tmp_wire, prev_digest, prev_digest_len);
	/* Add original message. */
	memcpy(tmp_wire + prev_digest_len, wire, size);
	return knot_tsig_server_check(tsig_rr, tmp_wire,
	                              prev_digest_len + size, tsig_key);
}
