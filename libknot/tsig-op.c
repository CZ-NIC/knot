#include <assert.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <time.h>

#include "common.h"
#include "tsig.h"
#include "tsig-op.h"
#include "util/error.h"

static int knot_tsig_check_algorithm(const knot_rrset_t *tsig_rr)
{
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EMALF;
	}

	tsig_algorithm_t alg = tsig_alg_from_name(alg_name);
	if (alg == 0) {
		/*!< \todo is this error OK? */
		return KNOT_TSIG_EBADSIG;
	}

	return KNOT_EOK;
}

static int knot_tsig_check_key(const knot_rrset_t *tsig_rr,
                               const knot_key_t *tsig_key)
{
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

	return KNOT_EOK;
}

static int knot_tsig_compute_digest(const knot_rrset_t *tsig_rr,
                                    const uint8_t *wire, size_t wire_len,
                                    uint8_t **digest, size_t *digest_len,
                                    const knot_key_t *key)
{
	if (!tsig_rr || !wire || !digest || !digest_len || !key) {
		return KNOT_EBADARG;
	}

	/* Get the algorithm. */
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EMALF;
	}

	tsig_algorithm_t tsig_alg = tsig_alg_from_name(alg_name);
	if (tsig_alg == 0) {
		return KNOT_TSIG_EBADSIG;
	}

	/* Create digest, using length of the algorithm. */
	*digest =
		malloc(sizeof(uint8_t) * tsig_alg_digest_length(tsig_alg));
	if (!digest) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Compute digest. */
	HMAC_CTX ctx;

	switch (tsig_alg) {
		case KNOT_TSIG_ALG_HMAC_MD5:
			HMAC_Init(&ctx, key->secret,
			          key->secret_size, EVP_md5());
			break;
		default:
			return KNOT_ENOTSUP;
	} /* switch */

	HMAC_Update(&ctx, wire, wire_len);
	HMAC_Final(&ctx, *digest, digest_len);

	return KNOT_EOK;
}

static int knot_tsig_check_time_signed(const knot_rrset_t *tsig_rr)
{
	if (!tsig_rr) {
		return KNOT_EBADARG;
	}

	/* Get the time signed and fudge values. */
	uint64_t time_signed = tsig_rdata_time_signed(tsig_rr);
	if (time_signed == 0) {
		return KNOT_TSIG_EBADTIME;
	}
	uint16_t fudge = tsig_rdata_fudge(tsig_rr);
	if (fudge == 0) {
		return KNOT_TSIG_EBADTIME;
	}

	/* Get the current time. */
	time_t curr_time = time(NULL);

	/*!< \todo bleeding eyes. */
	if (difftime(curr_time, (time_t)time_signed) > fudge) {
		return KNOT_TSIG_EBADTIME;
	}

	return KNOT_EOK;
}

static int knot_tsig_write_tsig_variables(uint8_t *wire, size_t *size,
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

	/*!< \todo which order? */

	/* Copy class. */
	knot_wire_write_u16(wire + offset, knot_rrset_class(tsig_rr));
	offset += sizeof(uint16_t);

	/* Copy TTL - always 0. */
	knot_wire_write_u32(wire + offset, knot_rrset_ttl(tsig_rr));
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

	/*
	 * We cannot write the whole other_data, as it contains its length in
	 * machine order.
	 */
	uint16_t other_data_length = other_data[0];
	knot_wire_write_u16(wire + offset, other_data_length);
	offset += sizeof(uint16_t);

	/* Skip the length. */
	other_data++;
	memcpy(wire + offset, other_data, other_data_length);
	offset += sizeof(uint16_t);

	*size += offset;

	return KNOT_EOK;
}

static int knot_tsig_write_std_digest_data(uint8_t *wire, size_t *size,
                                           const knot_rrset_t *tsig_rr)
{
	const uint8_t *orig_wire = wire;
	size_t orig_size = *size;
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EBADARG;
	}

	*size += KNOT_TSIG_VARIABLES_LENGTH + knot_dname_size(alg_name);

	/* TODO boundary checks. */

	int offset = 0;

	/* Copy the original message. */
	memcpy(wire + offset, orig_wire, sizeof(uint8_t) * orig_size);
	offset += *size;

	/* Space for TSIG variables is already allocated. */
	if (knot_tsig_write_tsig_variables(wire + offset,
	                                   size, tsig_rr) != KNOT_EOK) {
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

static int knot_tsig_wire_write_timers(uint8_t *wire, size_t size,
                                       const knot_rrset_t *tsig_rr)
{
	knot_wire_write_u48(wire, tsig_rdata_time_signed(tsig_rr));
	knot_wire_write_u16(wire + 6, tsig_rdata_fudge(tsig_rr));

	return KNOT_EOK;
}

int knot_tsig_sign(uint8_t *msg, size_t *msg_len,
                   size_t msg_max_len, const uint8_t *request_mac,
                   size_t request_mac_len,
                   const knot_rrset_t *tsig_rr,
                   uint8_t **digest, size_t *digest_len,
                   const knot_key_t *key)
{
	if (!msg || !msg_len || !tsig_rr || !digest || !digest_len || !key) {
		return KNOT_EBADARG;
	}

	/* Copy the request MAC - should work even if NULL. */
	memcpy(msg, request_mac, sizeof(uint8_t) * request_mac_len);
	*msg_len += request_mac_len;

	/* Copies the original message appended with TSIG variables. */
	/*!< msg_len is changed, \todo consider returning added bytes */
	int ret = knot_tsig_write_std_digest_data(msg + request_mac_len,
	                                          msg_len, tsig_rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Compute digest. */
	ret = knot_tsig_compute_digest(tsig_rr, msg, *msg_len,
	                               digest, digest_len, key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

int knot_tsig_sign_next(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                        const uint8_t *prev_digest, size_t prev_digest_len,
                        const knot_rrset_t *tsig_rr, const knot_key_t *key,
                        uint8_t **digest, size_t *digest_len)
{
	if (!msg || !msg_len || !tsig_rr || !key || !key) {
		return KNOT_EBADARG;
	}
	const uint8_t *orig_msg = msg;
	size_t orig_len = *msg_len;

	*msg_len += prev_digest_len + KNOT_TSIG_TIMERS_LENGTH;
	/*!< \todo proper check! */
	assert(*msg_len <= msg_max_len);

	/* Write previous digest. */
	memcpy(msg, prev_digest, sizeof(uint8_t) * prev_digest_len);
	/* Write original message. */
	memcpy(msg + prev_digest_len, orig_msg, orig_len);
	/* Write timers. */
	knot_tsig_wire_write_timers(msg + prev_digest_len + orig_len,
	                            msg_max_len, tsig_rr);

	int ret = knot_tsig_compute_digest(tsig_rr, msg, *msg_len,
	                                   digest, digest_len, key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

int knot_tsig_server_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const knot_key_t *tsig_key)
{
	if (!tsig_rr || !wire || !tsig_key) {
		return KNOT_EBADARG;
	}

	/* Check time signed. */
	int ret = knot_tsig_check_time_signed(tsig_rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check that libknot knows the algorithm. */
	ret = knot_tsig_check_algorithm(tsig_rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check that key is valid, ie. the same as given in args. */
	ret = knot_tsig_check_key(tsig_rr, tsig_key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Time OK algorithm OK, key name OK - do digest. */
	uint8_t *digest = NULL;
	size_t digest_len = 0;
	ret = knot_tsig_compute_digest(tsig_rr, wire, size, &digest,
	                               &digest_len, tsig_key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Compare MAC from TSIG RR RDATA with just computed digest. */
	const uint16_t *tsig_mac = tsig_rdata_mac(tsig_rr);
	if (!tsig_mac) {
		return KNOT_EMALF;
	}

	/*!< \todo move to function. */
	const knot_dname_t *alg_name = tsig_rdata_alg_name(tsig_rr);
	tsig_algorithm_t alg = tsig_alg_from_name(alg_name);

	uint16_t mac_length = tsig_mac[0];
	if (mac_length != tsig_alg_digest_length(alg)) {
		return KNOT_TSIG_EBADSIG;
	}

	assert(tsig_alg_digest_length(alg) == mac_length);

	if (strncasecmp((char *)(tsig_mac + 1), (char *)digest,
	                tsig_alg_digest_length(alg)) != 0) {
		return KNOT_TSIG_EBADSIG;
	}

	return KNOT_EOK;
}

int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len,
                           const knot_key_t *tsig_key)
{
	if (!tsig_rr || !wire || !request_mac || !tsig_key) {
		return KNOT_EBADARG;
	}

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
	return knot_tsig_client_check(tsig_rr, wire, size, prev_digest,
	                              prev_digest_len, tsig_key);
}
