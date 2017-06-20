/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <inttypes.h>
#include <time.h>
#include <stdint.h>

#include "dnssec/error.h"
#include "dnssec/tsig.h"
#include "libknot/attribute.h"
#include "libknot/tsig-op.h"
#include "libknot/errcode.h"
#include "libknot/descriptor.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/packet/wire.h"
#include "libknot/consts.h"
#include "libknot/descriptor.h"
#include "libknot/packet/wire.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/tsig-op.h"
#include "libknot/packet/rrset-wire.h"
#include "contrib/wire.h"

const int KNOT_TSIG_MAX_DIGEST_SIZE = 64;    // size of HMAC-SHA512 digest
const uint16_t KNOT_TSIG_FUDGE_DEFAULT = 300;  // default Fudge value

static int check_algorithm(const knot_rrset_t *tsig_rr)
{
	if (tsig_rr == NULL) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *alg_name = knot_tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EMALF;
	}

	dnssec_tsig_algorithm_t alg = dnssec_tsig_algorithm_from_dname(alg_name);
	if (alg == DNSSEC_TSIG_UNKNOWN) {
		/*!< \todo is this error OK? */
		return KNOT_TSIG_EBADSIG;
	}

	return KNOT_EOK;
}

static int check_key(const knot_rrset_t *tsig_rr,
                     const knot_tsig_key_t *tsig_key)
{
	if (tsig_rr == NULL || tsig_key == NULL) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *tsig_name = tsig_rr->owner;
	if (!tsig_name) {
		return KNOT_EMALF;
	}

	char *name = knot_dname_to_str_alloc(tsig_name);
	if (!name) {
		return KNOT_EMALF;
	}

	if (knot_dname_cmp(tsig_name, tsig_key->name) != 0) {
		/*!< \todo which error. */
		free(name);
		return KNOT_TSIG_EBADKEY;
	}

	free(name);
	return KNOT_EOK;
}

static int compute_digest(const uint8_t *wire, size_t wire_len,
                          uint8_t *digest, size_t *digest_len,
                          const knot_tsig_key_t *key)
{
	if (!wire || !digest || !digest_len || !key) {
		return KNOT_EINVAL;
	}

	if (!key->name) {
		return KNOT_EMALF;
	}

	dnssec_tsig_ctx_t *ctx = NULL;
	int result = dnssec_tsig_new(&ctx, key->algorithm, &key->secret);
	if (result != DNSSEC_EOK) {
		return KNOT_TSIG_EBADSIG;
	}

	dnssec_binary_t cover = { .data = (uint8_t *)wire, .size = wire_len };
	dnssec_tsig_add(ctx, &cover);

	*digest_len = dnssec_tsig_size(ctx);
	dnssec_tsig_write(ctx, digest);
	dnssec_tsig_free(ctx);

	return KNOT_EOK;
}

static int check_time_signed(const knot_rrset_t *tsig_rr,
                             uint64_t prev_time_signed)
{
	if (!tsig_rr) {
		return KNOT_EINVAL;
	}

	/* Get the time signed and fudge values. */
	uint64_t time_signed = knot_tsig_rdata_time_signed(tsig_rr);
	if (time_signed == 0) {
		return KNOT_TSIG_EBADTIME;
	}
	uint16_t fudge = knot_tsig_rdata_fudge(tsig_rr);
	if (fudge == 0) {
		return KNOT_TSIG_EBADTIME;
	}

	/* Get the current time. */
	time_t curr_time = time(NULL);

	/*!< \todo bleeding eyes. */
	double diff = difftime(curr_time, (time_t)time_signed);

	if (diff > fudge || diff < -fudge) {
		return KNOT_TSIG_EBADTIME;
	}

	diff = difftime((time_t)time_signed, prev_time_signed);

	if (diff < 0) {
		return KNOT_TSIG_EBADTIME;
	}

	return KNOT_EOK;
}

static int write_tsig_variables(uint8_t *wire, const knot_rrset_t *tsig_rr)
{
	if (wire == NULL || tsig_rr == NULL) {
		return KNOT_EINVAL;
	}

	/* Copy TSIG variables - starting with key name. */
	const knot_dname_t *tsig_owner = tsig_rr->owner;
	if (!tsig_owner) {
		return KNOT_EINVAL;
	}

	int offset = 0;

	offset += knot_dname_to_wire(wire + offset, tsig_owner, KNOT_DNAME_MAXLEN);

	/*!< \todo which order? */

	/* Copy class. */
	wire_write_u16(wire + offset, tsig_rr->rclass);
	offset += sizeof(uint16_t);

	/* Copy TTL - always 0. */
	wire_write_u32(wire + offset, knot_rdata_ttl(knot_rdataset_at(&tsig_rr->rrs, 0)));
	offset += sizeof(uint32_t);

	/* Copy alg name. */
	const knot_dname_t *alg_name = knot_tsig_rdata_alg_name(tsig_rr);
	if (!alg_name) {
		return KNOT_EINVAL;
	}

	/* Te algorithm name must be in canonical form, i.e. in lowercase. */
	uint8_t *alg_name_wire = wire + offset;
	offset += knot_dname_to_wire(alg_name_wire, alg_name, KNOT_DNAME_MAXLEN);
	if (knot_dname_to_lower(alg_name_wire) != KNOT_EOK) {
		return KNOT_EINVAL;
	}

	/* Following data are written in network order. */
	/* Time signed. */
	wire_write_u48(wire + offset, knot_tsig_rdata_time_signed(tsig_rr));
	offset += 6;
	/* Fudge. */
	wire_write_u16(wire + offset, knot_tsig_rdata_fudge(tsig_rr));
	offset += sizeof(uint16_t);
	/* TSIG error. */
	wire_write_u16(wire + offset, knot_tsig_rdata_error(tsig_rr));
	offset += sizeof(uint16_t);
	/* Get other data length. */
	uint16_t other_data_length = knot_tsig_rdata_other_data_length(tsig_rr);
	/* Get other data. */
	const uint8_t *other_data = knot_tsig_rdata_other_data(tsig_rr);
	if (!other_data) {
		return KNOT_EINVAL;
	}

	/*
	 * We cannot write the whole other_data, as it contains its length in
	 * machine order.
	 */
	wire_write_u16(wire + offset, other_data_length);
	offset += sizeof(uint16_t);

	/* Skip the length. */
	memcpy(wire + offset, other_data, other_data_length);

	return KNOT_EOK;
}

static int wire_write_timers(uint8_t *wire, const knot_rrset_t *tsig_rr)
{
	if (wire == NULL || tsig_rr == NULL) {
		return KNOT_EINVAL;
	}

	//write time signed
	wire_write_u48(wire, knot_tsig_rdata_time_signed(tsig_rr));
	//write fudge
	wire_write_u16(wire + 6, knot_tsig_rdata_fudge(tsig_rr));

	return KNOT_EOK;
}

static int create_sign_wire(const uint8_t *msg, size_t msg_len,
                            const uint8_t *request_mac, size_t request_mac_len,
                            uint8_t *digest, size_t *digest_len,
                            const knot_rrset_t *tmp_tsig,
                            const knot_tsig_key_t *key)
{
	if (!msg || !key || digest_len == NULL) {
		return KNOT_EINVAL;
	}

	/* Create tmp TSIG. */
	int ret = KNOT_EOK;

	/*
	 * Create tmp wire, it should contain message
	 * plus request mac plus tsig varibles.
	 */
	size_t wire_len = sizeof(uint8_t) *
			(msg_len + request_mac_len + ((request_mac_len > 0)
			 ? 2 : 0) +
			knot_tsig_rdata_tsig_variables_length(tmp_tsig));
	uint8_t *wire = malloc(wire_len);
	if (!wire) {
		return KNOT_ENOMEM;
	}

	memset(wire, 0, wire_len);

	uint8_t *pos = wire;

	/* Copy the request MAC - should work even if NULL. */
	if (request_mac_len > 0) {
		wire_write_u16(pos, request_mac_len);
		pos += 2;
		memcpy(pos, request_mac, sizeof(uint8_t) * request_mac_len);
	}
	pos += request_mac_len;
	/* Copy the original message. */
	memcpy(pos, msg, msg_len);
	pos += msg_len;
	/* Copy TSIG variables. */
	ret = write_tsig_variables(pos, tmp_tsig);
	if (ret != KNOT_EOK) {
		free(wire);
		return ret;
	}

	/* Compute digest. */
	ret = compute_digest(wire, wire_len, digest, digest_len, key);
	if (ret != KNOT_EOK) {
		*digest_len = 0;
		free(wire);
		return ret;
	}

	free(wire);

	return KNOT_EOK;
}

static int create_sign_wire_next(const uint8_t *msg, size_t msg_len,
                                 const uint8_t *prev_mac, size_t prev_mac_len,
                                 uint8_t *digest, size_t *digest_len,
                                 const knot_rrset_t *tmp_tsig,
                                 const knot_tsig_key_t *key)
{
	if (!msg || !key || digest_len == NULL) {
		return KNOT_EINVAL;
	}

	/* Create tmp TSIG. */
	int ret = KNOT_EOK;

	/*
	 * Create tmp wire, it should contain message
	 * plus request mac plus tsig varibles.
	 */
	size_t wire_len = sizeof(uint8_t) *
	                (msg_len + prev_mac_len +
			knot_tsig_rdata_tsig_timers_length() + 2);
	uint8_t *wire = malloc(wire_len);
	if (!wire) {
		return KNOT_ENOMEM;
	}

	memset(wire, 0, wire_len);

	/* Copy the request MAC - should work even if NULL. */
	wire_write_u16(wire, prev_mac_len);
	memcpy(wire + 2, prev_mac, sizeof(uint8_t) * prev_mac_len);
	/* Copy the original message. */
	memcpy(wire + prev_mac_len + 2, msg, msg_len);
	/* Copy TSIG variables. */

	ret = wire_write_timers(wire + prev_mac_len + msg_len + 2,
	                                  tmp_tsig);
	if (ret != KNOT_EOK) {
		free(wire);
		return ret;
	}

	/* Compute digest. */
	ret = compute_digest(wire, wire_len,
	                               digest, digest_len, key);
	if (ret != KNOT_EOK) {
		*digest_len = 0;
		free(wire);
		return ret;
	}

	free(wire);

	return KNOT_EOK;
}

_public_
int knot_tsig_sign(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                   const uint8_t *request_mac, size_t request_mac_len,
                   uint8_t *digest, size_t *digest_len,
                   const knot_tsig_key_t *key, uint16_t tsig_rcode,
                   uint64_t request_time_signed)
{
	if (!msg || !msg_len || !key || digest == NULL || digest_len == NULL) {
		return KNOT_EINVAL;
	}

	knot_rrset_t *tmp_tsig =
		knot_rrset_new(key->name, KNOT_RRTYPE_TSIG, KNOT_CLASS_ANY,
		               NULL);
	if (!tmp_tsig) {
		return KNOT_ENOMEM;
	}

	/* Create rdata for TSIG RR. */
	uint16_t rdata_rcode = 0;
	if (tsig_rcode == KNOT_TSIG_ERR_BADTIME)
		rdata_rcode = tsig_rcode;

	const uint8_t *alg_name = dnssec_tsig_algorithm_to_dname(key->algorithm);
	size_t alg_size = dnssec_tsig_algorithm_size(key->algorithm);
	knot_tsig_create_rdata(tmp_tsig, alg_name, alg_size, rdata_rcode);

	/* Distinguish BADTIME response. */
	if (tsig_rcode == KNOT_TSIG_ERR_BADTIME) {
		/* Set client's time signed into the time signed field. */
		knot_tsig_rdata_set_time_signed(tmp_tsig, request_time_signed);

		/* Store current time into Other data. */
		uint8_t time_signed[6];
		time_t curr_time = time(NULL);

		uint64_t time64 = curr_time;
		wire_write_u48(time_signed, time64);

		knot_tsig_rdata_set_other_data(tmp_tsig, 6, time_signed);
	} else {
		knot_tsig_rdata_set_time_signed(tmp_tsig, time(NULL));

		/* Set other len. */
		knot_tsig_rdata_set_other_data(tmp_tsig, 0, 0);
	}

	knot_tsig_rdata_set_fudge(tmp_tsig, KNOT_TSIG_FUDGE_DEFAULT);

	/* Set original ID */
	knot_tsig_rdata_set_orig_id(tmp_tsig, knot_wire_get_id(msg));

	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;

	int ret = KNOT_ERROR;
	ret = create_sign_wire(msg, *msg_len, /*msg_max_len,*/
	                                     request_mac, request_mac_len,
	                                     digest_tmp, &digest_tmp_len,
					     tmp_tsig, key);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&tmp_tsig, NULL);
		return ret;
	}

	/* Set the digest. */
	knot_tsig_rdata_set_mac(tmp_tsig, digest_tmp_len, digest_tmp);

	/* Write RRSet to wire */

	ret = knot_rrset_to_wire(tmp_tsig, msg + *msg_len,
	                         msg_max_len - *msg_len, NULL);
	if (ret < 0) {
		*digest_len = 0;
		knot_rrset_free(&tmp_tsig, NULL);
		return ret;
	}

	size_t tsig_wire_len = ret;

	knot_rrset_free(&tmp_tsig, NULL);

	*msg_len += tsig_wire_len;

	uint16_t arcount = knot_wire_get_arcount(msg);
	knot_wire_set_arcount(msg, ++arcount);

	// everything went ok, save the digest to the output parameter
	memcpy(digest, digest_tmp, digest_tmp_len);
	*digest_len = digest_tmp_len;

	return KNOT_EOK;
}

_public_
int knot_tsig_sign_next(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                        const uint8_t *prev_digest, size_t prev_digest_len,
                        uint8_t *digest, size_t *digest_len,
                        const knot_tsig_key_t *key, uint8_t *to_sign,
                        size_t to_sign_len)
{
	if (!msg || !msg_len || !key || !digest || !digest_len) {
		return KNOT_EINVAL;
	}

	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;
	knot_rrset_t *tmp_tsig = knot_rrset_new(key->name, KNOT_RRTYPE_TSIG,
	                                        KNOT_CLASS_ANY, NULL);
	if (!tmp_tsig) {
		return KNOT_ENOMEM;
	}

	/* Create rdata for TSIG RR. */
	const uint8_t *alg_name = dnssec_tsig_algorithm_to_dname(key->algorithm);
	size_t alg_size = dnssec_tsig_algorithm_size(key->algorithm);
	knot_tsig_create_rdata(tmp_tsig, alg_name, alg_size, 0);
	knot_tsig_rdata_set_time_signed(tmp_tsig, time(NULL));
	knot_tsig_rdata_set_fudge(tmp_tsig, KNOT_TSIG_FUDGE_DEFAULT);

	/* Create wire to be signed. */
	size_t wire_len = prev_digest_len + to_sign_len
	                  + KNOT_TSIG_TIMERS_LENGTH + 2;
	uint8_t *wire = malloc(wire_len);
	if (!wire) {
		knot_rrset_free(&tmp_tsig, NULL);
		return KNOT_ENOMEM;
	}
	memset(wire, 0, wire_len);

	/* Write previous digest length. */
	wire_write_u16(wire, prev_digest_len);
	/* Write previous digest. */
	memcpy(wire + 2, prev_digest, sizeof(uint8_t) * prev_digest_len);
	/* Write original message. */
	memcpy(wire + prev_digest_len + 2, to_sign, to_sign_len);
	/* Write timers. */
	wire_write_timers(wire + prev_digest_len + to_sign_len + 2,
	                            tmp_tsig);

	int ret = KNOT_ERROR;
	ret = compute_digest(wire, wire_len,
	                               digest_tmp, &digest_tmp_len, key);

	/* No matter how the function did, this data is no longer needed. */
	free(wire);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&tmp_tsig, NULL);
		*digest_len = 0;
		return ret;
	}

	if (digest_tmp_len > *digest_len) {
		knot_rrset_free(&tmp_tsig, NULL);
		*digest_len = 0;
		return KNOT_ESPACE;
	}

	/* Set the MAC. */
	knot_tsig_rdata_set_mac(tmp_tsig, digest_tmp_len, digest_tmp);

	/* Set original id. */
	knot_tsig_rdata_set_orig_id(tmp_tsig, knot_wire_get_id(msg));

	/* Set other data. */
	knot_tsig_rdata_set_other_data(tmp_tsig, 0, NULL);

	ret = knot_rrset_to_wire(tmp_tsig, msg + *msg_len,
	                         msg_max_len - *msg_len, NULL);
	if (ret < 0) {
		knot_rrset_free(&tmp_tsig, NULL);
		*digest_len = 0;
		return ret;
	}

	size_t tsig_wire_size = ret;

	knot_rrset_free(&tmp_tsig, NULL);

	*msg_len += tsig_wire_size;
	uint16_t arcount = knot_wire_get_arcount(msg);
	knot_wire_set_arcount(msg, ++arcount);

	memcpy(digest, digest_tmp, digest_tmp_len);
	*digest_len = digest_tmp_len;

	return KNOT_EOK;
}

static int check_digest(const knot_rrset_t *tsig_rr,
                        const uint8_t *wire, size_t size,
                        const uint8_t *request_mac, size_t request_mac_len,
                        const knot_tsig_key_t *tsig_key,
                        uint64_t prev_time_signed, int use_times)
{
	if (!wire || !tsig_key) {
		return KNOT_EINVAL;
	}

	/* No TSIG record means verification failure. */
	if (tsig_rr == NULL) {
		return KNOT_TSIG_EBADKEY;
	}

	/* Check that libknot knows the algorithm. */
	int ret = check_algorithm(tsig_rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check that key is valid, ie. the same as given in args. */
	ret = check_key(tsig_rr, tsig_key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	uint8_t *wire_to_sign = malloc(sizeof(uint8_t) * size);
	if (!wire_to_sign) {
		return KNOT_ENOMEM;
	}

	memset(wire_to_sign, 0, sizeof(uint8_t) * size);
	memcpy(wire_to_sign, wire, size);

	uint8_t digest_tmp[KNOT_TSIG_MAX_DIGEST_SIZE];
	size_t digest_tmp_len = 0;
	assert(tsig_rr->rrs.rr_count > 0);

	if (use_times) {
		/* Wire is not a single packet, TSIG RRs must be stripped already. */
		ret = create_sign_wire_next(wire_to_sign, size,
		                                 request_mac, request_mac_len,
		                                 digest_tmp, &digest_tmp_len,
		                                 tsig_rr, tsig_key);
	} else {
		ret = create_sign_wire(wire_to_sign, size,
		                            request_mac, request_mac_len,
		                            digest_tmp, &digest_tmp_len,
		                            tsig_rr, tsig_key);
	}

	assert(tsig_rr->rrs.rr_count > 0);
	free(wire_to_sign);

	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Compare MAC from TSIG RR RDATA with just computed digest. */

	/*!< \todo move to function. */
	const knot_dname_t *alg_name = knot_tsig_rdata_alg_name(tsig_rr);
	dnssec_tsig_algorithm_t alg = dnssec_tsig_algorithm_from_dname(alg_name);

	/*! \todo [TSIG] TRUNCATION */
	uint16_t mac_length = knot_tsig_rdata_mac_length(tsig_rr);
	const uint8_t *tsig_mac = knot_tsig_rdata_mac(tsig_rr);

	if (mac_length != dnssec_tsig_algorithm_size(alg)) {
		return KNOT_TSIG_EBADSIG;
	}

	if (memcmp(tsig_mac, digest_tmp, mac_length) != 0) {
		return KNOT_TSIG_EBADSIG;
	}

	/* Check TSIG validity period, must be after the signature check! */
	ret = check_time_signed(tsig_rr, prev_time_signed);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

_public_
int knot_tsig_server_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const knot_tsig_key_t *tsig_key)
{
	return check_digest(tsig_rr, wire, size, NULL, 0, tsig_key,
	                              0, 0);
}

_public_
int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len,
                           const knot_tsig_key_t *tsig_key,
                           uint64_t prev_time_signed)
{
	return check_digest(tsig_rr, wire, size, request_mac,
	                              request_mac_len, tsig_key,
	                              prev_time_signed, 0);
}

_public_
int knot_tsig_client_check_next(const knot_rrset_t *tsig_rr,
                                const uint8_t *wire, size_t size,
                                const uint8_t *prev_digest,
                                size_t prev_digest_len,
                                const knot_tsig_key_t *tsig_key,
                                uint64_t prev_time_signed)
{
	return check_digest(tsig_rr, wire, size, prev_digest,
	                              prev_digest_len, tsig_key,
	                              prev_time_signed, 1);
}

_public_
int knot_tsig_add(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                  uint16_t tsig_rcode, const knot_rrset_t *tsig_rr)
{
	/*! \todo Revise!! */

	if (!msg || !msg_len || !tsig_rr) {
		return KNOT_EINVAL;
	}

	/*! \todo What key to use, when we do not sign? Does this even work? */
	knot_rrset_t *tmp_tsig =
		knot_rrset_new(tsig_rr->owner, KNOT_RRTYPE_TSIG,
		               KNOT_CLASS_ANY, NULL);
	if (!tmp_tsig) {
		return KNOT_ENOMEM;
	}

	assert(tsig_rcode != KNOT_TSIG_ERR_BADTIME);
	knot_tsig_create_rdata(tmp_tsig, knot_tsig_rdata_alg_name(tsig_rr), 0, tsig_rcode);
	knot_tsig_rdata_set_time_signed(tmp_tsig, knot_tsig_rdata_time_signed(tsig_rr));

	/* Comparing to BIND it was found out that the Fudge should always be
	 * set to the server's value.
	 */
	knot_tsig_rdata_set_fudge(tmp_tsig, KNOT_TSIG_FUDGE_DEFAULT);

	/* Set original ID */
	knot_tsig_rdata_set_orig_id(tmp_tsig, knot_wire_get_id(msg));

	/* Set other len. */
	knot_tsig_rdata_set_other_data(tmp_tsig, 0, 0);

	/* Append TSIG RR. */
	int ret = knot_tsig_append(msg, msg_len, msg_max_len, tmp_tsig);

	/* key_name already referenced in RRSet, no need to free separately. */
	knot_rrset_free(&tmp_tsig, NULL);

	return ret;
}

_public_
int knot_tsig_append(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                     const knot_rrset_t *tsig_rr)
{
	/* Write RRSet to wire */
	int ret = knot_rrset_to_wire(tsig_rr, msg + *msg_len,
	                             msg_max_len - *msg_len, NULL);
	if (ret < 0) {
		return ret;
	}

	*msg_len += ret;

	knot_wire_set_arcount(msg, knot_wire_get_arcount(msg) + 1);

	return KNOT_EOK;
}
