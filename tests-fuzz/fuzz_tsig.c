/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>
#include <string.h>

#include "libknot/consts.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/packet/pkt.h"
#include "libknot/rrset.h"
#include "libknot/tsig-op.h"

#define MAX_INPUT_SIZE 4096
#define MAX_PACKET_SIZE 1024
#define MAX_TEXT_SIZE 255
#define MAX_DIGEST_SIZE 64

static const uint8_t name[] = "\x07" "example";
static const uint8_t key_name[] = "\x03" "key" "\x07" "example";
static const uint8_t wrong_key_name[] = "\x05" "wrong" "\x07" "example";
static const uint8_t secret[] = "fuzz-tsig-secret";
static const uint8_t previous_mac[] = "previous-tsig-mac";
static const dnssec_tsig_algorithm_t algorithms[] = {
	DNSSEC_TSIG_HMAC_SHA256, DNSSEC_TSIG_HMAC_SHA512,
	DNSSEC_TSIG_HMAC_SHA1, DNSSEC_TSIG_HMAC_SHA224,
	DNSSEC_TSIG_HMAC_SHA384, DNSSEC_TSIG_HMAC_MD5
};

static void parse_mutated_packet(const knot_pkt_t *packet,
			 const uint8_t *data, size_t size)
{
	if (size < 4 || packet->size > MAX_PACKET_SIZE) {
		return;
	}

	uint8_t wire[MAX_PACKET_SIZE];
	memcpy(wire, packet->wire, packet->size);
	for (size_t pos = 1; pos + 2 < size; pos += 3) {
		size_t offset = (((size_t)data[pos] << 8) | data[pos + 1]) % packet->size;
		wire[offset] ^= data[pos + 2];
	}

	knot_pkt_t *parsed = knot_pkt_new(wire, packet->size, NULL);
	if (parsed != NULL) {
		knot_pkt_parse(parsed, 0);
		knot_pkt_free(parsed);
	}
}

static void add_tsig_response(const knot_pkt_t *packet)
{
	uint8_t response[MAX_PACKET_SIZE];
	if (packet->size > sizeof(response)) {
		return;
	}

	memcpy(response, packet->wire, packet->size);
	size_t response_size = packet->size;
	if (knot_tsig_add(response, &response_size, sizeof(response), KNOT_RCODE_NOERROR,
	                  packet->tsig_rr) != KNOT_EOK) {
		return;
	}

	knot_pkt_t *parsed = knot_pkt_new(response, response_size, NULL);
	if (parsed != NULL) {
		knot_pkt_parse(parsed, 0);
		knot_pkt_free(parsed);
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	dnssec_crypto_init();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > MAX_INPUT_SIZE) {
		return 0;
	}
	uint8_t selector = size > 0 ? data[0] : 0;
	size_t payload_size = size > 1 ? size - 1 : 0;
	if (payload_size > MAX_TEXT_SIZE) {
		payload_size = MAX_TEXT_SIZE;
	}
	knot_tsig_key_t key = {
		.algorithm = algorithms[(selector >> 1) % (sizeof(algorithms) / sizeof(algorithms[0]))],
		.name = (knot_dname_t *)key_name,
		.secret = { .data = (uint8_t *)secret, .size = sizeof(secret) - 1 }
	};
	knot_pkt_t *message = knot_pkt_new(NULL, MAX_PACKET_SIZE, NULL);
	if (message == NULL) {
		return 0;
	}

	uint8_t text[MAX_TEXT_SIZE + 1];
	text[0] = (uint8_t)payload_size;
	if (payload_size > 0) {
		memcpy(text + 1, data + 1, payload_size);
	}
	knot_rrset_t rrset;
	knot_rrset_init(&rrset, (knot_dname_t *)name, KNOT_RRTYPE_TXT, KNOT_CLASS_IN, 60);
	if (knot_pkt_put_question(message, name, KNOT_CLASS_IN, KNOT_RRTYPE_TXT) != KNOT_EOK ||
	    knot_rrset_add_rdata(&rrset, text, payload_size + 1, NULL) != KNOT_EOK) {
		goto cleanup;
	}
	knot_pkt_begin(message, KNOT_ANSWER);
	if (knot_pkt_put(message, 0, &rrset, 0) != KNOT_EOK) {
		goto cleanup;
	}

	size_t unsigned_size = message->size;
	const uint8_t *request_mac = NULL;
	size_t request_mac_len = 0;
	if ((selector & 4) != 0 && (selector & 1) == 0 && size > 1) {
		request_mac = data + 1;
		request_mac_len = payload_size;
	}
	uint8_t digest[MAX_DIGEST_SIZE];
	size_t digest_len = sizeof(digest);
	int ret;
	if ((selector & 1) != 0) {
		ret = knot_tsig_sign_next(message->wire, &message->size, message->max_size,
		                          previous_mac, sizeof(previous_mac) - 1,
		                          digest, &digest_len, &key,
		                          message->wire, unsigned_size);
	} else {
		uint16_t rcode = (selector & 2) != 0 ? KNOT_RCODE_BADTIME : KNOT_RCODE_NOERROR;
		ret = knot_tsig_sign(message->wire, &message->size, message->max_size,
		                     request_mac, request_mac_len, digest, &digest_len,
		                     &key, rcode, rcode == KNOT_RCODE_BADTIME ? 1 : 0);
	}
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	if ((selector & 128) != 0) {
		parse_mutated_packet(message, data, size);
	}
	knot_pkt_t *parsed = knot_pkt_new(message->wire, message->size, NULL);
	if (parsed != NULL) {
		if (knot_pkt_parse(parsed, 0) == KNOT_EOK && parsed->tsig_rr != NULL) {
			knot_tsig_key_t verification_key = key;
			if ((selector & 8) != 0) {
				verification_key.name = (knot_dname_t *)wrong_key_name;
			}

			knot_rrset_t *tsig_copy = NULL;
			const knot_rrset_t *tsig_rr = parsed->tsig_rr;
			if ((selector & 64) != 0) {
				tsig_copy = knot_rrset_copy(tsig_rr, NULL);
				if (tsig_copy != NULL) {
					uint8_t *algorithm = (uint8_t *)knot_tsig_rdata_alg_name(tsig_copy);
					if (algorithm != NULL && algorithm[0] > 0 && algorithm[0] < 64) {
						algorithm[1] ^= 1;
					}
					tsig_rr = tsig_copy;
				}
			}

			if ((selector & 1) != 0) {
				knot_tsig_client_check_next(tsig_rr, parsed->wire, parsed->size,
				                            previous_mac, sizeof(previous_mac) - 1,
				                            &verification_key, 0);
			} else if ((selector & 4) != 0) {
				knot_tsig_client_check(tsig_rr, parsed->wire, parsed->size,
				                       request_mac, request_mac_len, &verification_key, 0);
			} else {
				knot_tsig_server_check(tsig_rr, parsed->wire, parsed->size,
				                       &verification_key);
			}

			if ((selector & 32) != 0) {
				add_tsig_response(parsed);
			}
			knot_rrset_free(tsig_copy, NULL);
		}
		knot_pkt_free(parsed);
	}

cleanup:
	knot_rdataset_clear(&rrset.rrs, NULL);
	knot_pkt_free(message);
	return 0;
}
