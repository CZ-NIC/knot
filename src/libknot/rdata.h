/*!
 * \file rdata.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief API for manipulating RDATA contents.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_RDATA_H_
#define _KNOT_RDATA_H_

#include "common/descriptor.h"
#include "libknot/dname.h"
#include "libknot/rr.h"
#include "libknot/util/utils.h"

#define KNOT_RDATA_DNSKEY_FLAG_KSK 1

#define RRS_CHECK(rrs, pos, code) \
	if (rrs == NULL || rrs->data == NULL || rrs->rr_count == 0 || \
	    pos >= rrs->rr_count) { \
		code; \
	}

static inline uint8_t *data_offset(const knot_rrs_t *rrs, size_t pos,
                                   size_t offset) {
	knot_rr_t *rr = knot_rrs_rr(rrs, pos);
	return knot_rr_rdata(rr) + offset;
}

static inline
const knot_dname_t *knot_rrs_cname_name(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return NULL);
	return data_offset(rrs, 0, 0);
}

static inline
const knot_dname_t *knot_rrs_dname_target(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return NULL);
	return data_offset(rrs, 0, 0);
}

static inline
const knot_dname_t *knot_rrs_soa_primary_ns(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return NULL);
	return data_offset(rrs, 0, 0);
}

static inline
const knot_dname_t *knot_rrs_soa_mailbox(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return NULL);
	return data_offset(rrs, 0, knot_dname_size(knot_rrs_soa_primary_ns(rrs)));
}

static inline
size_t knot_rrs_soa_names_len(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return 0);
	return knot_dname_size(knot_rrs_soa_primary_ns(rrs))
	       + knot_dname_size(knot_rrs_soa_mailbox(rrs));
}

static inline
uint32_t knot_rrs_soa_serial(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return 0);
	return knot_wire_read_u32(data_offset(rrs, 0,
	                                      knot_rrs_soa_names_len(rrs)));
}

static inline
void knot_rrs_soa_serial_set(knot_rrs_t *rrs, uint32_t serial)
{
	RRS_CHECK(rrs, 0, return);
	// the number is in network byte order, transform it
	knot_wire_write_u32(data_offset(rrs, 0, knot_rrs_soa_names_len(rrs)),
	                    serial);
}

static inline
uint32_t knot_rrs_soa_refresh(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return 0);
	return knot_wire_read_u32(data_offset(rrs, 0,
	                                      knot_rrs_soa_names_len(rrs) + 4));
}

static inline
uint32_t knot_rrs_soa_retry(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return 0);
	return knot_wire_read_u32(data_offset(rrs, 0,
	                                      knot_rrs_soa_names_len(rrs) + 8));
}

static inline
uint32_t knot_rrs_soa_expire(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return 0);
	return knot_wire_read_u32(data_offset(rrs, 0,
	                                      knot_rrs_soa_names_len(rrs) + 12));
}

static inline
uint32_t knot_rrs_soa_minimum(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return 0);
	return knot_wire_read_u32(data_offset(rrs, 0,
	                                      knot_rrs_soa_names_len(rrs) + 16));
}

static inline
uint16_t knot_rrs_rrsig_type_covered(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return knot_wire_read_u16(data_offset(rrs, pos, 0));
}

static inline
uint8_t knot_rrs_rrsig_algorithm(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return *data_offset(rrs, pos, 2);
}

static inline
uint8_t knot_rrs_rrsig_labels(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return *data_offset(rrs, pos, 3);
}

static inline
uint32_t knot_rrs_rrsig_original_ttl(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return knot_wire_read_u32(data_offset(rrs, pos, 4));
}

static inline
uint32_t knot_rrs_rrsig_sig_expiration(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return knot_wire_read_u32(data_offset(rrs, pos, 8));
}

static inline
uint32_t knot_rrs_rrsig_sig_inception(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return knot_wire_read_u32(data_offset(rrs, pos, 12));
}

static inline
uint16_t knot_rrs_rrsig_key_tag(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return knot_wire_read_u16(data_offset(rrs, pos, 16));
}

static inline
const knot_dname_t *knot_rrs_rrsig_signer_name(const knot_rrs_t *rrs,
                                                 size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return data_offset(rrs, pos, 18);
}

static inline
void knot_rrs_rrsig_signature(const knot_rrs_t *rrs, size_t pos,
                                uint8_t **signature, size_t *signature_size)
{
	if (!signature || !signature_size) {
		return;
	}

	if (rrs == NULL || pos >= rrs->rr_count) {
		*signature = NULL;
		*signature_size = 0;
		return;
	}

	uint8_t *rdata = data_offset(rrs, pos, 0);
	uint8_t *signer = rdata + 18;
	const knot_rr_t *rr = knot_rrs_rr(rrs, pos);
	size_t total_size = knot_rr_rdata_size(rr);
	size_t header_size = 18 + knot_dname_size(signer);

	*signature = rdata + header_size;
	*signature_size = total_size - header_size;
}

static inline
uint16_t knot_rrs_dnskey_flags(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return knot_wire_read_u16(data_offset(rrs, pos, 0));
}

static inline
uint8_t knot_rrs_dnskey_proto(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);

	return *data_offset(rrs, pos, 2);
}

static inline
uint8_t knot_rrs_dnskey_alg(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return *data_offset(rrs, pos, 3);
}

static inline
void knot_rrs_dnskey_key(const knot_rrs_t *rrs, size_t pos, uint8_t **key,
                           uint16_t *key_size)
{
	RRS_CHECK(rrs, pos, return);
	*key = data_offset(rrs, pos, 4);
	const knot_rr_t *rr = knot_rrs_rr(rrs, pos);
	*key_size = knot_rr_rdata_size(rr) - 4;
}

static inline
const knot_dname_t *knot_rrs_nsec_next(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return NULL);
	return data_offset(rrs, 0, 0);
}

static inline
void knot_rrs_nsec_bitmap(const knot_rrs_t *rrs,
                            uint8_t **bitmap, uint16_t *size)
{
	RRS_CHECK(rrs, 0, return);
	knot_rr_t *rr = knot_rrs_rr(rrs, 0);
	int next_size = knot_dname_size(knot_rrs_nsec_next(rrs));

	*bitmap = knot_rr_rdata(rr) + next_size;
	*size = knot_rr_rdata_size(rr) - next_size;
}

static inline
uint8_t knot_rrs_nsec3_algorithm(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return *data_offset(rrs, pos, 0);
}

static inline
uint8_t knot_rrs_nsec3_flags(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return *data_offset(rrs, pos, 1);
}

static inline
uint16_t knot_rrs_nsec3_iterations(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return knot_wire_read_u16(data_offset(rrs, pos, 2));
}

static inline
uint8_t knot_rrs_nsec3_salt_length(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);

	return *(data_offset(rrs, pos, 0) + 4);
}

static inline
const uint8_t *knot_rrs_nsec3_salt(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return NULL);
	return data_offset(rrs, pos, 5);
}

static inline
void knot_rrs_nsec3_next_hashed(const knot_rrs_t *rrs, size_t pos,
                                  uint8_t **name, uint8_t *name_size)
{
	RRS_CHECK(rrs, pos, return);
	uint8_t salt_size = knot_rrs_nsec3_salt_length(rrs, pos);
	*name_size = *data_offset(rrs, pos, 4 + salt_size + 1);
	*name = data_offset(rrs, pos, 4 + salt_size + 2);
}

static inline
void knot_rrs_nsec3_bitmap(const knot_rrs_t *rrs, size_t pos,
                             uint8_t **bitmap, uint16_t *size)
{
	RRS_CHECK(rrs, pos, return);

	/* Bitmap is last, skip all the items. */
	size_t offset = 6; //hash alg., flags, iterations, salt len., hash len.
	offset += knot_rrs_nsec3_salt_length(rrs, pos); //salt

	uint8_t *next_hashed = NULL;
	uint8_t next_hashed_size = 0;
	knot_rrs_nsec3_next_hashed(rrs, pos, &next_hashed, &next_hashed_size);
	offset += next_hashed_size; //hash

	*bitmap = data_offset(rrs, pos, offset);
	const knot_rr_t *rr = knot_rrs_rr(rrs, pos);
	*size = knot_rr_rdata_size(rr) - offset;
}

static inline
uint8_t knot_rrs_nsec3param_algorithm(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return *data_offset(rrs, pos, 0);
}

static inline
uint8_t knot_rrs_nsec3param_flags(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return *data_offset(rrs, pos, 1);
}

static inline
uint16_t knot_rrs_nsec3param_iterations(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return knot_wire_read_u16(data_offset(rrs, pos, 2));
}

static inline
uint8_t knot_rrs_nsec3param_salt_length(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return *data_offset(rrs, pos, 4);
}

static inline
const uint8_t *knot_rrs_nsec3param_salt(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return data_offset(rrs, pos, 5);
}

static inline
const knot_dname_t *knot_rrs_ns_name(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return data_offset(rrs, pos, 0);
}

static inline
const knot_dname_t *knot_rrs_mx_name(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return data_offset(rrs, pos, 2);
}

static inline
const knot_dname_t *knot_rrs_srv_name(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return data_offset(rrs, pos, 6);
}

static inline
const knot_dname_t *knot_rrs_name(const knot_rrs_t *rrs, size_t pos,
                                  uint16_t type)
{
	switch (type) {
		case KNOT_RRTYPE_NS:
			return knot_rrs_ns_name(rrs, pos);
		case KNOT_RRTYPE_MX:
			return knot_rrs_mx_name(rrs, pos);
		case KNOT_RRTYPE_SRV:
			return knot_rrs_srv_name(rrs, pos);
		case KNOT_RRTYPE_CNAME:
			return knot_rrs_cname_name(rrs);
	}

	return NULL;
}

#endif /* _KNOT_RDATA_H_ */
/*! @} */
