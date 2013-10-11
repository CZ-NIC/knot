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
#include "libknot/rrset.h"
#include "libknot/util/utils.h"

static inline
const knot_dname_t *knot_rdata_cname_name(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}

	return rrset->rdata;
}

static inline
const knot_dname_t *knot_rdata_dname_target(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}

	return rrset->rdata;
}

static inline
const knot_dname_t *knot_rdata_soa_primary_ns(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}

	return rrset->rdata;
}

static inline
const knot_dname_t *knot_rdata_soa_mailbox(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}

	return rrset->rdata + knot_dname_size(rrset->rdata);
}

static inline
size_t knot_rrset_rdata_soa_names_len(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_dname_size(knot_rdata_soa_primary_ns(rrset))
	       + knot_dname_size(knot_rdata_soa_mailbox(rrset));
}

static inline
uint32_t knot_rdata_soa_serial(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata
	                          + knot_rrset_rdata_soa_names_len(rrset));
}

static inline
void knot_rdata_soa_serial_set(knot_rrset_t *rrset, uint32_t serial)
{
	if (rrset == NULL) {
		return;
	}

	// the number is in network byte order, transform it
	knot_wire_write_u32(rrset->rdata
	                    + knot_rrset_rdata_soa_names_len(rrset), serial);
}

static inline
uint32_t knot_rdata_soa_refresh(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata
	                          + knot_rrset_rdata_soa_names_len(rrset) + 4);
}

static inline
uint32_t knot_rdata_soa_retry(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata
	                          + knot_rrset_rdata_soa_names_len(rrset) + 8);
}

static inline
uint32_t knot_rdata_soa_expire(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata
	                          + knot_rrset_rdata_soa_names_len(rrset) + 12);
}

static inline
uint32_t knot_rdata_soa_minimum(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata
	                          + knot_rrset_rdata_soa_names_len(rrset) + 16);
}

static inline
uint16_t knot_rdata_rrsig_type_covered(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return 0;
	}

	return knot_wire_read_u16(knot_rrset_get_rdata(rrset, pos));
}

static inline
uint8_t knot_rdata_rrsig_algorithm(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(knot_rrset_get_rdata(rrset, pos) + 2);
}

static inline
uint8_t knot_rdata_rrsig_labels(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(knot_rrset_get_rdata(rrset, pos) + 3);
}

static inline
uint32_t knot_rdata_rrsig_original_ttl(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u32(knot_rrset_get_rdata(rrset, pos) + 4);
}

static inline
uint32_t knot_rdata_rrsig_sig_expiration(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u32(knot_rrset_get_rdata(rrset, pos) + 8);
}

static inline
uint32_t knot_rdata_rrsig_sig_inception(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u32(knot_rrset_get_rdata(rrset, pos) + 12);
}

static inline
uint16_t knot_rdata_rrsig_key_tag(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u16(knot_rrset_get_rdata(rrset, pos) + 16);
}

static inline
const knot_dname_t *knot_rdata_rrsig_signer_name(const knot_rrset_t *rrset,
                                                 size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return NULL;
	}

	return knot_rrset_get_rdata(rrset, pos) + 18;
}

static inline
void knot_rdata_rrsig_signature(const knot_rrset_t *rrset, size_t pos,
                                uint8_t **signature, size_t *signature_size)
{
	if (!signature || !signature_size) {
		return;
	}

	if (rrset == NULL || pos >= rrset->rdata_count) {
		*signature = NULL;
		*signature_size = 0;
		return;
	}

	uint8_t *rdata = knot_rrset_get_rdata(rrset, pos);
	uint8_t *signer = rdata + 18;
	size_t total_size = rrset_rdata_item_size(rrset, pos);
	size_t header_size = 18 + knot_dname_size(signer);

	*signature = rdata + header_size;
	*signature_size = total_size - header_size;
}

static inline
uint16_t knot_rdata_dnskey_flags(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u16(knot_rrset_get_rdata(rrset, pos));
}

static inline
uint8_t knot_rdata_dnskey_proto(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(knot_rrset_get_rdata(rrset, pos) + 2);
}

static inline
uint8_t knot_rdata_dnskey_alg(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(knot_rrset_get_rdata(rrset, pos) + 3);
}

static inline
void knot_rdata_dnskey_key(const knot_rrset_t *rrset, size_t pos, uint8_t **key,
                           uint16_t *key_size)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return;
	}

	*key = knot_rrset_get_rdata(rrset, pos) + 4;
	*key_size = rrset_rdata_item_size(rrset, pos) - 4;
}

static inline
const knot_dname_t *knot_rdata_nsec_next(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return NULL;
	}

	return rrset_rdata_pointer(rrset, pos);
}

static inline
void knot_rdata_nsec_bitmap(const knot_rrset_t *rrset, size_t rr_pos,
                            uint8_t **bitmap, uint16_t *size)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return;
	}

	uint8_t *rdata = knot_rrset_get_rdata(rrset, rr_pos);
	int next_size = knot_dname_size(rdata);

	*bitmap = rdata + next_size;
	*size = rrset_rdata_item_size(rrset, rr_pos) - next_size;
}

static inline
uint8_t knot_rdata_nsec3_algorithm(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos));
}

static inline
uint8_t knot_rdata_nsec3_flags(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos) + 1);
}

static inline
uint16_t knot_rdata_nsec3_iterations(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u16(rrset_rdata_pointer(rrset, pos) + 2);
}

static inline
uint8_t knot_rdata_nsec3_salt_length(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos) + 4);
}

static inline
const uint8_t *knot_rdata_nsec3_salt(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return NULL;
	}

	return rrset_rdata_pointer(rrset, pos) + 5;
}

static inline
void knot_rdata_nsec3_next_hashed(const knot_rrset_t *rrset, size_t pos,
                                  uint8_t **name, uint8_t *name_size)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return;
	}

	uint8_t salt_size = knot_rdata_nsec3_salt_length(rrset, pos);
	*name_size = *(knot_rrset_get_rdata(rrset, pos) + 4 + salt_size + 1);
	*name = knot_rrset_get_rdata(rrset, pos) + 4 + salt_size + 2;
}

static inline
void knot_rdata_nsec3_bitmap(const knot_rrset_t *rrset, size_t pos,
                             uint8_t **bitmap, uint16_t *size)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return;
	}

	/* Bitmap is last, skip all the items. */
	size_t offset = 6; //hash alg., flags, iterations, salt len., hash len.
	offset += knot_rdata_nsec3_salt_length(rrset, pos); //salt

	uint8_t *next_hashed = NULL;
	uint8_t next_hashed_size = 0;
	knot_rdata_nsec3_next_hashed(rrset, pos, &next_hashed,
	                             &next_hashed_size);
	offset += next_hashed_size; //hash

	*bitmap = knot_rrset_get_rdata(rrset, pos) + offset;
	*size = rrset_rdata_item_size(rrset, pos) - offset;
}

static inline
uint8_t knot_rdata_nsec3param_algorithm(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos));
}

static inline
uint8_t knot_rdata_nsec3param_flags(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos) + 1);
}

static inline
uint16_t knot_rdata_nsec3param_iterations(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return 0;
	}

	return knot_wire_read_u16(rrset_rdata_pointer(rrset, pos) + 2);
}

static inline
uint8_t knot_rdata_nsec3param_salt_length(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos) + 4);
}

static inline
const uint8_t *knot_rdata_nsec3param_salt(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return NULL;
	}

	return rrset_rdata_pointer(rrset, pos) + 5;
}

static inline
const knot_dname_t *knot_rdata_ns_name(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return NULL;
	}

	return rrset_rdata_pointer(rrset, pos);
}

static inline
const knot_dname_t *knot_rdata_mx_name(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return NULL;
	}

	return rrset_rdata_pointer(rrset, pos) + 2;
}

static inline
const knot_dname_t *knot_rdata_srv_name(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return NULL;
	}

	return rrset_rdata_pointer(rrset, pos) + 6;
}

static inline
const knot_dname_t *knot_rdata_name(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_count <= pos) {
		return NULL;
	}

	switch (rrset->type) {
		case KNOT_RRTYPE_NS:
			return knot_rdata_ns_name(rrset, pos);
		case KNOT_RRTYPE_MX:
			return knot_rdata_mx_name(rrset, pos);
		case KNOT_RRTYPE_SRV:
			return knot_rdata_srv_name(rrset, pos);
		case KNOT_RRTYPE_CNAME:
			return knot_rdata_cname_name(rrset);
	}

	return NULL;
}

#endif /* _KNOT_RDATA_H_ */
/*! @} */
