/*!
 * \file rdata.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structures representing RDATA and its items and API for manipulating
 *        both.
 *
 * \addtogroup libknot
 * @{
 */
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

#ifndef _KNOT_RDATA_H_
#define _KNOT_RDATA_H_

#include <stdint.h>
#include <string.h>

#include "dname.h"
#include "util/descriptor.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief RDATA item structure.
 *
 * Each RDATA may be logically divided into items, each of possible different
 * type. This structure distinguishes between general data (\a raw_data)
 * represented as an array of octets, and domain name (\a dname) as domain names
 * require special treatment within some RDATA (e.g. compressing in packets).
 */
union knot_rdata_item {
	knot_dname_t *dname; /*!< RDATA item represented as a domain name. */

	/*!
	 * \brief RDATA item represented as raw array of octets.
	 *
	 * The first two bytes hold the length of the item in bytes. The length
	 * is stored in little endian.
	 *
	 * In some cases the stored length is also used in the wire format of
	 * RDATA (e.g. character-data as defined in RFC1035). In such case,
	 * the length should be less than 256, so that it fits into one byte
	 * in the wireformat.
	 *
	 * \todo Store the length in system byte order.
	 */
	uint16_t *raw_data;
};

typedef union knot_rdata_item knot_rdata_item_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief RDATA structure.
 *
 * Each RDATA may be logically divided into items, each of possible different
 * type (see knot_rdata_item). This structure stores an array of such items.
 * It is not dynamic, so any RDATA structure may hold either 0 or one specified
 * number of items which cannot be changed later. However, the number of items
 * may be different for each RDATA structure. The number of items should be
 * given by descriptors for each RR type. Some types may have variable number
 * of items. In such cases, the last item in the array will be set tu NULL
 * to distinguish the actual count of items.
 *
 * This structure does not hold information about the RDATA items, such as
 * what type is which item or how long are they. This information should be
 * stored elsewhere (in descriptors) as it is RR-specific and given for each
 * RR type.
 *
 * \todo Find out whether NULL is appropriate value. If it is a possible
 *       value for some of the items, we must find some other way to deal with
 *       this.
 * \todo Add some function for freeing particular item? Or a non-const getter?
 */
struct knot_rdata {
	knot_rdata_item_t *items; /*!< RDATA items comprising this RDATA. */
	unsigned int count; /*! < Count of RDATA items in this RDATA. */
	struct knot_rdata *next; /*!< Next RDATA item in a linked list. */
};

typedef struct knot_rdata knot_rdata_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates an empty RDATA structure.
 *
 * \return Pointer to the new RDATA structure or NULL if an error occured.
 */
knot_rdata_t *knot_rdata_new();

/*!
 * \brief Parses RDATA from the given data in wire format.
 *
 * \param rdata RDATA to fill.
 * \param wire Wire format of the whole data in which the RDATA are present.
 * \param pos Position in \a wire where to start parsing.
 * \param total_size Size of the whole data.
 * \param rdlength Size of the RDATA to parse in bytes.
 * \param desc RR type descriptor for the RDATA type.
 *
 * \retval KNOT_ENOMEM
 * \retval KNOT_EFEWDATA
 * \retval KNOT_EMALF
 * \retval KNOT_ERROR
 * \retval KNOT_EOK
 */
int knot_rdata_from_wire(knot_rdata_t *rdata, const uint8_t *wire,
                           size_t *pos, size_t total_size, size_t rdlength,
                           const knot_rrtype_descriptor_t *desc);

/*!
 * \brief Sets the RDATA item on position \a pos.
 *
 * \param rdata RDATA structure in which the item should be set.
 * \param pos Position of the RDATA item to be set.
 * \param item RDATA item value to be set.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EBADARG if \a pos is not a valid position.
 *
 * \todo Use the union or a pointer to it as parameter? IMHO there is always
 *       only one pointer that is copied, so it doesn't matter.
 */
int knot_rdata_set_item(knot_rdata_t *rdata, unsigned int pos,
                          knot_rdata_item_t item);

/*!
 * \brief Sets all RDATA items within the given RDATA structure.
 *
 * \a rdata must be empty so far (\a rdata->count == 0). The necessary space
 * is allocated.
 *
 * This function copies the array of RDATA items from \a items to \a rdata.
 *
 * \param rdata RDATA structure to store the items in.
 * \param items An array of RDATA items to be stored in this RDATA structure.
 * \param count Count of RDATA items to be stored.
 *
 * \retval 0 if successful.
 * \retval KNOT_EBADARG
 * \retval KNOT_ENOMEM
 */
int knot_rdata_set_items(knot_rdata_t *rdata,
                           const knot_rdata_item_t *items,
                           unsigned int count);

unsigned int knot_rdata_item_count(const knot_rdata_t *rdata);

/*!
 * \brief Returns the RDATA item on position \a pos.
 *
 * \note Although returning union would be OK (no overhead), we need to be able
 *       to distinguish errors (in this case by returning NULL).
 *
 * \param rdata RDATA structure to get the item from.
 * \param pos Position of the item to retrieve.
 *
 * \return The RDATA item on position \a pos, or NULL if such position does not
 *         exist within the given RDATA structure.
 */
knot_rdata_item_t *knot_rdata_get_item(const knot_rdata_t *rdata,
                                           unsigned int pos);

/*!
 * \brief Returns the RDATA item on position \a pos.
 *
 * \note Although returning union would be OK (no overhead), we need to be able
 *       to distinguish errors (in this case by returning NULL).
 * \note This function is identical to knot_rdata_get_item(), only it returns
 *       constant data.
 *
 * \param rdata RDATA structure to get the item from.
 * \param pos Position of the item to retrieve.
 *
 * \return The RDATA item on position \a pos, or NULL if such position does not
 *         exist within the given RDATA structure.
 */
const knot_rdata_item_t *knot_rdata_item(const knot_rdata_t *rdata,
                                             unsigned int pos);

/*!
 * \brief Sets the given domain name as a value of RDATA item on position
 *        \a pos.
 *
 * \param rdata RDATA structure to set the item in.
 * \param pos Position of the RDATA item to set.
 * \param dname Domain name to set to the item.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EBADARG
 */
int knot_rdata_item_set_dname(knot_rdata_t *rdata, unsigned int pos,
                                knot_dname_t *dname);

/*!
 * \brief Sets the given raw data as a value of RDATA item on position \a pos.
 *
 * \param rdata RDATA structure to set the item in.
 * \param pos Position of the RDATA item to set.
 * \param raw_data Raw data to set to the item.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EBADARG
 */
int knot_rdata_item_set_raw_data(knot_rdata_t *rdata, unsigned int pos,
                                   uint16_t *raw_data);

/*!
 * \brief Copies the given RDATA.
 *
 * \param rdata RDATA to copy.
 * \param type RR type of the RDATA.
 *
 * \return Copy of \a rdata.
 */
knot_rdata_t *knot_rdata_deep_copy(const knot_rdata_t *rdata, 
                                       uint16_t type);

/*!
 * \brief Destroys the RDATA structure without deleting RDATA items.
 *
 * Also sets the given pointer to NULL.
 *
 * \param rdata RDATA structure to be destroyed.
 */
void knot_rdata_free(knot_rdata_t **rdata);

/*!
 * \brief Destroys the RDATA structure and all its RDATA items.
 *
 * RDATA items are deleted according to the given RR Type. In case of domain
 * name, it is deallocated only if either the free_all_dnames parameter is set
 * to <> 0 or the name does not contain reference to a node (i.e. it is not an
 * owner of some node) or if it does contain a reference to a node, but is
 * not equal to its owner. (If free_all_dnames is set to <> 0, no other
 * condition is evaluated.)
 *
 * Also sets the given pointer to NULL.
 *
 * \param rdata RDATA structure to be destroyed.
 * \param type RR Type of the RDATA.
 * \param free_all_dnames Set to <> 0 if you want to delete ALL domain names
 *                        from the RDATA. Set to 0 otherwise.
 */
void knot_rdata_deep_free(knot_rdata_t **rdata, unsigned int type,
                            int free_all_dnames);

/*!
 * \brief Compares two RDATAs of the same type.
 *
 * \note Compares domain names normally (dname_compare()), i.e.
 *       case-insensitive.
 *
 * \param r1 First RDATA.
 * \param r2 Second RDATA.
 * \param format Descriptor of the RDATA format.
 *
 * \retval 0 if RDATAs are equal.
 * \retval < 0 if \a r1 goes before \a r2 in canonical order.
 * \retval > 0 if \a r1 goes after \a r2 in canonical order.
 */
int knot_rdata_compare(const knot_rdata_t *r1, const knot_rdata_t *r2,
                         const uint8_t *format);

/*!
 * \brief Retrieves the domain name from CNAME RDATA.
 *
 * \note This is only convenience function. It does not (and cannot) check if
 *       the given RDATA is of the right type, so it always returns the first
 *       RDATA item, even if it is not a domain name.
 *
 * \param rdata RDATA to get the CNAME domain name from.
 *
 * \return Canonical name stored in \a rdata or NULL if \a rdata has no items.
 */
const knot_dname_t *knot_rdata_cname_name(const knot_rdata_t *rdata);

/*!
 * \brief Retrieves the domain name from DNAME RDATA.
 *
 * \note This is only convenience function. It does not (and cannot) check if
 *       the given RDATA is of the right type, so it always returns the first
 *       RDATA item, even if it is not a domain name.
 *
 * \param rdata RDATA to get the DNAME domain name from.
 *
 * \return Target domain name stored in \a rdata or NULL if \a rdata has no
 *         items.
 */
const knot_dname_t *knot_rdata_dname_target(const knot_rdata_t *rdata);

/*!
 * \brief Retrieves the domain name from RDATA of given type.
 *
 * Supported types:
 * - KNOT_RRTYPE_NS
 * - KNOT_RRTYPE_MX
 * - KNOT_RRTYPE_SRV
 * - KNOT_RRTYPE_CNAME
 *
 * \note This is only convenience function. It does not (and cannot) check if
 *       the given RDATA is of the right type, so it always returns the RDATA
 *       item according to the given type, even if it is not a domain name.
 *
 * \param rdata RDATA to get the domain name from.
 * \param type RR type of the RDATA.
 *
 * \return Domain name stored in \a rdata or NULL if \a rdata has not enough
 *         items.
 */
const knot_dname_t *knot_rdata_get_name(const knot_rdata_t *rdata,
                                            uint16_t type);

int64_t knot_rdata_soa_serial(const knot_rdata_t *rdata);

uint32_t knot_rdata_soa_refresh(const knot_rdata_t *rdata);
uint32_t knot_rdata_soa_retry(const knot_rdata_t *rdata);
uint32_t knot_rdata_soa_expire(const knot_rdata_t *rdata);
uint32_t knot_rdata_soa_minimum(const knot_rdata_t *rdata);

uint16_t knot_rdata_rrsig_type_covered(const knot_rdata_t *rdata);

#endif /* _KNOT_RDATA_H */

/*! @} */
