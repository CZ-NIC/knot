/*!
 * \file rdata.h
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structures representing RDATA and its items and API for manipulating
 *        both.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _CUTEDNS_RDATA_H
#define _CUTEDNS_RDATA_H

#include <stdint.h>
#include "dname.h"
#include "common.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief RDATA item structure.
 *
 * Each RDATA may be logically divided into items, each of possible different
 * type. This structure distinguishes between general data (\a raw_data)
 * represented as an array of octets, and domain name (\a dname) as domain names
 * require special treatment within some RDATA (e.g. compressing in packets).
 */
union dnslib_rdata_item {
	dnslib_dname_t *dname; /*!< RDATA item represented as a domain name. */

	/*!
	 * \brief RDATA item represented as raw array of octets.
	 *
	 * In some cases the first octet will be the length of the array.
	 * In other, the size is determined by the type (i.e. 4 bytes in case of
	 * IPv4 address).
	 *
	 * In some cases this length is also used in the wire format of RDATA
	 * (e.g. character-data as defined in RFC1035).
	 */
	uint8_t *raw_data;
};

typedef union dnslib_rdata_item dnslib_rdata_item_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief RDATA structure.
 *
 * Each RDATA may be logically divided into items, each of possible different
 * type (see dnslib_rdata_item). This structure stores an array of such items.
 * It is not dynamic, so any RDATA structure may hold either 0 or one specified
 * number of items which cannot be changed later. However, the number of items
 * may be different for each RDATA structure. The number of items should be
 * given by descriptors for each RR type. Some types may have variable number
 * of items. In such cases, the last item in the array will be set tu NULL
 * to distinguish the actual count of items.
 *
 * \todo Find out whether NULL is appropriate value. If it is a possible
 *       value for some of the items, we must find some other way to deal with
 *       this.
 *
 * This structure does not hold information about the RDATA items, such as
 * what type is which item or how long are they. This information should be
 * stored elsewhere (in descriptors) as it is RR-specific and given for each
 * RR type.
 */
struct dnslib_rdata {
	dnslib_rdata_item_t *items;	/*!< RDATA items comprising this RDATA. */
	uint count;	/*! < Count of RDATA items in this RDATA. */
	struct dnslib_rdata *next;	/*!< Next RDATA item in a linked list. */
};

typedef struct dnslib_rdata dnslib_rdata_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates an empty RDATA structure.
 *
 * \return Pointer to the new RDATA structure or NULL if an error occured.
 */
dnslib_rdata_t *dnslib_rdata_new();

/*!
 * \brief Sets the RDATA item on position \a pos.
 *
 * \param rdata RDATA structure in which the item should be set.
 * \param pos Position of the RDATA item to be set.
 * \param item RDATA item value to be set.
 *
 * \retval 0 if successful.
 * \retval < 0 on error. (-1 if the allocation was not successful).
 *
 * \todo Use the union or a pointer to it as parameter? IMHO there is always
 *       only one pointer that is copied, so it doesn't matter.
 */
int dnslib_rdata_set_item( dnslib_rdata_t *rdata, uint pos,
						   dnslib_rdata_item_t item );

/*!
 * \brief Sets all RDATA items within the given RDATA structure.
 *
 * \param rdata RDATA structure to store the items in.
 * \param items An array of RDATA items to be stored in this RDATA structure.
 * \param count Count of RDATA items to be stored.
 *
 * If \a rdata has been empty so far (\a rdata->count == 0), the necessary space
 * is allocated. Otherwise \a rdata->count must be equal to \a count. If it is
 * not, this function does not alter the stored items and returns an error.
 *
 * This function copies the array of RDATA items from \a items to \a rdata.
 *
 * \retval 0 if successful.
 * \retval 1 if the \a count is 0, i.e. nothing was done.
 * \retval -1 if allocation of necessary space was not successful.
 * \retval -2 if \a rdata->count != \a count.
 */
int dnslib_rdata_set_items( dnslib_rdata_t *rdata,
							const dnslib_rdata_item_t *items, uint count );

/*!
 * \brief Returns the RDATA item on position \a pos.
 *
 * \param rdata RDATA structure to get the item from.
 * \param pos Position of the item to retrieve.
 *
 * \return The RDATA item on position \a pos, or NULL if such position does not
 *         exist within the given RDATA structure.
 *
 * \note Although returning union would be OK (no overhead), we need to be able
 *       to distinguish errors (in this case by returning NULL).
 */
const dnslib_rdata_item_t *dnslib_rdata_get_item( const dnslib_rdata_t *rdata,
												  uint pos );

/*!
 * \brief Returns the size of the RDATA in wire format.
 *
 * \param rdata RDATA structure to get the wire format size of.
 * \param format RDATA format descriptor.
 *
 * \return Size of the RDATA in wire format.
 *
 * \todo Consider adding the size to the structure for faster retrieval.
 */
uint dnslib_rdata_wire_size( const dnslib_rdata_t *rdata,
							 const uint8_t *format );

/*!
 * \brief Converts the RDATA to wire format.
 *
 * \param rdata RDATA structure to convert to wire format.
 * \param format RDATA format descriptor.
 * \param buffer Place to put the wire format into.
 * \param buf_size Size of the buffer.
 *
 * \return 0 on success.
 * \return <> 0 otherwise.
 *
 * \todo Shouldn't we keep the size of the data always in the item? It would
 *       make the converting quicker.
 */
int dnslib_rdata_to_wire( const dnslib_rdata_t *rdata, const uint8_t *format,
						  uint8_t *buffer, uint buf_size );

/*!
 * \brief Destroys the RDATA structure.
 *
 * \param rdata RDATA structure to be destroyed.
 *
 * Contents of RDATA items are not deallocated, as it is not clear whether the
 * particular item is a domain name (which should not be deallocated here) or
 * raw data (which could be). But this is actually higher-level logic, so maybe
 * a parameter to decide whether to free the items or not would be better.
 *
 * Sets the given pointer to NULL.
 */
void dnslib_rdata_free( dnslib_rdata_t **rdata );

/*!
 * \brief Compares two RDATAs of the same type.
 *
 * \param r1 First RDATA.
 * \param r2 Second RDATA.
 * \param format Descriptor of the RDATA format.
 *
 * \return 0 if RDATAs are equal.
 * \retval -1 if \a r1 goes before \a r2 in canonical order.
 * \retval 1 if \a r1 goes after \a r2 in canonical order.
 *
 * \todo Domain names in certain types should be converted to lowercase.
 * \note This function will probably be useless, no ordering will be needed
 *       for our purposes.
 */
int dnslib_rdata_compare( const dnslib_rdata_t *r1, const dnslib_rdata_t *r2,
						  const uint8_t *format );

#endif /* _CUTEDNS_RDATA_H */

/*! @} */
