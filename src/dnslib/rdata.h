/*!
 * \file rdata.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structures representing RDATA and its items and API for manipulating
 *        both.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_RDATA_H_
#define _KNOT_DNSLIB_RDATA_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/dname.h"
#include "dnslib/descriptor.h"

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
struct dnslib_rdata {
	dnslib_rdata_item_t *items; /*!< RDATA items comprising this RDATA. */
	unsigned int count; /*! < Count of RDATA items in this RDATA. */
	struct dnslib_rdata *next; /*!< Next RDATA item in a linked list. */
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
 * \brief Parses RDATA from the given data in wire format.
 *
 * \param rdata RDATA to fill.
 * \param wire Wire format of the whole data in which the RDATA are present.
 * \param pos Position in \a wire where to start parsing.
 * \param total_size Size of the whole data.
 * \param rdlength Size of the RDATA to parse in bytes.
 * \param desc RR type descriptor for the RDATA type.
 *
 * \retval DNSLIB_ENOMEM
 * \retval DNSLIB_EFEWDATA
 * \retval DNSLIB_EMALF
 * \retval DNSLIB_ERROR
 * \retval DNSLIB_EOK
 */
int dnslib_rdata_from_wire(dnslib_rdata_t *rdata, const uint8_t *wire,
                           size_t *pos, size_t total_size, size_t rdlength,
                           const dnslib_rrtype_descriptor_t *desc);

/*!
 * \brief Sets the RDATA item on position \a pos.
 *
 * \param rdata RDATA structure in which the item should be set.
 * \param pos Position of the RDATA item to be set.
 * \param item RDATA item value to be set.
 *
 * \retval DNSLIB_EOK if successful.
 * \retval DNSLIB_EBADARG if \a pos is not a valid position.
 *
 * \todo Use the union or a pointer to it as parameter? IMHO there is always
 *       only one pointer that is copied, so it doesn't matter.
 */
int dnslib_rdata_set_item(dnslib_rdata_t *rdata, unsigned int pos,
                          dnslib_rdata_item_t item);

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
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENOMEM
 */
int dnslib_rdata_set_items(dnslib_rdata_t *rdata,
                           const dnslib_rdata_item_t *items,
                           unsigned int count);

unsigned int dnslib_rdata_item_count(const dnslib_rdata_t *rdata);

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
dnslib_rdata_item_t *dnslib_rdata_get_item(const dnslib_rdata_t *rdata,
                                           unsigned int pos);

/*!
 * \brief Returns the RDATA item on position \a pos.
 *
 * \note Although returning union would be OK (no overhead), we need to be able
 *       to distinguish errors (in this case by returning NULL).
 * \note This function is identical to dnslib_rdata_get_item(), only it returns
 *       constant data.
 *
 * \param rdata RDATA structure to get the item from.
 * \param pos Position of the item to retrieve.
 *
 * \return The RDATA item on position \a pos, or NULL if such position does not
 *         exist within the given RDATA structure.
 */
const dnslib_rdata_item_t *dnslib_rdata_item(const dnslib_rdata_t *rdata,
                                             unsigned int pos);

/*!
 * \brief Sets the given domain name as a value of RDATA item on position
 *        \a pos.
 *
 * \param rdata RDATA structure to set the item in.
 * \param pos Position of the RDATA item to set.
 * \param dname Domain name to set to the item.
 *
 * \retval DNSLIB_EOK if successful.
 * \retval DNSLIB_EBADARG
 */
int dnslib_rdata_item_set_dname(dnslib_rdata_t *rdata, unsigned int pos,
                                dnslib_dname_t *dname);

/*!
 * \brief Sets the given raw data as a value of RDATA item on position \a pos.
 *
 * \param rdata RDATA structure to set the item in.
 * \param pos Position of the RDATA item to set.
 * \param raw_data Raw data to set to the item.
 *
 * \retval DNSLIB_EOK if successful.
 * \retval DNSLIB_EBADARG
 */
int dnslib_rdata_item_set_raw_data(dnslib_rdata_t *rdata, unsigned int pos,
                                   uint16_t *raw_data);

/*!
 * \brief Copies the given RDATA.
 *
 * \param rdata RDATA to copy.
 * \param type RR type of the RDATA.
 *
 * \return Copy of \a rdata.
 */
dnslib_rdata_t *dnslib_rdata_copy(const dnslib_rdata_t *rdata, uint16_t type);

/*!
 * \brief Destroys the RDATA structure without deleting RDATA items.
 *
 * Also sets the given pointer to NULL.
 *
 * \param rdata RDATA structure to be destroyed.
 */
void dnslib_rdata_free(dnslib_rdata_t **rdata);

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
void dnslib_rdata_deep_free(dnslib_rdata_t **rdata, unsigned int type,
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
int dnslib_rdata_compare(const dnslib_rdata_t *r1, const dnslib_rdata_t *r2,
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
const dnslib_dname_t *dnslib_rdata_cname_name(const dnslib_rdata_t *rdata);

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
const dnslib_dname_t *dnslib_rdata_dname_target(const dnslib_rdata_t *rdata);

/*!
 * \brief Retrieves the domain name from RDATA of given type.
 *
 * Supported types:
 * - DNSLIB_RRTYPE_NS
 * - DNSLIB_RRTYPE_MX
 * - DNSLIB_RRTYPE_SRV
 * - DNSLIB_RRTYPE_CNAME
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
const dnslib_dname_t *dnslib_rdata_get_name(const dnslib_rdata_t *rdata,
                                            uint16_t type);

int64_t dnslib_rdata_soa_serial(const dnslib_rdata_t *rdata);

uint32_t dnslib_rdata_soa_refresh(const dnslib_rdata_t *rdata);
uint32_t dnslib_rdata_soa_retry(const dnslib_rdata_t *rdata);
uint32_t dnslib_rdata_soa_expire(const dnslib_rdata_t *rdata);

uint16_t dnslib_rdata_rrsig_type_covered(const dnslib_rdata_t *rdata);

#endif /* _KNOT_DNSLIB_RDATA_H */

/*! @} */
