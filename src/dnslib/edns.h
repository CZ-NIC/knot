/*!
 * \file edns.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Functions for manipulating and parsing EDNS OPT pseudo-RR.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_EDNS_H_
#define _KNOT_DNSLIB_EDNS_H_

#include <stdint.h>

#include "dnslib/utils.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing one OPT RR Option.
 */
struct dnslib_opt_option {
	uint16_t code;
	uint16_t length;
	uint8_t *data;
};

typedef struct dnslib_opt_option dnslib_opt_option_t;

/*!
 * \brief Structure for holding EDNS parameters.
 *
 * \todo NSID
 */
struct dnslib_opt_rr {
	uint16_t payload;    /*!< UDP payload. */
	uint8_t ext_rcode;   /*!< Extended RCODE. */

	/*!
	 * \brief Supported version of EDNS.
	 *
	 * Set to EDNS_NOT_SUPPORTED if not supported.
	 */
	uint8_t version;

	uint16_t flags;                /*!< EDNS flags. */
	dnslib_opt_option_t *options;  /*!< EDNS options. */
	short option_count;         /*!< Count of EDNS options in this OPT RR.*/
	short options_max;          /*!< Maximum count of options. */
	short size;             /*!< Total size of the OPT RR in wire format. */
};

typedef struct dnslib_opt_rr dnslib_opt_rr_t;

/*----------------------------------------------------------------------------*/

enum dnslib_edns_versions {
	EDNS_VERSION_0 = (uint8_t)0,
	EDNS_NOT_SUPPORTED = (uint8_t)255
};

static const short DNSLIB_EDNS_MIN_SIZE = 11;

enum dnslib_edns_option_codes {
	EDNS_OPTION_NSID = (uint16_t)3
};

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates new empty OPT RR structure for holding EDNS parameters.
 *
 * \return New empty dnslib_opt_rr_t structure, or NULL if not successful.
 */
dnslib_opt_rr_t *dnslib_edns_new();

/*!
 * \brief Initializes OPT RR structure from given OPT RR in wire format.
 *
 * \param opt_rr OPT RR structure to initialize.
 * \param wire Wire format of the OPT RR to parse.
 * \param max_size Maximum size of the wire format in bytes (may be more
 *                 than acutal size of the OPT RR).
 *
 * \return Size of the parserd OPT RR in bytes if successful (always > 0).
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_EFEWDATA
 * \retval DNSLIB_EMALF
 * \retval DNSLIB_ENOMEM
 */
int dnslib_edns_new_from_wire(dnslib_opt_rr_t *opt_rr, const uint8_t *wire,
                              size_t max_size);

/*!
 * \brief Returns the UDP payload stored in the OPT RR.
 *
 * \param opt_rr OPT RR structure to get the payload from.
 *
 * \return UDP payload in bytes.
 */
uint16_t dnslib_edns_get_payload(const dnslib_opt_rr_t *opt_rr);

/*!
 * \brief Sets the UDP payload field in the OPT RR.
 *
 * \param opt_rr OPT RR structure to set the payload to.
 * \param payload UDP payload in bytes.
 */
void dnslib_edns_set_payload(dnslib_opt_rr_t *opt_rr, uint16_t payload);

/*!
 * \brief Returns the Extended RCODE stored in the OPT RR.
 *
 * \param opt_rr OPT RR structure to get the Extended RCODE from.
 *
 * \return Extended RCODE.
 */
uint8_t dnslib_edns_get_ext_rcode(const dnslib_opt_rr_t *opt_rr);

/*!
 * \brief Sets the Extended RCODE field in the OPT RR.
 *
 * \param opt_rr OPT RR structure to set the Extended RCODE to.
 * \param ext_rcode Extended RCODE to set.
 */
void dnslib_edns_set_ext_rcode(dnslib_opt_rr_t *opt_rr, uint8_t ext_rcode);

/*!
 * \brief Returns the EDNS version stored in the OPT RR.
 *
 * \param opt_rr OPT RR structure to get the EDNS version from.
 *
 * \return EDNS version.
 */
uint8_t dnslib_edns_get_version(const dnslib_opt_rr_t *opt_rr);

/*!
 * \brief Sets the EDNS version field in the OPT RR.
 *
 * \param opt_rr OPT RR structure to set the EDNS version to.
 * \param version EDNS version to set.
 */
void dnslib_edns_set_version(dnslib_opt_rr_t *opt_rr, uint8_t version);

/*!
 * \brief Returns the flags stored in the OPT RR.
 *
 * \param opt_rr OPT RR structure to get the flags from.
 *
 * \return EDNS flags.
 */
uint16_t dnslib_edns_get_flags(const dnslib_opt_rr_t *opt_rr);

/*!
 * \brief Returns the state of the DO bit in the OPT RR flags.
 *
 * \param opt_rr OPT RR structure to get the DO bit from.
 *
 * \return <> 0 if the DO bit is set.
 * \return 0 if the DO bit is not set.
 */
int dnslib_edns_do(const dnslib_opt_rr_t *opt_rr);

/*!
 * \brief Sets the DO bit in the OPT RR.
 *
 * \param opt_rr OPT RR structure to set the DO bit in.
 */
void dnslib_edns_set_do(dnslib_opt_rr_t *opt_rr);

/*!
 * \brief Adds EDNS Option to the OPT RR.
 *
 * \param opt_rr OPT RR structure to add the Option to.
 * \param code Option code.
 * \param length Option data length in bytes.
 * \param data Option data.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENOMEM
 */
int dnslib_edns_add_option(dnslib_opt_rr_t *opt_rr, uint16_t code,
                           uint16_t length, const uint8_t *data);

/*!
 * \brief Checks if the OPT RR contains Option with the specified code.
 *
 * \param opt_rr OPT RR structure to check for the Option in.
 * \param code Option code to check for.
 *
 * \retval <> 0 if the OPT RR contains Option with Option code \a code.
 * \retval 0 otherwise.
 */
int dnslib_edns_has_option(const dnslib_opt_rr_t *opt_rr, uint16_t code);

/*!
 * \brief Converts the given OPT RR into wire format.
 *
 * \param opt_rr OPT RR structure to convert into wire format.
 * \param wire Place to put the wire format to.
 * \param max_size Maximum space available for the wire format in bytes.
 *
 * \return Size of the wire format in bytes if successful.
 * \retval DNSLIB_ESPACE
 */
short dnslib_edns_to_wire(const dnslib_opt_rr_t *opt_rr, uint8_t *wire,
                          short max_size);

/*!
 * \brief Returns size of the OPT RR in wire format.
 *
 * \param opt_rr OPT RR to get the size of.
 *
 * \return Size of the OPT RR in bytes.
 */
short dnslib_edns_size(dnslib_opt_rr_t *opt_rr);

/*!
 * \brief Properly destroys the OPT RR structure.
 *
 * \note Also sets the given pointer to NULL.
 */
void dnslib_edns_free(dnslib_opt_rr_t **opt_rr);

#endif /* _KNOT_DNSLIB_EDNS_H_ */

/*! @} */
