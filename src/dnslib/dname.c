#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "common.h"
#include "consts.h"
#include "dname.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 *	\brief Returns the size of the wire format of domain name which has
 *         \a str_size characters in presentation format.
 */
static inline uint dnslib_dname_wire_size( uint str_size )
{
	return str_size + 1;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Converts domain name from string representation to wire format.
 *
 * \param name Domain name in string representation (presentation format).
 * \param size Size of the given domain name in characters (not counting the
 *             terminating 0 character.
 * \param wire [in/out] Pointer to position where the wire format of the domain
 *             name will be stored.
 *
 * This function also allocates the space for the wire format.
 *
 * \return Size of the wire format of the domain name in octets. If 0, no
 *         space has been allocated.
 *
 * \todo handle \X and \DDD (RFC 1035 5.1) or it can be handled by the parser?
 */
static uint dnslib_dname_str_to_wire( const char *name, uint size,
									 uint8_t **wire )
{
	if (size > DNSLIB_MAX_DNAME_LENGTH) {
		return 0;
	}

	uint wire_size = dnslib_dname_wire_size(size);

	// signed / unsigned issues??
	*wire = (uint8_t *)malloc(wire_size * sizeof(uint8_t));
	if (*wire == NULL) {
		return 0;
	}

	debug_dnslib_dname("Allocated space for wire format of dname: %p\n",
					   *wire);

	const uint8_t *ch = (const uint8_t *)name;
	uint8_t *label_start = *wire;
	uint8_t *w = *wire + 1;
	uint8_t label_length = 0;

	while (ch - (const uint8_t *)name < size) {
		assert(w - *wire < wire_size);
		assert(w - *wire - 1 == ch - (const uint8_t *)name);

		if (*ch == '.' ) {
			debug_dnslib_dname("Position %u (%p): label length: %u\n",
							   label_start - *wire, label_start, label_length);
			*label_start = label_length;
			label_start = w;
			label_length = 0;
		} else {
			debug_dnslib_dname("Position %u (%p): character: %c\n",
							   w - *wire, w, *ch);
			*w = *ch;
			++label_length;
		}

		++w;
		++ch;
		assert(ch >= (const uint8_t *)name);
	}

	// put 0 for root label regardless whether the name ended with .
	--w;
	debug_dnslib_dname("Position %u (%p): character: (null)\n", w - *wire, w);
	*w = 0;

	//memcpy(*wire, name, size);
	return wire_size;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new()
{
	dnslib_dname_t *dname = (dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));
	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = NULL;
	dname->size = 0;
	dname->node = NULL;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_str( char *name, uint size,
										   struct dnslib_node *node )
{
	if (name == NULL || size == 0) {
		return NULL;
	}

	dnslib_dname_t *dname = (dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));
	if (name == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->size = dnslib_dname_str_to_wire(name, size, &dname->name);
	if (dname->size <= 0) {
		log_warning("Could not parse domain name from string: '%.*s'\n",
					size, name);
	}
	assert(dname->name != NULL);

	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_wire( uint8_t *name, uint size,
											struct dnslib_node *node )
{
	if (name == NULL && size != 0) {
		printf("No name given!\n");
		return NULL;
	}

	dnslib_dname_t *dname = (dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));
	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (dname->name == NULL) {
		ERR_ALLOC_FAILED;
		free(dname);
		return NULL;
	}

	memcpy(dname->name, name, size);
	dname->size = size;
	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

char *dnslib_dname_to_str( const dnslib_dname_t *dname )
{
	char *name = (char *)malloc(dname->size * sizeof(char));

	uint8_t *w = dname->name;
	char *ch = name;

	while (*w != 0) {
		uint8_t *next = w + *w + 1;
		// skip label length
		++w;
		while (w != next) {
			*(ch++) = *(w++);
		}
		// insert . at the end of label
		*(ch++) = '.';
	}

	*ch = 0;
	assert(ch - name == dname->size - 1);

	return name;
}

/*----------------------------------------------------------------------------*/

const uint8_t *dnslib_dname_name( const dnslib_dname_t *dname )
{
	return dname->name;
}

/*----------------------------------------------------------------------------*/

uint dnslib_dname_size( const dnslib_dname_t *dname )
{
	return dname->size;
}

/*----------------------------------------------------------------------------*/

const struct dnslib_node *dnslib_dname_node( const dnslib_dname_t *dname )
{
	return dname->node;
}

/*----------------------------------------------------------------------------*/

void dnslib_dname_free( dnslib_dname_t *dname )
{
	free(dname->name);
	free(dname);
}
