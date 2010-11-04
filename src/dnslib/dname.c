#include <stdint.h>
#include "common.h"
#include "consts.h"
#include "dname.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

/*!
 * \todo handle \X and \DDD (RFC 1035 5.1) or it can be handled by the parser?
 */
int dnslib_dname_str_to_wire( const char *name, uint size, uint8_t **wire )
{
	if (size > DNSLIB_MAX_DNAME_LENGTH) {
		return 0;
	}

	// signed / unsigned issues??
	*wire = (uint8_t *)malloc((size + 1) * sizeof(uint8_t));
	if (*wire == NULL) {
		return 0;
	}

	const uint8_t *ch = (const uint8_t *)name;
	uint8_t *label_start = *wire;
	uint8_t *w = *wire;
	uint8_t label_length = 0;

	while (ch - name < size) {
		assert(w - *wire < size);
		assert(w - *wire == ch - name);

		if (*ch == '.' ) {
			*label_start = label_length;
			label_start = w;
		} else {
			*w = *ch;
		}

		++w;
		++ch;
		assert(ch >= name);
	}

	// put 0 for root label regardless whether the name ended with .
	*w = 0;

	//memcpy(*wire, name, size);
	return size;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new()
{
	dnslib_dname_t *dname = (dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));
	if (name == NULL) {
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
										   dnslib_node_t *node )
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
	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

dnslib_dname_t *dnslib_dname_new_from_wire( uint8_t *name, uint size,
											dnslib_node_t *node )
{
	dnslib_dname_t *dname = (dnslib_dname_t *)malloc(sizeof(dnslib_dname_t));
	if (name == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = name;
	dname->size = size;
	dname->node = node;

	return dname;
}

/*----------------------------------------------------------------------------*/

char *dnslib_dname_to_str( dnslib_dname_t *dname )
{
	char *name = (char *)malloc(dname->size * sizeof(char));

	uint8_t *w = dname->name;
	char *ch = name;

	while (*w != 0) {
		// skip label length
		uint8_t *next = w + *w + 1;
		while (w != next) {
			*(ch++) = *(w++);
		}
	}

	*ch = 0;
	assert(ch - name == dname->size);

	return name;
}

/*----------------------------------------------------------------------------*/

void dnslib_dname_free( dnslib_dname *dname )
{
	free(dname->name);
	free(dname);
}
