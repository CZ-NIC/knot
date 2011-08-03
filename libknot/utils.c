#include <config.h>
#include <string.h>
#include <pthread.h>

#include "common.h"
#include "utils.h"

/*----------------------------------------------------------------------------*/

knot_lookup_table_t *knot_lookup_by_name(knot_lookup_table_t *table,
                                             const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

knot_lookup_table_t *knot_lookup_by_id(knot_lookup_table_t *table,
                                           int id)
{
	while (table->name != NULL) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

size_t knot_strlcpy(char *dst, const char *src, size_t size)
{
	char *d = dst;
	const char *s = src;
	size_t n = size;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0) {
				break;
			}
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (size != 0) {
			*d = '\0';        /* NUL-terminate dst */
		}
		while (*s++)
			;
	}

	return(s - src - 1);        /* count does not include NUL */
}

/*! \brief TLS key for rand seed. */
static pthread_key_t _qr_key;
static pthread_once_t _qr_once = PTHREAD_ONCE_INIT;

/*! \brief TLS key initializer. */
static void _qr_init()
{
	(void) pthread_key_create(&_qr_key, NULL);
	(void) pthread_setspecific(_qr_key, (void*)time(0));
}

size_t knot_quick_rand()
{
	(void) pthread_once(&_qr_once, _qr_init);
	size_t x = (size_t)pthread_getspecific(_qr_key);

	/* Numerical Recipes in C.
	 * The Art of Scientific Computing, 2nd Edition,
	 * 1992, ISBN 0-521-43108-5.
	 * Page 284.
	 */
	x = 1664525L * x + 1013904223L;
	(void) pthread_setspecific(_qr_key, (void*)x);
	return x;
}
