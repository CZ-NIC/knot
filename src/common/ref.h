/*!
 * \file ref.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Atomic reference counting structures.
 *
 * Reference counting allows implicit sharing of objects
 * between threads with custom destructor functions.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOT_REF_H_
#define _KNOT_REF_H_

#include <stddef.h>

struct ref_t;

/*! \brief Prototype for object destructor callback. */
typedef void (*ref_destructor_t)(struct ref_t * p);

/*!
 * \brief Structure for reference counting.
 *
 * Size equals to two sizes of pointer size.
 * Structure may be embedded to the structures which
 * we want to use for reference counting.
 *
 * \code
 * struct mystruct {
 *    ref_t ref;
 *    int mydata;
 *    char *mystr;
 * }
 * \endcode
 */
typedef struct ref_t {
	size_t count;          /*! \brief Reference counter. */
	ref_destructor_t dtor; /*! \brief Object destructor function. */
} ref_t;

/*!
 * \brief Initialize reference counter.
 *
 * Set reference counter to 0 and initialize destructor callback.
 *
 * \param p Reference-counted object.
 * \param dtor Destructor function.
 */
void ref_init(ref_t *p, ref_destructor_t dtor);

/*!
 * \brief Mark object as used by the caller.
 *
 * Reference counter will be incremented.
 *
 * \param p Reference-counted object.
 */
void ref_retain(ref_t *p);

/*!
 * \brief Marks object as unused by the caller.
 *
 * Reference counter will be decremented.
 *
 * \param p Reference-counted object.
 */
void ref_release(ref_t *p);

#endif /* _KNOT_REF_H_ */

/*! @} */
