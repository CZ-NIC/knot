/*
 * Basic utility routines for the TAP protocol.
 *
 * This file is part of C TAP Harness.  The current version plus supporting
 * documentation is at <http://www.eyrie.org/~eagle/software/c-tap-harness/>.
 *
 * Copyright 2009, 2010, 2011, 2012 Russ Allbery <rra@stanford.edu>
 * Copyright 2001, 2002, 2004, 2005, 2006, 2007, 2008, 2011, 2012
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#pragma once

#include "macros.h"
#include <stdarg.h>             /* va_list */
#include <sys/types.h>          /* size_t */

/*
 * Used for iterating through arrays.  ARRAY_SIZE returns the number of
 * elements in the array (useful for a < upper bound in a for loop) and
 * ARRAY_END returns a pointer to the element past the end (ISO C99 makes it
 * legal to refer to such a pointer as long as it's never dereferenced).
 */
#define ARRAY_SIZE(array)       (sizeof(array) / sizeof((array)[0]))
#define ARRAY_END(array)        (&(array)[ARRAY_SIZE(array)])

BEGIN_DECLS

/*
 * The test count.  Always contains the number that will be used for the next
 * test status.
 */
extern unsigned long testnum;

/* Print out the number of tests and set standard output to line buffered. */
void plan(unsigned long count);

/*
 * Prepare for lazy planning, in which the plan will be  printed automatically
 * at the end of the test program.
 */
void plan_lazy(void);

/* Skip the entire test suite.  Call instead of plan. */
void skip_all(const char *format, ...)
    __attribute__((__noreturn__, __format__(printf, 1, 2)));

/*
 * Basic reporting functions.  The okv() function is the same as ok() but
 * takes the test description as a va_list to make it easier to reuse the
 * reporting infrastructure when writing new tests.
 */
void ok(int success, const char *format, ...)
    __attribute__((__format__(printf, 2, 3)));
void okv(int success, const char *format, va_list args);
void skip(const char *reason, ...)
    __attribute__((__format__(printf, 1, 2)));

/* Report the same status on, or skip, the next count tests. */
void ok_block(unsigned long count, int success, const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void skip_block(unsigned long count, const char *reason, ...)
    __attribute__((__format__(printf, 2, 3)));

/* Check an expected value against a seen value. */
void is_int(long long wanted, long long seen, const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_string(const char *wanted, const char *seen, const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));
void is_hex(unsigned long long wanted, unsigned long long seen,
            const char *format, ...)
    __attribute__((__format__(printf, 3, 4)));

/* Bail out with an error.  sysbail appends strerror(errno). */
void bail(const char *format, ...)
    __attribute__((__noreturn__, __nonnull__, __format__(printf, 1, 2)));
void sysbail(const char *format, ...)
    __attribute__((__noreturn__, __nonnull__, __format__(printf, 1, 2)));

/* Report a diagnostic to stderr prefixed with #. */
void diag(const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 1, 2)));
void sysdiag(const char *format, ...)
    __attribute__((__nonnull__, __format__(printf, 1, 2)));

/* Allocate memory, reporting a fatal error with bail on failure. */
void *bcalloc(size_t, size_t)
    __attribute__((__alloc_size__(1, 2), __malloc__));
void *bmalloc(size_t)
    __attribute__((__alloc_size__(1), __malloc__));
void *brealloc(void *, size_t)
    __attribute__((__alloc_size__(2), __malloc__));
char *bstrdup(const char *)
    __attribute__((__malloc__, __nonnull__));
char *bstrndup(const char *, size_t)
    __attribute__((__malloc__, __nonnull__));

/*
 * Find a test file under BUILD or SOURCE, returning the full path.  The
 * returned path should be freed with test_file_path_free().
 */
char *test_file_path(const char *file)
    __attribute__((__malloc__, __nonnull__));
void test_file_path_free(char *path);

/*
 * Create a temporary directory relative to BUILD and return the path.  The
 * returned path should be freed with test_tmpdir_free.
 */
char *test_tmpdir(void)
    __attribute__((__malloc__));
void test_tmpdir_free(char *path);

END_DECLS
