/*
 * Utility routines for writing floating point tests.
 *
 * Currently provides only one function, which checks whether a double is
 * equal to an expected value within a given epsilon.  This is broken into a
 * separate source file from the rest of the basic C TAP library because it
 * may require linking with -lm on some platforms, and the package may not
 * otherwise care about floating point.
 *
 * This file is part of C TAP Harness.  The current version plus supporting
 * documentation is at <http://www.eyrie.org/~eagle/software/c-tap-harness/>.
 *
 * Copyright 2008, 2010, 2012 Russ Allbery <rra@stanford.edu>
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

/* Required for isnan() and isinf(). */
#if defined(__STRICT_ANSI__) || defined(PEDANTIC)
# ifndef _XOPEN_SOURCE
#  define _XOPEN_SOURCE 600
# endif
#endif

#include <math.h>
#include <stdarg.h>
#include <stdio.h>

#include "basic.h"
#include "float.h"

/*
 * Takes an expected double and a seen double and assumes the test passes if
 * those two numbers are within delta of each other.
 */
void
is_double(double wanted, double seen, double epsilon, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    fflush(stderr);
    if ((isnan(wanted) && isnan(seen))
        || (isinf(wanted) && isinf(seen) && wanted == seen)
        || fabs(wanted - seen) <= epsilon)
        okv(1, format, args);
    else {
        printf("# wanted: %g\n#   seen: %g\n", wanted, seen);
        okv(0, format, args);
    }
}
