#pragma once

#include <stdio.h>

static inline void fclose_ptr(FILE **handle)
{
	fclose(*handle);
}

#define _unused_ __attribute__((unused))
#define _cleanup_(var) __attribute__((cleanup(var)))
#define _destructor_ __attribute__((destructor))

#define _cleanup_free_ _cleanup_(free)
#define _cleanup_fclose_ _cleanup_(fclose_ptr)

#define _public_ __attribute__((visibility("default")))
#define _hidden_ __attribute__((visibility("hidden")))
