#pragma once

#define _unused_ __attribute__((unused))
#define _cleanup_(var) __attribute__((cleanup(var)))
#define _destructor_ __attribute__((destructor))

#define _public_ __attribute__((visibility("default")))
#define _hidden_ __attribute__((visibility("hidden")))
