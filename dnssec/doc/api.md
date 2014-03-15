# API

At this phase of the library development, the API is very unstable and is
likely to be changing often.

## Conventions for API definitions

- All identifiers are prefixed with `dnssec_` (functions, types) or `DNSSEC_` (constants).
- All public headers are placed in `lib/dnssec`.
- Use `#pragma once` in the headers files as a include guard.
- Includes of other library modules have the following form: `#include <dnssec/module.h>`.

## TODO

- Decide how to work with `extern "C"`.
- Decide how to mark the symbols to be exported in ELF.
