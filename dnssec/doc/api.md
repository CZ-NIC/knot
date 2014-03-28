# API

At this phase of the library development, the API is very unstable and is
likely to be changing often.

## Conventions for API definitions

- All identifiers are prefixed with `dnssec_` (functions, types) or `DNSSEC_` (constants).
- All public headers are placed in `lib/dnssec`.
- Use `#pragma once` in the headers files as a include guard.
- Includes of other library modules have the following form: `#include <dnssec/module.h>`.

## Linking

- During the build process, all sources are linked into the lib.la library,
  which exports all symbols, including the private ones. From this library, the
  libdnssec.la library is made, which exports only public symbols.

- Unit tests are linked against lib.la to be able to test internal interfaces.

- The tools must be linked to the libdnssec.la library.

## TODO

- Decide how to work with `extern "C"`.
- Decide how to mark the symbols to be exported in ELF.
- Autogenerating of public library headers.
