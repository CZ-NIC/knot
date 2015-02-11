# API

At this phase of the library development, the API is very unstable and is
likely to be changing often.

## Conventions for API definitions

- All identifiers are prefixed with `dnssec_` (functions, types) or `DNSSEC_` (constants).
- All public headers are placed in `lib/dnssec`.
- Use `#pragma once` in the headers files as a include guard.
- Includes of other library modules have the following form: `#include <dnssec/module.h>`.
- Public symbols in the `.c` files are decorated using `_public_` macro from `shared.h`.

## Linking

- Building of static libraries is enabled by default, as shared libraries expose
  only a public interface. The unit tests perform testing of some internal
  interfaces, therefore disabling the static build breaks the tests.
- Installing of static libraries into the system is not recommended.

## TODO

- Decide how to work with `extern "C"`.
- Autogenerating of public library headers.
