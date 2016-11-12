# Coding

## Components Location

- library: `lib` (public headers in `lib/dnssec`)
- shared: `shared` (shared code for library and utilities, inaccessible from the library)
- tests: `tests`
- utilities: `utils`

## Coding Style

Basically, [Linux kernel coding style](https://www.kernel.org/doc/Documentation/CodingStyle) with a few changes is used.

Rules worth to highlight:

- Line limit is 80 chars (if it increases readability, can be exceeded a little).
- Use tabs for indentation, align with tabs and spaces.
- Tabs are 8 characters.
- No white space charactes at the end of the line are allowed.
- No empty lines at the end of the file, the last line ends with a '\n' char
- Use braces even for single line statements after if, else, while, for, ...
- Use typedefs for structs, do not use them for pointers.
- Use comma after the last element of a list, unless there is a terminating sentinel.
