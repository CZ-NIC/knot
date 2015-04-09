/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * \file
 *
 * Convenient header to include all library modules.
 *
 * \mainpage Introduction
 *
 * The \c libdnssec is a DNSSEC library for authoritative name servers and
 * similar solutions for DNSSEC management on the server side. Primarily,
 * the library is designed for use in the [Knot DNS](https://www.knot-dns.cz)
 * server.
 *
 * This is the API documentation for the \c libdnssec library.
 * At the moment, the API is not stable and is subject to frequent changes.
 *
 * The source code of the library is available in the Knot DNS repository in
 * the \c dnssec directory. Compilation of the library is integrated into the
 * Knot DNS build.
 *
 * \par Git repository
 * [git://git.nic.cz/knot-dns.git](git://git.nic.cz/knot-dns.git)
 *
 * \par Git repository browser
 * https://gitlab.labs.nic.cz/labs/knot/tree/libdnssec
 *
 * \par Issue tracker
 * https://gitlab.labs.nic.cz/labs/knot/issues
 *
 * \par Mailing list
 * knot-dns-users@lists.nic.cz
 *
 * \author Jan Vcelak
 *
 * \copyright 2013-2014 CZ.NIC, z.s.p.o.
 *
 * \copyright Licensed under the terms of
 * [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.txt)
 * version 3 or later.
 *
 * \page library Library overview
 *
 * \section dependencies Library dependencies
 *
 * In order to compile Knot DNS with \c libdnssec, following libraries
 * are required:
 *
 * - [GnuTLS](http://www.gnutls.org) >= 3.0
 *   for cryptographic operations.
 * - [Nettle](http://www.lysator.liu.se/~nisse/nettle/) >= 2.4
 *   for Base64 encoding.
 * - [LibYAML](http://pyyaml.org/wiki/LibYAML) >= 0.1
 *   for YAML parsing and writing.
 *
 * On Debian based distributions, install following packages:
 *
 *     libgnutls28-dev nettle-dev libyaml-dev
 *
 * On Fedora based distributions, install following packages:
 *
 *     gnutls-devel nettle-devel libyaml-devel
 *
 * The library also utilizes following libraries, which are bundled with
 * \c libdnssec:
 *
 * - [LibUCW](http://www.ucw.cz/libucw/) for various internal structures.
 * - [C TAP Harness](http://www.eyrie.org/~eagle/software/c-tap-harness/)
 *   for unit tests writing and execution.
 *
 * \section organization Library organization
 *
 * The library is structured into modules. Interface of each module is covered
 * by a separate header file.
 *
 * It is recommended to include only required modules, for instance:
 *
 * ~~~~ {.c}
 * #include <dnssec/binary.h>
 * #include <dnssec/key.h>
 * ~~~~
 *
 * In order to include all headers, following header can be used:
 *
 * ~~~~ {.c}
 * #include <dnssec/dnssec.h>
 * ~~~~
 */

#pragma once

#include <dnssec/binary.h>
#include <dnssec/crypto.h>
#include <dnssec/error.h>
#include <dnssec/event.h>
#include <dnssec/kasp.h>
#include <dnssec/key.h>
#include <dnssec/keyid.h>
#include <dnssec/keystore.h>
#include <dnssec/keytag.h>
#include <dnssec/list.h>
#include <dnssec/nsec.h>
#include <dnssec/random.h>
#include <dnssec/sign.h>
#include <dnssec/tsig.h>
