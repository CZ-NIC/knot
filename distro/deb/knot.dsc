Format: 3.0 (quilt)
Source: knot
Binary: knot, libknot7, libzscanner1, libdnssec5, libknot-dev, knot-dnsutils, knot-host, knot-doc
Architecture: any all
Version: __VERSION__-1
Maintainer: Knot DNS <knot-dns@lists.nic.cz>
Uploaders: Tomas Krizek <tomas.krizek@nic.cz>
Homepage: https://www.knot-dns.cz/
Build-Depends: autotools-dev, bash-completion, bison, debhelper (>= 9), dh-autoreconf, dh-systemd, flex, latexmk, libedit-dev, libfstrm-dev, libgnutls28-dev, libidn11-dev, libjansson-dev (>= 2.4), liblmdb-dev, libprotobuf-c-dev, libsystemd-dev [linux-any] | libsystemd-daemon-dev [linux-any], libsystemd-dev [linux-any] | libsystemd-journal-dev [linux-any], liburcu-dev (>= 0.4), pkg-config, protobuf-c-compiler
Build-Depends-Indep: ghostscript, python-sphinx, texinfo, texlive, texlive-font-utils, texlive-generic-extra, texlive-latex-extra
Package-List:
 knot deb net optional arch=any
 knot-dnsutils deb net optional arch=any
 knot-doc deb doc optional arch=all
 knot-host deb net optional arch=any
 libdnssec5 deb libs optional arch=any
 libknot-dev deb libdevel optional arch=any
 libknot7 deb libs optional arch=any
 libzscanner1 deb libs optional arch=any
Files:
