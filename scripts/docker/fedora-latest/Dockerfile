FROM fedora:latest
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>
ENV DEBIAN_FRONTEND noninteractive
RUN dnf -y upgrade
RUN dnf -y install \
	'autoconf' \
	'automake' \
	'clang' \
	'diffutils' \
	'libtool' \
	'llvm' \
	'lmdb-devel' \
	'make' \
	'pkgconfig' \
	'pkgconfig(gnutls)' \
	'pkgconfig(libbpf)' \
	'pkgconfig(libcap-ng)' \
	'pkgconfig(libedit)' \
	'pkgconfig(libfstrm)' \
	'pkgconfig(libidn2)' \
	'pkgconfig(libmaxminddb)' \
	'pkgconfig(libmnl)' \
	'pkgconfig(libprotobuf-c)' \
	'pkgconfig(libsystemd)' \
	'pkgconfig(liburcu)' \
	'python-sphinx'
