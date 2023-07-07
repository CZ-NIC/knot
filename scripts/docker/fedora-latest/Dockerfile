FROM fedora:latest
LABEL maintainer="Knot DNS <knot-dns@labs.nic.cz>"
ENV DEBIAN_FRONTEND noninteractive
RUN dnf -y upgrade
RUN dnf -y install \
	'autoconf' \
	'automake' \
	'clang' \
	'diffutils' \
	'libtool' \
	'make' \
	'pkgconfig' \
	'pkgconfig(lmdb)' \
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
	'pkgconfig(libxdp)' \
	'python-sphinx'
