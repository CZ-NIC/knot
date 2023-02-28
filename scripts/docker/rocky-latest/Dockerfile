FROM rockylinux:9
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>
ENV DEBIAN_FRONTEND noninteractive
RUN dnf -y upgrade
RUN dnf -y install epel-release
RUN dnf -y --enablerepo crb install \
	'autoconf' \
	'automake' \
	'diffutils' \
	'libtool' \
	'make' \
	'pkgconfig' \
	'pkgconfig(lmdb)' \
	'pkgconfig(gnutls)' \
	'pkgconfig(libcap-ng)' \
	'pkgconfig(libedit)' \
	'pkgconfig(libfstrm)' \
	'pkgconfig(libidn2)' \
	'pkgconfig(libmaxminddb)' \
	'pkgconfig(libprotobuf-c)' \
	'pkgconfig(libsystemd)' \
	'pkgconfig(liburcu)' \
	'python3-sphinx' \
	'systemd'
