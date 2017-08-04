FROM centos:latest
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>
ENV DEBIAN_FRONTEND noninteractive
RUN yum -y upgrade
RUN yum -y install epel-release
RUN yum -y install \
	'autoconf' \
	'automake' \
	'libtool' \
	'lmdb-devel' \
	'pkgconfig' \
	'pkgconfig(gnutls)' \
	'pkgconfig(jansson)' \
	'pkgconfig(libcap-ng)' \
	'pkgconfig(libedit)' \
	'pkgconfig(libfstrm)' \
	'pkgconfig(libidn2)' \
	'pkgconfig(libprotobuf-c)' \
	'pkgconfig(libsystemd)' \
	'pkgconfig(liburcu)' \
	'pkgconfig(nettle)' \
	'python-sphinx' \
	'systemd'
