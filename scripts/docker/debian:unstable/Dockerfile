FROM debian:unstable-slim
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>
ENV DEBIAN_FRONTEND noninteractive
RUN sed -i 's/deb.debian.org/ftp.cz.debian.org/' /etc/apt/sources.list
RUN apt-get -y update
RUN apt-get -y dist-upgrade
RUN apt-get -y install \
	apt-utils \
	autoconf \
	automake \
	autotools-dev \
	bash-completion \
	build-essential \
	clang-6.0 \
	curl \
	ghostscript \
	git \
	libedit-dev \
	libfstrm-dev \
	libgnutls28-dev \
	libidn11-dev \
	liblmdb-dev \
	libprotobuf-c-dev \
	libsystemd-dev \
	libtool \
	liburcu-dev \
	locales-all \
	pkg-config \
	protobuf-c-compiler	\
	python-sphinx \
	texinfo texlive \
	texlive-font-utils \
	texlive-generic-extra \
	texlive-latex-extra \
	unzip
