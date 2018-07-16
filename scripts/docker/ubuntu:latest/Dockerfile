FROM ubuntu:latest
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update
RUN apt-get -y dist-upgrade
RUN apt-get -y install \
	autoconf \
	automake \
	autotools-dev \
	build-essential \
	curl \
	ghostscript \
	git \
	language-pack-en \
	libedit-dev \
	libgnutls28-dev \
	libidn2-0-dev \
	liblmdb-dev \
	libmaxminddb-dev \
	libsystemd-dev \
	libtool \
	liburcu-dev \
	pkg-config \
	python-sphinx \
	texinfo \
	texlive \
	texlive-font-utils \
	texlive-generic-extra \
	texlive-latex-extra \
	unzip
