FROM debian:stable-slim
LABEL maintainer="Knot DNS <knot-dns@labs.nic.cz>"
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update
RUN apt-get -y dist-upgrade
RUN apt-get -y install \
	apt-utils \
	autoconf \
	automake \
	autotools-dev \
	build-essential \
	clang \
	curl \
	ghostscript \
	git \
	latexmk \
	libbpf-dev \
	libedit-dev \
	libfstrm-dev \
	libgnutls28-dev \
	libidn2-dev \
	liblmdb-dev \
	libmaxminddb-dev \
	libmnl-dev \
	libnghttp2-dev \
	libprotobuf-c-dev \
	libsystemd-dev \
	libtool \
	liburcu-dev \
	libxdp-dev \
	llvm \
	locales-all \
	pkg-config \
	protobuf-c-compiler \
	python3-sphinx \
	python3-sphinx-panels \
	texlive \
	texlive-font-utils \
	texlive-latex-extra \
	unzip \
	xxd
