%global _hardened_build 1
%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}}

%define GPG_CHECK 0
%define BASE_VERSION %(echo "%{version}" | sed 's/^\\([^.]\\+\\.[^.]\\+\\).*/\\1/')
%define repodir %{_builddir}/%{name}-%{version}

Summary:	High-performance authoritative DNS server
Name:		knot
Version:	{{ version }}
Release:	cznic.{{ release }}%{?dist}
License:	GPL-3.0-or-later
URL:		https://www.knot-dns.cz
Source0:	%{name}-%{version}.tar.xz

%if 0%{?GPG_CHECK}
Source1:	https://secure.nic.cz/files/knot-dns/%{name}-%{version}.tar.xz.asc
# PGP keys used to sign upstream releases
# Export with --armor using command from https://fedoraproject.org/wiki/PackagingDrafts:GPGSignatures
# Don't forget to update %%prep section when adding/removing keys
Source100:	gpgkey-742FA4E95829B6C5EAC6B85710BB7AF6FEBBD6AB.gpg.asc
BuildRequires:	gnupg2
%endif

# Test fails on F30+ aarch/s390x for unknown reason, but it is not neccassary for Knot DNS
Patch1:		01-disable-unconnected-net-test.patch
Patch2:		02-revert-AC_PROG_CC.patch

# Required dependencies
BuildRequires:	autoconf
BuildRequires:	automake
BuildRequires:	libtool
BuildRequires:	make
BuildRequires:	gcc
BuildRequires:	pkgconfig(liburcu)
BuildRequires:	pkgconfig(gnutls) >= 3.3
BuildRequires:	pkgconfig(libedit)

# Optional dependencies
BuildRequires:	pkgconfig(libcap-ng)
BuildRequires:	pkgconfig(libidn2)
BuildRequires:	pkgconfig(libmnl)
BuildRequires:	pkgconfig(libnghttp2)
BuildRequires:	pkgconfig(libsystemd)
BuildRequires:	pkgconfig(systemd)
# dnstap dependencies
BuildRequires:	pkgconfig(libfstrm)
BuildRequires:	pkgconfig(libprotobuf-c)
# geoip dependencies
BuildRequires:	pkgconfig(libmaxminddb)

# Distro-dependent dependencies
%if 0%{?suse_version}
BuildRequires:	python3-Sphinx
BuildRequires:	lmdb-devel
BuildRequires:	protobuf-c
Requires(pre):	pwdutils
%endif
%if 0%{?rhel} && 0%{?rhel} <= 7
BuildRequires:	python-sphinx
BuildRequires:	lmdb-devel
%endif
%if 0%{?fedora} || 0%{?rhel} > 7
BuildRequires:	python3-sphinx
BuildRequires:	pkgconfig(lmdb)
%endif

%if 0%{?centos} == 7 || 0%{?rhel} == 7
# disable XDP on old EL
%define configure_xdp --enable-xdp=no
%else
%define use_xdp 1
%if 0%{?rhel} >= 8 || 0%{?suse_version}
# enable XDP on recent EL using embedded libbpf
%define use_xdp 1
%define configure_xdp --enable-xdp=yes
BuildRequires:	pkgconfig(libelf)
%else
# XDP is auto-enabled when libbpf is present
BuildRequires:  pkgconfig(libbpf) >= 0.0.6
%endif
%endif

Requires(post):		systemd %{_sbindir}/runuser
Requires(preun):	systemd
Requires(postun):	systemd

# Knot DNS 2.7+ isn't compatible with earlier knot-resolver
Conflicts:	knot-resolver < 3.0.0

Requires:	%{name}-libs%{?_isa} = %{version}-%{release}

%description
Knot DNS is a high-performance authoritative DNS server implementation.

%package libs
Summary:	Libraries used by the Knot DNS server and client applications

%description libs
The package contains shared libraries used by the Knot DNS server and
utilities.

%package devel
Summary:	Development header files for the Knot DNS libraries
Requires:	%{name}-libs%{?_isa} = %{version}-%{release}

%description devel
The package contains development header files for the Knot DNS libraries
included in knot-libs package.

%package utils
Summary:	DNS client utilities shipped with the Knot DNS server
Requires:	%{name}-libs%{?_isa} = %{version}-%{release}

%description utils
The package contains DNS client utilities shipped with the Knot DNS server.

%package module-dnstap
Summary:	dnstap module for Knot DNS
Requires:	%{name} = %{version}-%{release}

%description module-dnstap
The package contains dnstap Knot DNS module for logging DNS traffic.

%package module-geoip
Summary:	geoip module for Knot DNS
Requires:	%{name} = %{version}-%{release}

%description module-geoip
The package contains geoip Knot DNS module for geography-based responses.

%package doc
Summary:	Documentation for the Knot DNS server
BuildArch:	noarch
Provides:	bundled(jquery) = 3.1.0

%description doc
The package contains documentation for the Knot DNS server.
On-line version is available on https://www.knot-dns.cz/documentation/

%prep
%if 0%{?GPG_CHECK}
export GNUPGHOME=./gpg-keyring
[ -d ${GNUPGHOME} ] && rm -r ${GNUPGHOME}
mkdir --mode=700 ${GNUPGHOME}
gpg2 --import %{SOURCE100}
gpg2 --verify %{SOURCE1} %{SOURCE0}
%endif
%autosetup -p1

%build
# disable debug code (causes unused warnings)
CFLAGS="%{optflags} -DNDEBUG -Wno-unused"

%ifarch armv7hl i686
# 32-bit architectures sometimes do not have sufficient amount of
# contiguous address space to handle default values
%define configure_db_sizes --with-conf-mapsize=64
%endif

autoreconf -if

%configure \
  --sysconfdir=/etc \
  --localstatedir=/var/lib \
  --libexecdir=/usr/lib/knot \
  --with-rundir=/run/knot \
  --with-moduledir=%{_libdir}/knot/modules-%{BASE_VERSION} \
  --with-storage=/var/lib/knot \
  %{?configure_db_sizes} \
  %{?configure_xdp} \
  --disable-static \
  --enable-dnstap=yes \
  --with-module-dnstap=shared \
  --with-module-geoip=shared
make %{?_smp_mflags}
make html

%install
make install DESTDIR=%{buildroot}

# install documentation
install -d -m 0755 %{buildroot}%{_pkgdocdir}/samples
install -p -m 0644 -t %{buildroot}%{_pkgdocdir}/samples samples/*.zone*
install -p -m 0644 NEWS README.md %{buildroot}%{_pkgdocdir}
cp -av doc/_build/html %{buildroot}%{_pkgdocdir}
[ -r %{buildroot}%{_pkgdocdir}/html/index.html ] || exit 1
rm -f %{buildroot}%{_pkgdocdir}/html/.buildinfo

# install daemon and dbus configuration files
rm %{buildroot}%{_sysconfdir}/%{name}/*
install -p -m 0644 -D %{repodir}/samples/%{name}.sample.conf %{buildroot}%{_sysconfdir}/%{name}/%{name}.conf
%if 0%{?fedora} || 0%{?rhel} > 7
install -p -m 0644 -D %{repodir}/distro/common/cz.nic.knotd.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/cz.nic.knotd.conf
%endif

# install systemd files
install -p -m 0644 -D %{repodir}/distro/pkg/el-7/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -p -m 0644 -D %{repodir}/distro/pkg/el-7/%{name}.tmpfiles %{buildroot}%{_tmpfilesdir}/%{name}.conf
%if 0%{?suse_version}
ln -s service %{buildroot}/%{_sbindir}/rcknot
%endif

# create storage dir
install -d %{buildroot}%{_sharedstatedir}
install -d -m 0770 -D %{buildroot}%{_sharedstatedir}/knot

# remove libarchive files
find %{buildroot} -type f -name "*.la" -delete -print

%check
V=1 make check

%pre
getent group knot >/dev/null || groupadd -r knot
getent passwd knot >/dev/null || \
  useradd -r -g knot -d %{_sharedstatedir}/knot -s /sbin/nologin \
  -c "Knot DNS server" knot
%if 0%{?suse_version}
%service_add_pre knot.service
%endif

%post
systemd-tmpfiles --create %{_tmpfilesdir}/knot.conf &>/dev/null || :
%if 0%{?suse_version}
%service_add_post knot.service
%else
%systemd_post knot.service
%endif

%preun
%if 0%{?suse_version}
%service_del_preun knot.service
%else
%systemd_preun knot.service
%endif

%postun
%if 0%{?suse_version}
%service_del_postun knot.service
%else
%systemd_postun_with_restart knot.service
%endif

%if 0%{?fedora} || 0%{?rhel} > 7
# https://fedoraproject.org/wiki/Changes/Removing_ldconfig_scriptlets
%else
%post libs -p /sbin/ldconfig
%postun libs -p /sbin/ldconfig
%endif

%files
%license COPYING
%doc %{_pkgdocdir}
%exclude %{_pkgdocdir}/html
%attr(770,root,knot) %dir %{_sysconfdir}/knot
%config(noreplace) %attr(640,root,knot) %{_sysconfdir}/knot/knot.conf
%if 0%{?fedora} || 0%{?rhel} > 7
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/dbus-1/system.d/cz.nic.knotd.conf
%endif
%attr(770,root,knot) %dir %{_sharedstatedir}/knot
%dir %{_libdir}/knot
%dir %{_libdir}/knot/modules-*
%{_unitdir}/knot.service
%{_tmpfilesdir}/knot.conf
%{_bindir}/kzonecheck
%{_bindir}/kzonesign
%{_sbindir}/kcatalogprint
%{_sbindir}/kjournalprint
%{_sbindir}/keymgr
%{_sbindir}/knotc
%{_sbindir}/knotd
%if 0%{?suse_version}
%{_sbindir}/rcknot
%endif
%{_mandir}/man1/kzonecheck.*
%{_mandir}/man1/kzonesign.*
%{_mandir}/man5/knot.conf.*
%{_mandir}/man8/kcatalogprint.*
%{_mandir}/man8/kjournalprint.*
%{_mandir}/man8/keymgr.*
%{_mandir}/man8/knotc.*
%{_mandir}/man8/knotd.*
%ghost %attr(770,root,knot) %dir %{_rundir}/knot

%files utils
%{_bindir}/kdig
%{_bindir}/khost
%{_bindir}/knsec3hash
%{_bindir}/knsupdate
%if 0%{?use_xdp}
%{_sbindir}/kxdpgun
%{_mandir}/man8/kxdpgun.*
%endif
%{_mandir}/man1/kdig.*
%{_mandir}/man1/khost.*
%{_mandir}/man1/knsec3hash.*
%{_mandir}/man1/knsupdate.*

%files module-dnstap
%{_libdir}/knot/modules-*/dnstap.so

%files module-geoip
%{_libdir}/knot/modules-*/geoip.so

%files libs
%license COPYING
%doc NEWS
%doc README.md
%{_libdir}/libdnssec.so.*
%{_libdir}/libknot.so.*
%{_libdir}/libzscanner.so.*

%files devel
%{_includedir}/libdnssec
%{_includedir}/knot
%{_includedir}/libknot
%{_includedir}/libzscanner
%{_libdir}/libdnssec.so
%{_libdir}/libknot.so
%{_libdir}/libzscanner.so
%{_libdir}/pkgconfig/knotd.pc
%{_libdir}/pkgconfig/libdnssec.pc
%{_libdir}/pkgconfig/libknot.pc
%{_libdir}/pkgconfig/libzscanner.pc

%files doc
%dir %{_pkgdocdir}
%doc %{_pkgdocdir}/html

%changelog
* {{ now }} Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-{{ release }}
- upstream package
- see https://www.knot-dns.cz
