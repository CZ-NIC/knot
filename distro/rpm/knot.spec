%global _hardened_build 1
%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}}

%define GPG_CHECK 0
%define VERSION __VERSION__

Summary:	High-performance authoritative DNS server
Name:		knot
Version:	%{VERSION}
Release:	1%{?dist}
License:	GPLv3
URL:		http://www.knot-dns.cz
Source0:	%{name}_%{version}.orig.tar.xz

Source2:	%{name}.service
Source3:	%{name}.tmpfiles

%if 0%{GPG_CHECK}
Source1:	http://public.nic.cz/files/knot-dns/%{name}-%{version}.tar.xz.asc
# PGP keys used to sign upstream releases
# Export with --armor using command from https://fedoraproject.org/wiki/PackagingDrafts:GPGSignatures
# Don't forget to update %%prep section when adding/removing keys
Source100:	gpgkey-742FA4E95829B6C5EAC6B85710BB7AF6FEBBD6AB.gpg.asc
BuildRequires:	gnupg2
%endif

# Required dependencies
BuildRequires:	gcc
BuildRequires:	pkgconfig(liburcu)
BuildRequires:	pkgconfig(gnutls) >= 3.3
BuildRequires:	pkgconfig(libedit)

# Optional dependencies
BuildRequires:	pkgconfig(libcap-ng)
BuildRequires:	pkgconfig(libfstrm)
BuildRequires:	pkgconfig(libidn2)
BuildRequires:	pkgconfig(libmaxminddb)
BuildRequires:	pkgconfig(libprotobuf-c)
BuildRequires:	pkgconfig(libsystemd)
BuildRequires:	pkgconfig(systemd)

# Distro-dependent dependencies
%if 0%{?suse_version}
BuildRequires:	python3-Sphinx
BuildRequires:	lmdb-devel
BuildRequires:	protobuf-c
Requires(pre):  pwdutils
%endif
%if 0%{?rhel}
BuildRequires:	python-sphinx
BuildRequires:	lmdb-devel
%endif
%if 0%{?fedora}
BuildRequires:	python3-sphinx
BuildRequires:	pkgconfig(lmdb)
%endif

Requires(post):		systemd %{_sbindir}/runuser
Requires(preun):	systemd
Requires(postun):	systemd

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

%package doc
Summary:	Documentation for the Knot DNS server
License:	GPLv3 and BSD and MIT
BuildArch:	noarch
Provides:	bundled(jquery) = 3.1.0

%description doc
The package contains documentation for the Knot DNS server.
On-line version is available on https://www.knot-dns.cz/documentation/

%prep
%if 0%{GPG_CHECK}
export GNUPGHOME=./gpg-keyring
mkdir ${GNUPGHOME}
gpg2 --import %{SOURCE100}
gpg2 --verify %{SOURCE1} %{SOURCE0}
%endif
%setup -q

%build
# disable debug code (causes unused warnings)
CFLAGS="%{optflags} -DNDEBUG -Wno-unused"

%ifarch armv7hl i686
# 32-bit architectures sometimes do not have sufficient amount of
# contiguous address space to handle default values
%define configure_db_sizes --with-conf-mapsize=64
%endif

%configure \
  --sysconfdir=/etc \
  --localstatedir=/var/lib \
  --libexecdir=/usr/lib/knot \
  --with-rundir=/run/knot \
  --with-storage=/var/lib/knot \
  %{?configure_db_sizes} \
  --disable-static \
  --enable-dnstap=yes \
  --with-module-dnstap=yes
make %{?_smp_mflags}
make html

%install
make install DESTDIR=%{buildroot}

# install documentation
install -d -m 0755 %{buildroot}%{_pkgdocdir}/samples
install -p -m 0644 -t %{buildroot}%{_pkgdocdir}/samples samples/*.zone*
install -p -m 0644 NEWS README %{buildroot}%{_pkgdocdir}
cp -av doc/_build/html %{buildroot}%{_pkgdocdir}
[ -r %{buildroot}%{_pkgdocdir}/html/index.html ] || exit 1
rm -f %{buildroot}%{_pkgdocdir}/html/.buildinfo

# install configuration file
rm %{buildroot}%{_sysconfdir}/%{name}/*
install -p -m 0644 -D samples/%{name}.sample.conf %{buildroot}%{_sysconfdir}/%{name}/%{name}.conf

# install systemd files
install -p -m 0644 -D %{SOURCE2} %{buildroot}%{_unitdir}/%{name}.service
install -p -m 0644 -D %{SOURCE3} %{buildroot}%{_tmpfilesdir}/%{name}.conf

# create storage dir and key dir
install -d %{buildroot}%{_sharedstatedir}
install -d -m 0775 -D %{buildroot}%{_sharedstatedir}/%{name}
install -d -m 0770 -D %{buildroot}%{_sharedstatedir}/%{name}/keys

# remove libarchive files
find %{buildroot} -type f -name "*.la" -delete -print

%check
make check

%pre
getent group knot >/dev/null || groupadd -r knot
getent passwd knot >/dev/null || \
  useradd -r -g knot -d %{_sysconfdir}/knot -s /sbin/nologin \
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

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%files
%license COPYING
%{_pkgdocdir}/NEWS
%{_pkgdocdir}/README
%{_pkgdocdir}/samples
%dir %attr(750,root,knot) %{_sysconfdir}/%{name}
%config(noreplace) %attr(640,root,knot) %{_sysconfdir}/%{name}/%{name}.conf
%dir %attr(775,root,knot) %{_sharedstatedir}/%{name}
%dir %attr(770,root,knot) %{_sharedstatedir}/%{name}/keys
%{_unitdir}/knot.service
%{_tmpfilesdir}/%{name}.conf
%{_bindir}/kzonecheck
%{_sbindir}/kjournalprint
%{_sbindir}/keymgr
%{_sbindir}/knotc
%{_sbindir}/knotd
%{_mandir}/man1/kzonecheck.*
%{_mandir}/man5/knot.conf.*
%{_mandir}/man8/kjournalprint.*
%{_mandir}/man8/keymgr.*
%{_mandir}/man8/knotc.*
%{_mandir}/man8/knotd.*

%files utils
%{_bindir}/kdig
%{_bindir}/khost
%{_bindir}/knsec3hash
%{_bindir}/knsupdate
%{_mandir}/man1/kdig.*
%{_mandir}/man1/khost.*
%{_mandir}/man1/knsec3hash.*
%{_mandir}/man1/knsupdate.*

%files libs
%license COPYING
%doc NEWS
%doc README
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
%{_pkgdocdir}/html

%changelog
* Wed Feb 21 2018 Tomas Krizek <tomas.krizek@nic.cz> - 2.6.5-1
- move spec upstream
- see NEWS or https://knot-dns.cz
