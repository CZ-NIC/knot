%global _hardened_build 1
%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}-%{version}}

%define GPG_CHECK 0
%define VERSION __VERSION__

Summary: High-performance authoritative DNS server
Name: knot
Version: %{VERSION}
Release: 1%{?dist}
License: GPLv3
Group: System Environment/Daemons
URL: http://www.knot-dns.cz
Source0: %{name}_%{version}.orig.tar.xz

Source2: %{name}.service
Source3: %{name}.conf
Source4: %{name}.tmpfiles

%if 0%{GPG_CHECK}
Source1: http://public.nic.cz/files/knot-dns/%{name}-%{version}.tar.xz.asc
# PGP keys used to sign upstream releases
# Export with --armor using command from https://fedoraproject.org/wiki/PackagingDrafts:GPGSignatures
# Don't forget to update %%prep section when adding/removing keys
Source100: gpgkey-742FA4E95829B6C5EAC6B85710BB7AF6FEBBD6AB.gpg.asc
BuildRequires:  gnupg2
%endif

# Required dependencies
BuildRequires: pkgconfig(liburcu) pkgconfig(gnutls) >= 3.3 pkgconfig(nettle) lmdb-devel pkgconfig(libedit)
# Optional dependencies
BuildRequires: pkgconfig(libcap-ng) pkgconfig(libidn2) pkgconfig(libsystemd) pkgconfig(libfstrm) pkgconfig(libprotobuf-c)
BuildRequires: systemd

Requires: python-lmdb

Requires(post): python-lmdb
Requires(post): systemd %{_sbindir}/runuser
Requires(preun): systemd
Requires(postun): systemd

Requires: %{name}-libs%{?_isa} = %{version}-%{release}

%description
Knot DNS is a high-performance authoritative DNS server implementation.

%package libs
Summary: Libraries used by the Knot DNS server and client applications

%description libs
The package contains shared libraries used by the Knot DNS server and
utilities.

%package devel
Summary: Development header files for the Knot DNS libraries
Requires: %{name}-libs%{?_isa} = %{version}-%{release}

%description devel
The package contains development header files for the Knot DNS libraries
included in knot-libs package.

%package utils
Summary: DNS client utilities shipped with the Knot DNS server
Requires: %{name}-libs%{?_isa} = %{version}-%{release}

%description utils
The package contains DNS client utilities shipped with the Knot DNS server.

%package doc
Summary: Documentation for the Knot DNS server
License: GPLv3 and BSD and MIT
BuildArch: noarch
%if 0%{?rhel}
BuildRequires: python-sphinx
%else
BuildRequires: python3-sphinx
%endif
Provides: bundled(jquery) = 3.1.0

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

# make sure embedded LMDB library is not used
rm -vr src/contrib/lmdb

%build
# disable debug code (causes unused warnings)
CFLAGS="%{optflags} -DNDEBUG -Wno-unused"

%ifarch armv7hl i686
# 32-bit architectures sometimes do not have sufficient amount of
# contiguous address space to handle default values
%define configure_db_sizes --with-conf-mapsize=64 --with-timer-mapsize=16
%endif

%configure %{configure_db_sizes} --disable-fastparser  # FIXME
make %{?_smp_mflags}
make html

%install
make install DESTDIR=%{buildroot}

# install documentation
mkdir -p %{buildroot}%{_pkgdocdir}
cp -av doc/_build/html %{buildroot}%{_pkgdocdir}
[ -r %{buildroot}%{_pkgdocdir}/html/index.html ] || exit 1
rm -f %{buildroot}%{_pkgdocdir}/html/.buildinfo

# install customized configuration file
rm %{buildroot}%{_sysconfdir}/%{name}/*
install -p -m 0644 -D %{SOURCE3} %{buildroot}%{_sysconfdir}/%{name}/%{name}.conf

# install service file and create rundir
install -p -m 0644 -D %{SOURCE2} %{buildroot}%{_unitdir}/%{name}.service
install -p -m 0644 -D %{SOURCE4} %{buildroot}%{_tmpfilesdir}/%{name}.conf
install -d -m 0755 %{buildroot}%{_localstatedir}/run/%{name}

# create storage dir and key dir
mkdir -p %{buildroot}%{_sharedstatedir}
install -d -m 0775 %{buildroot}%{_sharedstatedir}/%{name}
install -d -m 0770 %{buildroot}%{_sharedstatedir}/%{name}/keys

# install config samples into docdir
install -d -m 0755 %{buildroot}%{_pkgdocdir}/samples
for sample_file in knot.sample.conf example.com.zone; do
    install -p -m 0644 samples/${sample_file} %{buildroot}%{_pkgdocdir}/samples
done

# remove static libraries and libarchive files
rm %{buildroot}%{_libdir}/*.a
rm %{buildroot}%{_libdir}/*.la

%check
make check

%pre
getent group knot >/dev/null || groupadd -r knot
getent passwd knot >/dev/null || useradd -r -g knot -d %{_sysconfdir}/knot -s /sbin/nologin -c "Knot DNS server" knot
exit 0

%post
%systemd_post knot.service
if [ $1 -gt 1 ] ; then  # upgrade
    if rpm -q --qf=%%{version} knot | grep -q "^1\." ; then  # detect versions 1.y.z
        echo 'Automatic upgrade from Knot DNS versions 1.y.z is not supported anymore'
        echo 'Contact https://www.knot-dns.cz/support/'
        exit 1
    fi

    # 2.[0-4].z -> 2.5+.z migration
    if rpm -q --qf=%%{version} knot | grep -q '^2.[0-4]\.' ; then
        # rename modules
        echo 'Migrating module names in configuration file /etc/knot/knot.conf'
        sed -i.rpmsave -e 's/\bmod-online-sign\b/mod-onlinesign/' -e 's/\bmod-synth-record\b/mod-synthrecord/' /etc/knot/knot.conf
        echo 'Migrating KASP database %{_sharedstatedir}/%{name}/keys from JSON files to LMDB database'
        # migrate keys into LMDB
        %{_sbindir}/runuser -u knot -- %{_sbindir}/pykeymgr -i %{_sharedstatedir}/%{name}/keys
    fi
fi


%preun
%systemd_preun knot.service

%postun
%systemd_postun_with_restart knot.service

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%files
%{_pkgdocdir}/samples
%dir %attr(750,root,knot) %{_sysconfdir}/%{name}
%config(noreplace) %attr(640,root,knot) %{_sysconfdir}/%{name}/%{name}.conf
%dir %attr(775,root,knot) %{_sharedstatedir}/%{name}
%dir %attr(770,root,knot) %{_sharedstatedir}/%{name}/keys
%dir %attr(-,knot,knot) %{_localstatedir}/run/%{name}
%{_unitdir}/%{name}.service
%{_tmpfilesdir}/%{name}.conf
%{_bindir}/kjournalprint
%{_bindir}/kzonecheck
%{_sbindir}/keymgr
%{_sbindir}/knotc
%{_sbindir}/knotd
%{_sbindir}/pykeymgr
%{_mandir}/man1/kjournalprint.*
%{_mandir}/man1/kzonecheck.*
%{_mandir}/man5/knot.conf.*
%{_mandir}/man8/keymgr.*
%{_mandir}/man8/knotc.*
%{_mandir}/man8/knotd.*
%{_mandir}/man8/pykeymgr.*

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
%doc COPYING NEWS
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
