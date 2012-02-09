Summary: KNOT DNS daemon
Name: knot
Version: 0.9.1
Release: 1
License: GPL
Group: Networking/Daemons
Source: http://public.nic.cz/files/knot-dns/knot-%{version}.tar.gz
Source1: %{name}.sysconfig
Source2: %{name}.service
Patch: %{name}.diff
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-build
Url: http://www.knot-dns.cz
BuildRequires: flex userspace-rcu-devel openssl-devel bison

%description
KNOT DNS is a high-performance authoritative DNS server implementation.

%prep
%setup -n %{name}-%{version}
%patch -p1


%build
./configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir}/%{name} --localstatedir=%{_var}/lib --libexecdir=%{_libexecdir}/%{name}
make -C samples %{name}.sample.conf
make


%install
rm -rf %{buildroot}/*
make install prefix=%{buildroot}/%{_prefix} sysconfdir=%{buildroot}/%{_sysconfdir}/%{name} localstatedir=%{buildroot}/%{_var}/lib mandir=%{buildroot}/%{_mandir} libexecdir=%{buildroot}/%{_libexecdir}/%{name}

install -d %{buildroot}/%{_sysconfdir}/sysconfig
install $RPM_SOURCE_DIR/%{name}.sysconfig %{buildroot}/%{_sysconfdir}/sysconfig/%{name}
install -d %{buildroot}/%{_var}/lib/%{name}
install -d %{buildroot}/lib/systemd/system/
install $RPM_SOURCE_DIR/%{name}.service %{buildroot}/lib/systemd/system/%{name}.service

%post
# run after an installation
if [ $1 -eq 1 ] ; then
    # Initial installation
    /bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
# run before a package is removed
if [ $1 -eq 0 ]; then
    /bin/systemctl --no-reload disable %{name}.service >/dev/null 2>&1 || :
    /bin/systemctl stop %{name}.service > /dev/null 2>&1 || :
fi

%postun
# run after a package is removed
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ]; then
    /bin/systemctl try-restart %{name}.service >/dev/null 2>&1 || :
fi

%triggerun -- knot < 0.9
# Save the current service runlevel info
# User must manually run systemd-sysv-convert --apply %{name}
# to migrate them to systemd targets
/usr/bin/systemd-sysv-convert --save %{name}

/sbin/chkconfig --del %{name} >/dev/null 2>&1 || :
/bin/systemctl try-restart %{name}.service >/dev/null 2>&1 || :
/bin/systemctl daemon-reload >/dev/null 2>&1 || :



%files
%defattr(-,root,root,-)
%config %attr(644,root,root) %{_sysconfdir}/%{name}/*
%{_sbindir}/*
%{_libexecdir}/%{name}/*
%dir %{_var}/lib/%{name}/
%doc %{_mandir}/man8/*
%attr(0644,root,root) /lib/systemd/system/%{name}.service
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}



%changelog
* Mon Jan 16 2012 - feela@network.cz
- Support for systemd.
- Specfile cleanup

* Thu Nov 3 2011 - feela@network.cz
- Initial version

