Summary: KNOT DNS daemon
Name: knot
Version: 0.8
Release: 1
License: GPL
Group: Networking/Daemons
Source: http://public.nic.cz/files/knot-dns/knot-0.8.tar.gz
Source1: knot.init
Buildroot: /var/tmp/knot-root
Url: http://www.knot-dns.cz
#Prereq: /sbin/chkconfig
BuildRequires: flex userspace-rcu-devel openssl-devel

%description
KNOT DNS is a high-performance authoritative DNS server implementation.

%prep
%setup -n %{name}-%{version}
#%patch -p1


%build
./configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir}/%{name} --localstatedir=%{_var}/lib --libexecdir=%{_libexecdir}/%{name}
make -C samples knot.sample.conf
make


%install
rm -rf %{buildroot}/*
make install prefix=%{buildroot}/%{_prefix} sysconfdir=%{buildroot}/%{_sysconfdir}/%{name} localstatedir=%{buildroot}/%{_var}/lib mandir=%{buildroot}/%{_mandir} libexecdir=%{buildroot}/%{_libexecdir}/%{name}

install -d %{buildroot}/%{_sysconfdir}/init.d
install $RPM_SOURCE_DIR/%{name}.init %{buildroot}/%{_sysconfdir}/init.d/%{name}
install -d %{buildroot}/%{_var}/lib/%{name}

%post
/sbin/ldconfig
/sbin/chkconfig --add %{name}
 
%preun
if [ $1 = 0 ] ; then
        /sbin/chkconfig --del %{name}
fi 

%files
%defattr(-,root,root,-)
%config %attr(644,root,root) %{_sysconfdir}/%{name}/*
%{_sbindir}/*
%{_libexecdir}/%{name}/*
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%dir %{_var}/lib/%{name}/
%doc %{_mandir}/man8/*

%changelog

