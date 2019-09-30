srpm: tar spec-gen
	rpmbuild -bs ~/rpmbuild/SPECS/knot.spec
	cp -r ~/rpmbuild/SRPMS/* ${outdir}

spec-gen: tar
	./scripts/copr-spec.sh

tar:
	dnf install -y rpmdevtools libtool autoconf pkgconfig automake userspace-rcu-devel gnutls-devel libedit-devel lmdb-devel libcap-ng-devel systemd-devel libidn2-devel protobuf-c-devel fstrm-devel libmaxminddb-devel
	./autogen.sh
	./configure
	make dist


