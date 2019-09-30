srpm: tar spec-gen
	rpmbuild -bs ~/rpmbuild/SPECS/knot.spec
	cp -r ~/rpmbuild/SRPMS/* ${outdir}

spec-gen: tar
	./scripts/copr-spec.sh

tar:
	./autogen.sh
	./configure
	make dist


