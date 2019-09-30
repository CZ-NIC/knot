srpm: tar spec-gen
	rpmbuild -bs ~/rpmbuild/SPECS/${spec}
	cp -r ~/rpmbuild/SRPMS/* ${outdir}/

spec-gen: tar
	./scripts/copr-spec.sh ${spec}

tar:
	./autogen.sh
	./configure
	make dist


