srpm: tar spec
	echo "rpkg srpm -bs ${spec}"

spec: tar
	./scripts/copr-spec.sh ${spec}

tar:
	./autogen.sh
	./configure
	make dist


