srpm: generate-spec tar
	#tito tag --offline
	tito build --srpm --offline
	
generate-spec: tar
	./scripts/copr-spec.sh

tar:
	./autogen.sh
	./configure
	make dist


