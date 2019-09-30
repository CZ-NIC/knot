srpm: generate-spec tar
	#tito tag --offline
	tito build --test  --srpm --output=$(outdir) 
	
generate-spec: tar
	./scripts/copr-spec.sh

tar:
	./autogen.sh
	./configure
	make dist


