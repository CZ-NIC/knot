#!/usr/bin/env bash

cb() {
	echo "$1 [${@:2}]"
}

gdbus monitor --system --dest cz.nic.knotd --object-path /cz/nic/knotd \
	| awk '/^\/cz\/nic\/knotd/ {
		gsub("cz.nic.knotd.events.", "", $2);
		tmp="";
		for(i=3;i<=NF;++i) {
			if( $i ~ /[\),]$/ ) tmp=tmp$i;
		}
		gsub(/(^\()|(\)$)/, "", tmp);
		split(tmp, args, ",");
		printf "%s ", $2;
		for (i in args) printf "%s ", args[i];
		print "";
		fflush(stdout); }' \
	| while read line; do \
		cb ${line[@]}; \
	done
