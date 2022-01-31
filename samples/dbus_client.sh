#!/usr/bin/env bash

cb() {
	p1=$1;
	shift;
	echo "$p1 [$@]"
}

gdbus monitor --system --dest cz.nic.knotd --object-path /cz/nic/knotd \
	| awk '/^\/cz\/nic\/knotd/ {
		gsub("cz.nic.knotd.events.", "", $2);
		tmp="";
		for(i=3;i<=NF;++i) {
			if( $i ~ /[\),]$/ ) tmp=tmp$i;
		}
		gsub(/(^\()|(\)$)/, "", tmp);
		items=split(tmp, args, ",");
		printf "%s ", $2;
		for(i=1;i<=items;i++) printf "%s ", args[i];
		print "";
		fflush(stdout); }' \
	| while read line; do \
		cb ${line[@]}; \
	done
