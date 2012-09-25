#!/bin/bash

mkdir /tmp/tests

separation="========================================================="

echo $separation

for file in `/usr/bin/find ./tests/ -name "*.in" | /usr/bin/sort`; do
	fileout=`echo "$file" | /bin/sed 's/.in/.out/'`
	../../unittests-zscanner -m 2 . $file > /tmp/$fileout
	/bin/sed --in-place 's/Zone processing has stopped.*//' /tmp/$fileout
	echo $fileout
	diff /tmp/$fileout $fileout
	echo $separation
done
