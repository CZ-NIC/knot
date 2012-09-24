#!/bin/bash

separation="========================================================="

echo $separation

for file in `/usr/bin/find ./tests/ -name "*.in" | /usr/bin/sort`; do
	fileout=`echo "$file" | /bin/sed 's/.in/.out/'`
	../../unittests-zscanner -m 2 . $file > /tmp/_zscanner_test
	/bin/sed --in-place 's/Zone processing has stopped.*//' /tmp/_zscanner_test
#	../../unittests-zscanner -m 2 . $file > /tmp/$fileout
	echo $fileout
	diff /tmp/_zscanner_test $fileout
	echo $separation
done
