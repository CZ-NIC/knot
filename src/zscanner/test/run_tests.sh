#!/bin/bash

for file in `/usr/bin/find ./tests/ -name "*.in" | /usr/bin/sort`; do
    fileout=`echo "$file" | /bin/sed 's/.in/.out/'`
    ../../unittests-zscanner -m 2 . $file > /tmp/_zscanner_test
#    ../../unittests-zscanner -m 2 . $file > /tmp/$fileout
    diff /tmp/_zscanner_test $fileout
done
