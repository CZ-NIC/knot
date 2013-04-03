#!/bin/sh

TESTS_DIR="./tests"
OUTS_DIR="/tmp/zscanner_tests"
TEST_BIN="../../zscanner-tool -m 2"

# If verbose (default - no parameter) mode.
if [ $# -eq 0 ]; then
	echo "Launching zscanner tests"
fi

# Create output directory and copy include zone files.
mkdir -p ${OUTS_DIR}/${TESTS_DIR}
cp -r ${TESTS_DIR}/includes ${OUTS_DIR}

# Run zscanner on all test zone files.
for file in `find ${TESTS_DIR} -name "*.in" | sort`; do
	fileout=`echo "${file}" | sed 's/.in/.out/'`

	# Run zscanner.
	${TEST_BIN} . ${file} > ${OUTS_DIR}/${fileout}

	# Compare result with a reference one.
	cmp ${OUTS_DIR}/${fileout} ${fileout} > /dev/null 2>&1

	# Check for differences.
	if [ $? -ne 0 ]; then
		# If verbose print diff.
		if [ $# -eq 0 ]; then
			echo "\n=== ${fileout} DIFF ======================"
			diff ${OUTS_DIR}/${fileout} ${fileout}
		# Return error and exit.
		else
			return 1
		fi
	fi
done

if [ $# -eq 0 ]; then
	echo "\nFinished"
fi

