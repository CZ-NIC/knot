#!/bin/sh
# This script generates resource files.
# Usage: ./resource.sh <file>
# Resource file is printed to stdout.
# Usable variables (<file> is stripped from path and extension):
#    const char *<file>_rc; // File content in binary format
#    const unsigned <file_rc_size; // File size
# Examples:
#    (file: dumps/test.out content: "ahoj")
#    ./resource.sh dumps/test.out
#    static const unsigned test_rc_size = 4;
#    static const char test_rc[] = { 'a', 'h', 'o', 'j', '\0' };

hd="hexdump -v -e"
fmt="\"0\" \"x\" 1/1 \"%02X\" \", \""

# Preparse source file name
header="${1%.*}_rc"
header=`basename ${header}`

# Get file size and dump content
size=`wc -c ${1} | awk '{print $1}' 2>/dev/null`
dump=`${hd} "${fmt}" ${1} 2>/dev/null`

# Format file size variable
echo "static const unsigned ${header}_size = ${size};"

# Format file content dump
echo "static const char ${header}[] = { "
echo "${dump}0x00 };"
