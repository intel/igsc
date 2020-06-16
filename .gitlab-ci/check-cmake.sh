#!/bin/sh
FILES=`find  -name "*.cmake" -o -name "CMakeLists.txt"`
[ -z "$FILES" ] && { exit 0; }
for file in $FILES; do
	cmake-lint ${file}
done
