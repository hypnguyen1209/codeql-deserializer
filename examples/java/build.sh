#!/usr/bin/env bash
# Build a CodeQL database for the Java deserialization demo target.
set -e
cd "$(dirname "$0")/src"
rm -rf ../classes && mkdir -p ../classes
find . -name '*.java' > ../sources.txt
"${CODEQL_JAVA_HOME:=JAVA_HOME}/bin/javac" -d ../classes @../sources.txt
