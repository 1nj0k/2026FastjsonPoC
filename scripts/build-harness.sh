#!/usr/bin/env bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"
scripts/fetch-deps.sh
mkdir -p target/classes target/crafted
javac_bin="${JAVAC:-javac}"
java_bin="${JAVA:-java}"
port="${POC_PORT:-18080}"
host="${POC_HOST_TOKEN:-localhost}"
unset JAVA_TOOL_OPTIONS || true

if "${javac_bin}" --help 2>&1 | grep -q -- "--release"; then
  compile_level=(--release 8)
else
  compile_level=(-source 8 -target 8)
fi

echo "[build] javac=$(${javac_bin} -version 2>&1) java=$(${java_bin} -version 2>&1 | head -1)"
"${javac_bin}" "${compile_level[@]}" -encoding UTF-8 -cp "lib/*" -d target/classes src/main/java/*.java
"${java_bin}" -cp "target/classes:lib/asm-9.6.jar" Gen --port "${port}" --host "${host}" --out probe.jar
echo "[build] classes compiled under target/classes"
echo "[build] crafted probe jar written to probe.jar (host=${host} port=${port})"
