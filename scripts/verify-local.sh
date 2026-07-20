#!/usr/bin/env bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

if [[ ! -f probe.jar ]]; then
  bash scripts/build-harness.sh
fi

python3 -c "from pathlib import Path; Path('PWNED2').unlink(missing_ok=True)"

echo "[verify] java = $(java -version 2>&1 | head -1)"
echo "[verify] running Test2 sb27-parse ..."
java -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-2.7.18.jar" Test2 sb27-parse

if [[ -f PWNED2 ]]; then
  echo "[verify] SUCCESS: pure parse RCE confirmed (PWNED2 exists)"
  exit 0
fi

echo "[verify] PWNED2 missing. On JDK9+ this is expected (SSRF-only). Use JDK8 for full RCE."
exit 2
