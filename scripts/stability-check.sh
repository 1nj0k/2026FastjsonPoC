#!/usr/bin/env bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"
# shellcheck disable=SC1091
source scripts/common.sh
java_bin="${JAVA:-java}"
n="${1:-10}"
mode="${2:-sb27-parse}"
unset JAVA_TOOL_OPTIONS || true

if [[ ! -d target/classes ]]; then
  bash scripts/build-harness.sh
fi

pass=0
fail=0
for i in $(seq 1 "$n"); do
  python3 -c "from pathlib import Path; Path('PWNED2').unlink(missing_ok=True)"
  set +e
  out="$("${java_bin}" "${POC_JAVA_OPTS[@]}" -Dpoc.hostToken="${POC_HOST_TOKEN:-localhost}" \
    -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-2.7.18.jar:lib/asm-9.6.jar" \
    Test2 "${mode}" 2>&1)"
  ec=$?
  set -e
  if [[ $ec -eq 0 && -f PWNED2 ]]; then
    pass=$((pass+1))
    echo "RUN ${i}/${n}: PASS"
  else
    fail=$((fail+1))
    echo "RUN ${i}/${n}: FAIL exit=${ec}"
    echo "$out" | tail -25
  fi
done
echo "==== summary: pass=${pass} fail=${fail} total=${n} ===="
[[ $fail -eq 0 ]]
