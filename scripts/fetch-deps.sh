#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lib_dir="${root_dir}/lib"
mkdir -p "${lib_dir}"

download() {
  local url="$1"
  local out="$2"
  if [[ -f "${out}" ]]; then
    echo "[deps] present: ${out}"
    return
  fi
  echo "[deps] downloading ${url}"
  curl -fL --retry 3 -o "${out}" "${url}"
}

download "https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar" \
  "${lib_dir}/fastjson-1.2.83.jar"
download "https://repo1.maven.org/maven2/org/springframework/boot/spring-boot-loader/2.7.18/spring-boot-loader-2.7.18.jar" \
  "${lib_dir}/spring-boot-loader-2.7.18.jar"
download "https://repo1.maven.org/maven2/org/springframework/boot/spring-boot-loader/1.5.22.RELEASE/spring-boot-loader-1.5.22.RELEASE.jar" \
  "${lib_dir}/spring-boot-loader-1.5.22.RELEASE.jar"
download "https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar" \
  "${lib_dir}/asm-9.6.jar"

echo "[deps] done"
