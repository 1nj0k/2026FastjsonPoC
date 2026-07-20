#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编译并启动本地 Fastjson 1.2.83 漏洞 HTTP 服务（127.0.0.1:18080）。"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA_DIR = ROOT / "java"
JAR = JAVA_DIR / "fastjson-1.2.83.jar"
SRC = JAVA_DIR / "VulnServer.java"
MAVEN_URL = "https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.83/fastjson-1.2.83.jar"
DEFAULT_PORT = "18080"


def ensure_jar() -> Path:
    if JAR.exists() and JAR.stat().st_size > 100_000:
        print(f"[+] jar: {JAR}")
        return JAR
    print("[*] downloading fastjson-1.2.83.jar ...")
    JAR.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(MAVEN_URL, JAR)
    print(f"[+] downloaded: {JAR}")
    return JAR


def main() -> int:
    port = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PORT
    for bin_name in ("javac", "java"):
        if not shutil.which(bin_name):
            print(f"[-] missing: {bin_name}")
            return 1
    if not SRC.exists():
        print(f"[-] missing source: {SRC}")
        return 1

    jar = ensure_jar()
    work = Path(tempfile.mkdtemp(prefix="fj_vuln_server_"))
    print(f"[*] workdir: {work}")
    shutil.copy2(SRC, work / "VulnServer.java")

    compile_cmd = ["javac", "-cp", str(jar), "VulnServer.java"]
    print("[*] compile:", " ".join(compile_cmd))
    subprocess.run(compile_cmd, cwd=work, check=True)

    run_cmd = [
        "java",
        "--add-opens",
        "java.desktop/java.beans=ALL-UNNAMED",
        "-cp",
        f"{work}{os.pathsep}{jar}",
        "VulnServer",
        port,
    ]
    print("[*] run:", " ".join(run_cmd))
    print()
    # 前台运行，Ctrl+C 结束
    return subprocess.call(run_cmd, cwd=work)


if __name__ == "__main__":
    raise SystemExit(main())
