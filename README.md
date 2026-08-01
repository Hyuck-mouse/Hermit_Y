# AI Pentest Agent - CLI 使用指南

## 项目简介

AI Pentest Agent 是一个基于 LLM 的自动化渗透测试工具，支持多种安全测试场景，包括漏洞扫描、CTF 解题等。

## 快速开始

### 环境要求

- Python 3.9+
- conda 或虚拟环境

### 安装步骤

```bash
# 1. 创建并激活 conda 环境
conda create -n pentest-agent python=3.11 -y
conda activate pentest-agent

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置环境变量
cp .env.example .env
# 编辑 .env 文件，添加你的 API Key
```

### 配置文件

编辑 `.env` 文件：

```bash
PROVIDER=deepseek
API_KEY=your-api-key-here
DEFAULT_MODEL=deepseek-v4-pro
BASE_URL=https://api.deepseek.com/v1
TEMPERATURE=0.7
MAX_TOKENS=4096
```

## CLI 命令

### 1. run - 交互式模式

运行渗透测试 Agent，支持交互式对话。

#### 命令格式

```bash
python3 src/main.py run [OPTIONS] [PROMPT]
```

#### 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `prompt` | string | 可选 | 初始输入，若省略则进入交互式模式 |
| `--provider` / `-p` | string | deepseek | LLM 提供商 |
| `--model` / `-m` | string | deepseek-v4-pro | 模型名称 |

#### 可用 Provider

- `deepseek` - DeepSeek（已测试，推荐使用）

> **注意**：当前仅测试了 DeepSeek。代码中虽保留了其他 Provider（openai、openrouter、anthropic、google、local）的接口，但未经测试，不保证可用。

#### 示例

```bash
# 进入交互式模式
python3 src/main.py run

# 指定初始输入
python3 src/main.py run "测试 http://example.com"

# 指定 Provider 和模型
python3 src/main.py run --provider deepseek --model deepseek-v4-pro

# 组合使用
python3 src/main.py run "测试 SQL注入" --provider deepseek --model deepseek-v4-pro
```

### 2. scan - 扫描模式

对目标主机进行全面的渗透测试扫描。
#### 命令格式

```bash
python3 src/main.py scan TARGET [OPTIONS]
```

#### 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `target` | string | 必填 | 目标 URL 或 IP 地址 |
| `--provider` / `-p` | string | deepseek | LLM 提供商 |
| `--model` / `-m` | string | deepseek-v4-pro | 模型名称 |

#### 示例

```bash
# 扫描单个目标
python3 src/main.py scan "http://example.com"

# 扫描带端口的目标
python3 src/main.py scan "http://example.com:8080"

# 指定 Provider
python3 src/main.py scan "http://example.com" --provider deepseek --model deepseek-v4-pro

# 扫描 IP 地址
python3 src/main.py scan "192.168.1.1"
```

#### 扫描流程

1. 信息收集（端口扫描、服务识别）
2. 漏洞检测（SQL注入、XSS、RCE等）
3. 漏洞验证
4. 生成报告

### 3. ctf - CTF 解题模式

解决 CTF 挑战题目。

#### 命令格式

```bash
python3 src/main.py ctf CHALLENGE [OPTIONS]
```

#### 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `challenge` | string | 必填 | CTF 题目描述或目标 URL |
| `--provider` / `-p` | string | deepseek | LLM 提供商 |
| `--model` / `-m` | string | deepseek-v4-pro | 模型名称 |

#### 示例

```bash
# 只提供目标 URL
python3 src/main.py ctf "http://challenge-xxx.sandbox.ctfhub.com:10800/"

# 指定题目类型
python3 src/main.py ctf "SQL注入题目 http://challenge-xxx.sandbox.ctfhub.com:10800/"

# 详细描述题目
python3 src/main.py ctf "这是一个CTF Web题目，目标是http://challenge-xxx.sandbox.ctfhub.com:10800/，可能存在文件包含漏洞，请分析并获取flag"

# 指定 Provider 和模型
python3 src/main.py ctf "http://challenge-xxx.sandbox.ctfhub.com:10800/" --provider deepseek --model deepseek-v4-pro
```

#### 支持的 CTF 类型

当前仅支持 **Web 题型**：

- SQL 注入
- XSS 跨站脚本
- 文件包含漏洞
- 命令注入
- SSRF
- 代码执行
- 加密解密
- 其他 Web 漏洞

> **注意**：后续将补充 Pwn、Reverse 等非 Web 类型题目。


### 4. tools - 列出可用工具

显示当前注册的所有工具列表。

#### 命令格式

```bash
python3 src/main.py tools
```

#### 示例

```bash
python3 src/main.py tools
```

## 内置工具列表

### HTTP 工具

| 工具名称 | 功能 | 参数 |
|----------|------|------|
| `http_request` | 发送 HTTP 请求 | method, url |
| `http_get` | 发送 HTTP GET 请求 | url, params, headers |
| `http_post` | 发送 HTTP POST 请求 | url, data, json, headers |

### 扫描工具

| 工具名称 | 功能 | 参数 |
|----------|------|------|
| `nmap_scan` | 端口扫描 | targets, ports, arguments |
| `directory_brute` | 目录枚举 | base_url, wordlist |
| `subdomain_enum` | 子域名枚举 | domain, wordlist |
| `detect_waf` | WAF 检测 | url |

### 加密工具

| 工具名称 | 功能 | 参数 |
|----------|------|------|
| `base64_encode` | Base64 编码 | data |
| `base64_decode` | Base64 解码 | data |
| `sha256_hash` | SHA256 哈希 | data |
| `md5_hash` | MD5 哈希 | data |

### 代码执行工具

| 工具名称 | 功能 | 参数 |
|----------|------|------|
| `execute_python` | 执行 Python 代码 | code, timeout |
| `execute_bash` | 执行 Bash 命令 | command, timeout |

## 高级用法

### 指定 LLM Provider

当前仅推荐使用 DeepSeek：

```bash
# 使用 DeepSeek
python3 src/main.py run --provider deepseek --model deepseek-v4-flash
```

### 批量扫描

```bash
# 使用循环扫描多个目标
for target in "http://example1.com" "http://example2.com"; do
    python3 src/main.py scan "$target" --provider deepseek
done
```

### 使用 Makefile

```bash
# 启动交互式模式
make run

# 扫描目标
make scan TARGET=http://example.com

# 解决 CTF 题目
make ctf CHALLENGE="http://challenge-xxx.ctfhub.com"

# 构建 Docker 镜像
make docker-build

# 清理环境
make clean
```

## 注意事项

1. **合法授权**：仅对授权目标进行测试，遵守法律法规
2. **API Key 安全**：不要将 API Key 提交到版本控制系统
3. **网络环境**：确保能访问目标和 LLM API
4. **耐心等待**：复杂任务可能需要多次迭代
5. **结果验证**：AI 分析结果仅供参考，需人工验证

## 故障排除

### 常见错误

**ModuleNotFoundError: No module named 'typer'**

```bash
# 确保在正确的环境中安装依赖
conda activate pentest-agent
pip install -r requirements.txt
```

**Provider 无效错误**

```bash
# 检查 Provider 是否正确
# 当前支持: deepseek
python3 src/main.py run --provider deepseek
```

**网络连接问题**

```bash
# 测试网络连接
curl -I https://api.deepseek.com/v1/chat/completions
```

**API Key 无效**

```bash
# 检查 .env 文件中的 API Key
cat .env | grep API_KEY
```

## 项目结构

```
pentest-agent/
├── src/
│   ├── main.py              # CLI 入口
│   ├── agent/               # Agent 核心模块
│   ├── tools/               # 内置工具
│   ├── config/              # 配置管理
│   ├── kb/                  # 知识库
│   ├── mcp/                 # MCP 协议支持
│   ├── report/              # 报告生成
│   └── skills/              # 技能加载器
├── requirements.txt         # 依赖列表
├── .env.example             # 配置示例
├── Dockerfile               # Docker 镜像
├── docker-compose.yml       # Docker Compose
├── Makefile                 # 快捷命令
└── setup.sh                 # 一键安装脚本
```

## 许可证

本项目基于 MIT License 开源。

## 免责声明

1. **仅供学习研究使用**：本项目仅用于网络安全教学、CTF 竞赛训练和已授权的安全测试。使用者须确保在合法授权范围内进行测试，并遵守所在地区的法律法规。
2. **禁止非法使用**：严禁将本工具用于任何未经授权的渗透测试、攻击行为或其他非法用途。因不当使用本工具造成的任何法律责任和后果，由使用者自行承担。
3. **结果仅供参考**：AI 生成的分析结果可能存在误报或漏报，仅供安全研究参考，不能替代专业的人工安全评估。
4. **API 费用**：使用 LLM API（如 DeepSeek）会产生调用费用，费用由使用者自行承担。

## 第三方工具说明

本项目**不包含**任何第三方工具的源码或二进制文件。所有第三方工具均由 `setup.sh` 脚本从官方仓库自动下载到 `src/thirdparty/` 目录（该目录已被 `.gitignore` 排除，不会上传至仓库）。

使用者需自行下载并遵守各工具的许可证协议：

| 工具 | 用途 | 来源 | 许可证 |
|------|------|------|--------|
| sqlmap | SQL 注入检测与利用 | https://github.com/sqlmapproject/sqlmap | GPL-2.0-or-later |
| Fenjing | Flask/Jinja2 SSTI 利用 | https://github.com/duo-labs/fenjing | MPL-2.0 |
| flask-session-cookie-manager | Flask Session Cookie 编解码 | https://github.com/noraj/flask-session-cookie-manager | MIT |
| ysoserial | Java 反序列化利用 | https://github.com/frohoff/ysoserial | MIT |

各第三方工具的版权归其原作者所有，使用者应阅读并遵守对应的许可证条款。
