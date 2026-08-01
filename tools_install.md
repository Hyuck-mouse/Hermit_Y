# 外部工具安装指南

本项目依赖一些外部开源工具，需要手动下载并编译/安装到项目的 `thirdparty` 目录。以下是各工具的安装方式：

## 目录

- [nmap](#nmap)
- [sqlmap](#sqlmap)
- [fenjing](#fenjing)
- [ysoserial](#ysoserial)
- [flask-session-cookie-manager](#flask-session-cookie-manager)

---

## nmap

**用途**: 端口扫描、服务识别、操作系统检测

### 安装方式

将 nmap 源码克隆到项目的 `thirdparty` 目录并编译：

```bash
mkdir -p src/thirdparty
cd src/thirdparty
git clone https://github.com/nmap/nmap.git
cd nmap
./configure --prefix=$(pwd) --without-zenmap --without-ndiff
make -j$(nproc)
```

### 编译依赖

**macOS**:

```bash
brew install libpcap openssl
```

**Ubuntu/Debian**:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev libssl-dev
```

**CentOS/RHEL**:

```bash
sudo yum install -y gcc make libpcap-devel openssl-devel
```

### 验证安装

```bash
./nmap --version
```

### 使用说明

nmap 是一个强大的网络扫描工具，支持多种扫描技术。

**常用命令**:
- 快速扫描: `./nmap -sV -p 1-100 target`
- 全面扫描: `./nmap -sV -p 1-65535 target`
- 操作系统检测: `./nmap -O target`
- 服务版本检测: `./nmap -sV target`

### 许可证

nmap 使用自定义许可证（基于 GPLv2），详见: [https://nmap.org/book/man-legal.html](https://nmap.org/book/man-legal.html)

---

## sqlmap

**用途**: SQL注入检测与利用

### 安装方式

将 sqlmap 克隆到项目的 `thirdparty` 目录：

```bash
mkdir -p src/thirdparty
cd src/thirdparty
git clone https://github.com/sqlmapproject/sqlmap.git
```

### 验证安装

```bash
python3 sqlmap/sqlmap.py --version
```

### 使用说明

sqlmap 是一个强大的 SQL 注入检测工具，支持多种数据库和注入技术。

**常用命令**:
- 检测注入点: `python3 sqlmap.py -u "http://target.com/page?id=1"`
- 获取数据库列表: `python3 sqlmap.py -u "http://target.com/page?id=1" --dbs`
- 获取表名: `python3 sqlmap.py -u "http://target.com/page?id=1" -D database_name --tables`
- 导出数据: `python3 sqlmap.py -u "http://target.com/page?id=1" -D database_name -T table_name --dump`

### 许可证

sqlmap 使用 GPLv2 许可证，详见: [https://github.com/sqlmapproject/sqlmap/blob/master/LICENSE](https://github.com/sqlmapproject/sqlmap/blob/master/LICENSE)

---

## fenjing

**用途**: Jinja2 SSTI 全自动绕 WAF

### 安装方式

将 Fenjing 克隆到项目的 `thirdparty` 目录并安装依赖：

```bash
mkdir -p src/thirdparty
cd src/thirdparty
git clone https://github.com/Marven11/Fenjing.git
cd Fenjing
pip install -e .
```

### 验证安装

```bash
python3 -m fenjing --help
```

### 使用说明

Fenjing 是一个专门针对 CTF 比赛中 Jinja2 SSTI 绕过 WAF 的全自动脚本。

**常用命令**:
- 扫描目标: `python3 -m fenjing --url "http://target.com/page"`
- POST 请求: `python3 -m fenjing --url "http://target.com/page" --method POST --data "param=value"`
- 添加自定义头: `python3 -m fenjing --url "http://target.com/page" --headers "Cookie: session=xxx"`

### 许可证

Fenjing 使用 MPL-2.0 许可证，详见: [https://github.com/Marven11/Fenjing/blob/main/LICENSE](https://github.com/Marven11/Fenjing/blob/main/LICENSE)

---

## ysoserial

**用途**: Java 反序列化 payload 生成工具

### 安装方式

将 ysoserial-all.jar 下载到项目的 `thirdparty` 目录：

```bash
mkdir -p thirdparty/ysoserial
cd thirdparty/ysoserial
curl -L -o ysoserial-all.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
```

### 验证安装

```bash
java -jar ysoserial-all.jar 2>&1 | head -5
```

### 使用说明

ysoserial 是一个强大的 Java 反序列化 payload 生成工具，支持多种 gadget 链。

**常用命令**:
- 列出所有 gadgets: `java -jar ysoserial-all.jar`
- 生成 payload: `java -jar ysoserial-all.jar CommonsCollections1 'command'`
- 生成 payload 并保存到文件: `java -jar ysoserial-all.jar CommonsCollections1 'id' > payload.bin`

**常用 gadgets**:
- CommonsCollections1 - 经典的 Commons Collections 链
- CommonsCollections2-7 - 不同版本的 Commons Collections 链
- BeanShell1 - BeanShell 脚本执行
- C3P0 - C3P0 连接池链
- Clojure - Clojure 脚本执行

### Java 版本兼容性

**Java 17+**: 需要添加 `--add-opens` 参数：

```bash
java --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED -jar ysoserial-all.jar CommonsCollections1 'command'
```

### 许可证

ysoserial 使用 MIT 许可证，详见: [https://github.com/frohoff/ysoserial/blob/master/LICENSE](https://github.com/frohoff/ysoserial/blob/master/LICENSE)

---

## flask-session-cookie-manager

**用途**: Flask session cookie 解码、伪造、爆破 secret_key

### 安装方式

将 flask-session-cookie-manager 下载到项目的 `thirdparty` 目录：

```bash
# 方式1: 下载zip并解压
mkdir -p thirdparty
cd thirdparty
curl -L -o flask-session-cookie-manager-master.zip https://github.com/noraj/flask-session-cookie-manager/archive/refs/heads/master.zip
unzip flask-session-cookie-manager-master.zip

# 方式2: git clone
mkdir -p thirdparty
cd thirdparty
git clone https://github.com/noraj/flask-session-cookie-manager.git flask-session-cookie-manager-master
```

### Python 依赖

```bash
pip install flask itsdangerous
```

### 验证安装

```bash
python3 thirdparty/flask-session-cookie-manager-master/flask_session_cookie_manager3.py --help
```

### 使用说明

flask-session-cookie-manager 是一个用于解码和编码 Flask session cookie 的工具。

**常用命令**:
- 解码cookie(不需要key): `python3 flask_session_cookie_manager3.py decode -c <cookie_value>`
- 解码cookie(验证签名): `python3 flask_session_cookie_manager3.py decode -s <secret_key> -c <cookie_value>`
- 编码/伪造cookie: `python3 flask_session_cookie_manager3.py encode -s <secret_key> -t "{'user': 'admin'}"`

**Agent工具调用**:
- `flask_session_decode(cookie, secret_key='')`: 解码Flask session cookie
- `flask_session_encode(data, secret_key)`: 伪造Flask session cookie，data为Python dict字符串
- `flask_session_brute(cookie, wordlist='')`: 爆破Flask session的secret_key

### 自动下载

如果工具不存在，Agent会自动从GitHub下载并解压到 `thirdparty/flask-session-cookie-manager-master/` 目录。也可手动将zip放在项目根目录，Agent会自动解压。

### 许可证

flask-session-cookie-manager 使用 MIT 许可证，详见: [https://github.com/noraj/flask-session-cookie-manager/blob/master/LICENSE](https://github.com/noraj/flask-session-cookie-manager/blob/master/LICENSE)

---

## 一键安装脚本

为方便一键安装所有工具，可使用以下脚本：

```bash
#!/bin/bash

set -e

echo "=== 安装 nmap ==="
mkdir -p src/thirdparty
cd src/thirdparty
if [ ! -d "nmap" ]; then
    git clone https://github.com/nmap/nmap.git
fi
cd nmap
if [ ! -f "nmap" ]; then
    ./configure --prefix=$(pwd) --without-zenmap --without-ndiff
    make -j$(nproc)
fi

echo "=== 安装 sqlmap ==="
cd ..
if [ ! -d "sqlmap" ]; then
    git clone https://github.com/sqlmapproject/sqlmap.git
fi

echo "=== 安装 fenjing ==="
if [ ! -d "Fenjing" ]; then
    git clone https://github.com/Marven11/Fenjing.git
    cd Fenjing
    pip install -e .
    cd ..
fi

echo "=== 安装 flask-session-cookie-manager ==="
if [ ! -d "flask-session-cookie-manager-master" ]; then
    curl -L -o flask-session-cookie-manager-master.zip https://github.com/noraj/flask-session-cookie-manager/archive/refs/heads/master.zip
    unzip flask-session-cookie-manager-master.zip
    rm -f flask-session-cookie-manager-master.zip
fi
pip install flask itsdangerous

echo "所有工具安装完成！"
```

将上述内容保存为 `install_tools.sh`，然后运行：

```bash
chmod +x install_tools.sh
./install_tools.sh
```

---

## 注意事项

1. **合法使用**: 所有工具仅用于授权的渗透测试和安全研究
2. **网络环境**: 确保网络环境能够访问 GitHub
3. **编译依赖**: nmap 需要编译环境和依赖库（libpcap、openssl）
4. **定期更新**: 建议定期更新这些工具以获取最新功能和安全修复

---

## 新增工具指南

当需要添加新的外部工具时，请按照以下步骤操作：

1. 在 `src/tools/` 目录下创建新的工具模块（如 `new_tool.py`）
2. 在 `src/tools/__init__.py` 中导出新工具类
3. 在 `src/main.py` 的 `setup_agent()` 函数中注册新工具
4. 在本文档中添加工具的安装说明，包括：
   - 工具名称和用途
   - 安装命令
   - 验证方法
   - 使用说明
   - 许可证信息