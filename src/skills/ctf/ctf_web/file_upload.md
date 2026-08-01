# 文件上传漏洞

## 描述
通过上传恶意文件（如WebShell）获取服务器权限，或利用解析漏洞执行代码。

## 触发条件
- 网站存在上传功能，如头像、附件、文档上传等。

## 检测方法
1. **尝试上传合法图片**：观察响应是否返回路径或成功。
2. **尝试上传PHP文件**：如果直接上传 `.php` 被拦截，说明有过滤。

## 利用方式
- **绕过前端验证**：抓包修改文件扩展名。
- **绕过MIME验证**：将 `Content-Type` 改为 `image/jpeg`。
- **绕过内容检测**：在图片中插入PHP代码（图片马），然后利用文件包含或Apache解析漏洞执行。
- **利用`.htaccess`**：上传 `.htaccess` 文件，设置 `AddType application/x-httpd-php .jpg`，使所有 `.jpg` 文件被解析为PHP。
- **解析漏洞**（IIS、Nginx、Apache）：
  - 上传 `test.php.jpg`，Apache可能按扩展名从右向左解析，导致执行PHP。
  - Nginx配置错误：如果 `location` 规则将 `.php` 文件转发至FastCGI，而 `test.jpg` 可通过路径包含 `test.jpg/x.php` 触发。

## 绕过技巧
- **扩展名双写**：`test.pphphp` → 可能变为 `test.php`。
- **末尾加 `%00` 截断**（旧版本）：`test.php%00.jpg`。
- **利用 `::$DATA`**（Windows）：`test.php::$DATA` 会被保存为 `test.php`。
- **修改文件头**：添加 `GIF89a` 作为前几个字节，绕过内容检查。

## 附加提示
- 成功上传后，需找到上传路径（可能通过返回信息或目录扫描发现）。
- 上传后尽快访问，防止被清理。