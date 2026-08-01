# HTTP协议攻击

## 描述
利用HTTP协议特性进行参数污染、请求走私、CRLF注入等攻击，绕过WAF或获取额外权限。

## 常见攻击类型

### 1. HTTP参数污染（HPP）
- **原理**：向同一参数多次赋值，服务器取最后一个值，而WAF可能取第一个值。
- **示例**：`?id=1&id=2`，服务器可能使用 `id=2`，WAF检查了 `id=1` 认为安全，最终绕过。
- **利用**：在SQL注入或命令注入中，用于绕过WAF。

### 2. 请求走私（HTTP Smuggling）
- **CL-TE**（Content-Length vs Transfer-Encoding）：
  - 前端使用 `Content-Length`，后端使用 `Transfer-Encoding: chunked`。
  - 构造请求，使前后端解析的请求边界不同，将恶意请求“走私”给后端。
- **TE-CL**：反向利用。
- **利用**：绕过缓存、请求劫持、无授权访问、SSRF。

### 3. CRLF注入
- **原理**：在参数值中插入 `%0d%0a`（CRLF），可添加HTTP头或修改响应体。
- **示例**：`?url=http://example.com%0d%0aLocation:%20http://evil.com`，可能引发重定向。
- **利用**：XSS（通过注入 `Set-Cookie`）、SSRF（修改Host头）。

### 4. Host头攻击
- 服务器使用 `Host` 头生成URL或包含密码重置链接，可被篡改。
- **示例**：修改 `Host: evil.com`，导致密码重置邮件发送到攻击者域名。

## 检测方法
- **HPP**：提交两个同名参数，观察响应或请求日志。
- **请求走私**：发送 `CL` 和 `TE` 混合请求，观察响应差异。
- **CRLF**：在参数中插入 `%0d%0a`，观察响应头是否出现新行。

## 绕过技巧
- 使用 `%0d%0a` 编码（URL编码、双编码）。
- 在请求走私中，注意 `Content-Length` 的计算要精确。
- 利用 `X-Forwarded-For` 伪造IP，绕过基于IP的访问控制。

## 附加提示
- 请求走私漏洞多出现在CDN与源站之间，或反向代理与后端。
- CRLF注入在PHP `$_SERVER['HTTP_HOST']` 等环境中可能导致XSS。