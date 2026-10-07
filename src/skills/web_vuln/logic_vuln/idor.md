# 越权访问漏洞（IDOR / 水平越权 / 垂直越权）

## 描述
由于服务端未对"当前用户是否有权访问目标对象"做校验，攻击者通过修改请求中的对象引用（URL 参数、请求体字段、路径段）即可访问或操作他人数据，或以普通身份调用管理功能。属业务逻辑漏洞，WAF 与常规过滤通常无效。

## 分类
- **水平越权**：相同权限级别的用户互相访问对方数据（A 用户改 `user_id=2` 看 B 用户订单）。
- **垂直越权**：普通用户访问高权限接口（普通用户调用 `/admin/user/delete`）。
- **IDOR（不安全直接对象引用）**：直接用递增 ID/枚举值访问对象，最常见形态。

## 触发条件
- URL 或请求体中存在对象标识：`?id=`、`?uid=`、`?order_id=`、`/api/user/123`、`?doc=8a8f...`。
- 接口仅校验"是否登录"，未校验"该对象是否属于当前用户"。
- 响应直接返回他人敏感数据（手机号、地址、订单详情、token）。

## 检测方法（快速验证）
1. **双账号比对法**：注册/登录两个账号 A、B，A 抓自己的请求，把对象 ID 改成 B 的，看是否返回 B 的数据。
2. **ID 递增枚举**：从自己的 ID 往 `±5`、`1`、`999999` 等方向探测，对比响应长度/状态码差异。
3. **垂直越权探测**：普通用户登录后，直接请求 `/admin/*`、`/api/admin/*` 路径，或带 `role=admin`、`is_admin=1` 参数。
4. **HTTP 方法切换**：`GET /api/users` 普通用户被拒，尝试 `POST`/`PUT`/`PATCH`/`DELETE` 是否放行。

## 利用步骤
1. 登录目标，抓取带对象引用的请求（个人中心、订单详情、文件下载）。
2. 记录自己的对象 ID 作为基准值 `current_value`。
3. 替换为他人 ID（递增/递减），观察是否 200 且内容与基准不同。
4. 垂直越权：把普通用户会话 Cookie 套用到管理接口请求上。
5. 确认能读/写后，扩大枚举范围批量获取数据。

## 使用 logic_idor_test 工具测试（重点）

工具签名：`logic_idor_test(url, param_name, current_value, method="GET", test_range="", headers="", session_id="")`

### 标准测试流程
1. **先登录拿会话**：用 `logic_session_http` 登录账号 A，拿到 `session_id`（如 `"userA"`），保证 Cookie/Token 跨调用保持。
2. **构造目标 URL**：两种写法
   - 占位符（推荐）：`http://target/api/user?id=__VALUE__`，工具会把 `__VALUE__` 替换为各测试值。
   - 无占位符：`http://target/api/user`，工具自动追加 `?param_name=value`。
3. **调用工具**：
   - `param_name`：对象引用参数名（如 `user_id`、`order_id`）。
   - `current_value`：当前用户自己的值（作为基准响应）。
   - `test_range`：留空则自动生成（数字基准会测 `base±5` 及 `0/-1/1/999999/admin/root`；非数字基准测 `admin/root/test/guest/user/1/0`）。需精测可传逗号分隔值如 `"1,2,3,100,1000"`。
   - `session_id`：传入步骤 1 的会话 ID，确保带着登录态。
4. **解读结果**：
   - `baseline`：基准响应（自己的值）。
   - `findings`：每个命中项含 `test_value`、`status`、`content_length`、`content_preview`。
   - 命中规则：状态码 200 且（与基准状态不同 或 响应长度差 > 50）且 非 401/403。
   - 命中即代表"用别人的 ID 仍 200 且内容不同 → 越权"。再人工核对 `content_preview` 是否为他人的真实数据。
5. **垂直越权**：用普通账号 session 调管理接口 URL（如 `http://target/api/admin/users`），把 `param_name` 设为不存在的参数、`current_value` 设为 `"x"`，观察是否 200 返回管理数据。

### 示例（水平越权）
```
# 1. 登录 A 账号
logic_session_http(session_id="userA", method="POST", url="http://target/login",
                   data='{"username":"a","password":"a"}')

# 2. 用 A 的会话越权枚举 order_id
logic_idor_test(
    url="http://target/api/order/detail?id=__VALUE__",
    param_name="id",
    current_value="1001",
    session_id="userA"
)
# 关注 findings 中 test_value=1002/1003... 是否返回了别人的订单
```

## 绕过技巧
- **UUID 难枚举**：若对象用 UUID，从泄露页面/接口响应/JS 文件中收集他人 UUID，填入 `test_range`。
- **请求体越权**：GET 测不出时改 `method="POST"`，把 ID 放 `extra_params`/`data`。
- **HTTP 方法绕过**：`GET` 被拦试 `HEAD`/`OPTIONS`/`PUT`/`PATCH`。
- **路径段越权**：`/api/user/__VALUE__/profile`，用占位符写法同样适用。
- **头部伪造**：加 `X-Forwarded-For: 127.0.0.1`、`X-Original-URL: /admin/`、`X-Rewrite-URL` 绕过路径鉴权。
- **大小写/编码**：`/Admin/users`、`/api/user/1001%00`、`/api/user/1001/.` 绕过路由匹配。
- **参数污染**：`?id=1001&id=1002`，部分框架取最后一个。
- **JWT/角色字段篡改**：若 token 可读，改 `role`/`admin` 字段（无签名校验时）。

## 注意
- 测试前务必有授权；越权写操作（删除/转账）优先只读验证，避免破坏他人数据。
- 命中后核对 `content_preview`，排除缓存/通用页面造成的假阳性。
- 测完用 `logic_session_close(session_id="userA")` 释放会话。
