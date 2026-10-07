# 参数逻辑缺陷（Parameter Logic Flaws）

## 描述
服务端对入参只做格式校验、未做业务语义校验，攻击者传入边界值/特殊值使程序走入非预期分支：负数反转、零值绕过、超大值溢出、空值/null 绕过必填、类型混淆。结果常表现为 0 元购买、转账方余额反增、积分刷爆、鉴权绕过。属业务逻辑漏洞，无特征 payload，WAF 难拦截。

## 典型缺陷
- **负数反转**：金额传 `-100`，`余额 = 余额 - 金额` → 余额反增 100；或 `total = price * quantity`，数量为负使总价为负。
- **零值绕过**：金额 `0`、数量 `0`、价格 `0`，绕过"金额>0"判断，0 元下单/支付。
- **超大值溢出**：金额传 `999999999` 或 `1e10`，超过整型/浮点范围导致溢出、回绕成负数或 0。
- **空值/null 绕过**：必填字段传 `""`/`null`/`None`，绕过 `if param` 校验或命中空值分支。
- **类型混淆**：传布尔 `true`/`false`、数组 `[]`、对象 `{}`、科学计数 `1e10`、十六进制 `0x10`，弱类型比较 `==` 误判。

## 触发条件
- 接口接收数值/金额/数量/价格/积分/折扣参数。
- 服务端用弱类型比较、未限定取值范围、未做正负与类型校验。
- 计算逻辑直接用入参做加减乘除而未归一化。

## 检测方法（快速验证）
1. **抓关键参数**：下单/转账/充值/兑换接口，定位 `amount`、`price`、`quantity`、`count`、`discount`、`balance`。
2. **逐个边界值替换**：先记原始值作基准，再分别换 `-1`、`0`、`999999999`、`""`、`null` 观察响应。
3. **比对最终状态**：测试前后查余额/订单金额/积分，看是否出现负值、超额、0 元成交。
4. **类型混淆**：数字参数传布尔/数组/对象，看是否 500 报错（暴露异常）或走入异常分支。

## 使用 logic_param_fuzz 工具测试

工具签名：`logic_param_fuzz(url, method="GET", param_name="", param_value="", extra_params="", headers="", session_id="")`

### 标准测试流程
1. **登录拿会话**：`logic_session_http` 登录，记下 `session_id`。
2. **定位参数**：把要测的参数名填 `param_name`，原始正常值填 `param_value`（作为基准响应）。
3. **固定其他参数**：`extra_params` 传 JSON 串，如 `'{"order_id":"O1","token":"xxx"}'`，保证每次只变被测参数。
4. **执行 Fuzz**：工具自动用以下测试集替换 `param_name` 的值并发请求：
   - 边界值：`0`、`-1`、`-99999`、`999999999`
   - 空值/类型：`""`、`null`、`None`、`true`、`false`、`[]`、`{}`
   - 通用探测：SQLi `' or '1'='1`、SSTI `{{7*7}}`、路径穿越 `../../../etc/passwd`、XSS `<script>alert(1)</script>`
   - 若 `param_value` 是数字：额外测 `0x10`、`1e10`、`0b1`、`+0`、`00`
5. **解读结果**：
   - `baseline_status`/`baseline_length`：基准。
   - `findings`：每个异常项含 `fuzz_value`、`desc`、`status`、`anomalies`。
   - 异常指标：状态码变化、响应长度差 > 100、500 服务器错误、200 但内容不同（疑似逻辑绕过）。
   - 重点跟进 `desc=负数/零值/超大值` 且返回 200 的项，去业务侧核对实际金额/积分变化。
6. **二次确认**：对可疑值单独用 `logic_session_http` 再发一次，查账户/订单状态验证是否真发生逻辑绕过（如余额反增、0 元成交）。

### 示例（转账金额负数反转）
```
# 1. 登录
logic_session_http(session_id="u", method="POST", url="http://target/login",
                   json_data='{"username":"a","password":"a"}')

# 2. Fuzz amount 参数
logic_param_fuzz(
    url="http://target/api/transfer",
    method="POST",
    param_name="amount",
    param_value="100",
    extra_params='{"to_user":"bob"}',
    session_id="u"
)
# 若 amount=-1 返回 200，再去查自己余额是否反增 → 负数反转成立
```

### 示例（0 元购买）
```
logic_param_fuzz(
    url="http://target/api/order/create",
    method="POST",
    param_name="price",
    param_value="99",
    extra_params='{"goods_id":"G1","quantity":"1"}',
    session_id="u"
)
# 关注 price=0 时是否下单成功
```

## 绕过技巧
- **负数变体**：`-1`、`-0.01`、`-1e9`、`-0x10`，绕过仅 `> 0` 的校验。
- **零值变体**：`0`、`0.0`、`00`、`+0`、`0e10`，弱类型下都等于 0。
- **溢出变体**：`2147483647`（int32 上界）、`2147483648`（溢出为负）、`1e309`（浮点 Inf）、`99999999999`。
- **类型混淆**：金额传 `true`（PHP `==1`）、`[]`（弱比较 ==0/false）、`{"$gt":0}`（NoSQL 注入）。
- **多参数组合**：单参数测不出时，`price=-1&quantity=-1`、`discount=200`（折扣超 100%）、`coupon_value=999` 同时传。
- **单位混淆**：金额传分 vs 元（`100` 当 100 元还是 1 元）、数量传浮点 `0.5`。
- **JSON 体类型**：`{"amount":"-1"}`（字符串）、`{"amount":["-1"]}`（数组）触发不同解析分支。

## 注意
- 转账/下单类缺陷会改真实数据，测完联系授权方回滚或用测试账号小额验证。
- `findings` 只标记"响应异常"，是否真有业务危害需结合账户状态核对。
- 500 报错响应可能泄露堆栈，单独保存用于后续利用。
- 测完 `logic_session_close` 释放会话。
