# 业务流程绕过（Flow Bypass）

## 描述
多步业务流程（下单→支付→发货、领券→核销、注册→验证→激活、找回密码）依赖"按顺序、不跳步"的假设，但服务端未在前端之外做状态机校验，攻击者通过跳步、重放、乱序执行直接到达终态。属业务逻辑漏洞，危害包括免费拿货、重复领奖、绕过身份验证、任意重置密码。

## 典型缺陷
- **跳步执行**：下单流程跳过"支付"直接请求"完成订单"/"发货"，服务端未校验订单状态。
- **步骤重放**：领奖/签到最后一步重复请求，多次领取奖励。
- **顺序打乱**：把"验证码校验"放在"修改密码"之后调用，或先调"成功"回调再走校验。
- **密码重置绕过**：跳过"邮箱验证码校验"步骤，直接请求"设置新密码"接口；或重置 token 不与用户绑定。
- **状态机缺失**：订单状态 `待支付→已支付→已发货` 可从任意状态跳到任意状态。

## 触发条件
- 业务流程分多个 API 调用，前端控制顺序，后端无独立状态校验。
- 终态接口（完成、发货、领奖）只看"请求合法"，不看"前置步骤是否完成"。
- 重置/激活类接口的校验环节与执行环节可分离调用。

## 检测方法（快速验证）
1. **梳理完整流程**：抓包记录每一步的请求（URL、方法、参数、依赖前一步返回的值）。
2. **跳步测试**：删除中间某步（如支付），直接调后续步骤，看是否成功。
3. **重放测试**：流程跑完后，重复调最后一步（领奖/完成），看是否再次成功。
4. **乱序测试**：打乱步骤顺序，看是否仍能到达终态。
5. **跨用户/跨流程**：用 A 流程的 token 去完成 B 流程的最后一步。

## 使用 logic_flow_test 工具测试

工具签名：`logic_flow_test(steps, session_id="flow_test")`

`steps` 是 JSON 数组字符串，每个步骤对象含：
- `name`：步骤名（便于结果识别）。
- `method`：HTTP 方法。
- `url`：请求 URL，支持变量替换 `{{变量名}}`。
- `headers`：请求头 JSON 字符串（可选）。
- `data`：表单数据 JSON 字符串（可选）。
- `json_data`：JSON 体 JSON 字符串（可选，与 `data` 二选一）。
- `extract`：从响应提取变量，JSON 字符串，格式 `{"变量名":"$.路径"}`，如 `{"token":"$.data.token","order_id":"$.data.order_id"}`，提取后可在后续步骤 `{{token}}`、`{{order_id}}` 引用。

工具自动执行三类测试：
1. **基准流程**：按顺序跑完全部步骤，验证流程本身通（作为对照）。
2. **跳步测试**：逐个跳过中间步骤（第 1 步和最后一步不跳），重置会话后重跑剩余步骤；若仍全部 200 → "流程绕过"。
3. **重放测试**：流程跑完后再调一次最后一步；若仍 200 → "重放漏洞"。

### 标准测试流程
1. **抓包编步骤**：把完整业务流程的每一步写成 step，依赖前一步返回值的用 `extract` 提取再 `{{}}` 引用。
2. **登录态**：把登录作为第 1 步（或先 `logic_session_http` 建会话），`session_id` 贯穿全流程共享 Cookie。
3. **执行工具**：传 `steps`（JSON 字符串）和 `session_id`。
4. **解读结果**：
   - `baseline_flow`：基准流程每步的状态码与内容预览，先确认全 200（流程通）。
   - `skip_test_findings`：每条记录 `skipped_step` + "跳过此步骤后流程仍然成功 → 可能存在流程绕过"。命中即漏洞。
   - `replay_test_findings`：命中表示最后一步可重复执行。
   - `extracted_variables`：流程中提取的变量，便于人工跟进。
5. **跟进验证**：对命中的跳步场景，单独用 `logic_session_http` 手动复现（只发首步+末步），核对业务后果（订单是否真完成、奖励是否真到账）。

### 示例（下单→支付→完成，跳过支付）
```
logic_flow_test(
    steps='[
      {"name":"login","method":"POST","url":"http://target/login",
       "json_data":"{\\"username\\":\\"a\\",\\"password\\":\\"a\\"}",
       "extract":"{\\"token\\":\\"$.data.token\\"}"},
      {"name":"create_order","method":"POST","url":"http://target/api/order/create",
       "headers":"{\\"Authorization\\":\\"Bearer {{token}}\\"}",
       "json_data":"{\\"goods_id\\":\\"G1\\"}",
       "extract":"{\\"order_id\\":\\"$.data.order_id\\"}"},
      {"name":"pay","method":"POST","url":"http://target/api/order/pay",
       "headers":"{\\"Authorization\\":\\"Bearer {{token}}\\"}",
       "json_data":"{\\"order_id\\":\\"{{order_id}}\\"}"},
      {"name":"finish","method":"POST","url":"http://target/api/order/finish",
       "headers":"{\\"Authorization\\":\\"Bearer {{token}}\\"}",
       "json_data":"{\\"order_id\\":\\"{{order_id}}\\"}"}
    ]',
    session_id="flow_test"
)
# 若 skip_test_findings 中 skipped_step=pay 命中 → 跳过支付仍能完成订单
# 若 replay_test_findings 命中 → finish 可重复调用
```

### 示例（密码重置绕过：跳过验证码校验）
```
steps='[
  {"name":"request_reset","method":"POST","url":"http://target/api/pwd/reset_request",
   "json_data":"{\\"email\\":\\"v@x.com\\"}"},
  {"name":"verify_code","method":"POST","url":"http://target/api/pwd/verify",
   "json_data":"{\\"email\\":\\"v@x.com\\",\\"code\\":\\"000000\\"}"},
  {"name":"set_new_pwd","method":"POST","url":"http://target/api/pwd/set",
   "json_data":"{\\"email\\":\\"v@x.com\\",\\"new_pwd\\":\\"P@ss1234\\"}"}
]'
# 跳过 verify_code 仍能 set 新密码 → 重置流程绕过
```

## 绕过技巧
- **跳步**：删除"支付/验证/激活"中间步骤，直接调终态接口。
- **重放**：领奖/签到/完成最后一步重复请求；改请求参数（如换 `order_id`）批量重放。
- **乱序**：先调"回调成功"再调"校验"；或把"校验"当可选步骤。
- **状态伪造**：在请求里直接带 `status=paid`、`paid=1`、`step=3` 跳过状态机。
- **Token 复用**：把他人/他流程的重置 token、支付回调 token 套用到自己的请求。
- **回调绕过**：支付回调接口不验签，直接伪造 `{"order_id":"O1","status":"success"}`。
- **前端参数依赖**：服务端信任前端传的 `price`/`amount`/`is_admin`，流程中篡改这些值。
- **并发+流程**：竞态条件下状态机校验更易绕过（见 race_condition）。

## 注意
- 流程绕过常造成真实订单/奖励/账号变更，测试用测试账号与测试数据，测前确认授权。
- `extract` 仅支持简单 `$.a.b` 路径，复杂嵌套需手工拆分或预先在步骤内处理。
- 跳步测试会重置会话与变量，若流程依赖持久化数据（如 DB 中的订单），跳步命中未必可复现，需手动验证。
- `steps` 中的 JSON 字符串内层引号需转义（`\\"`），或用单引号包裹外层 JSON。
- 测完 `logic_session_close` 释放会话。
