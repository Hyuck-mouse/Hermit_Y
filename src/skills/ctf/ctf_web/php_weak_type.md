# PHP弱类型与特性绕过

## 描述
利用PHP类型比较松散、函数行为异常等特性，绕过输入验证、身份认证或权限检查。

## 触发条件
- 存在松散比较（`==`）而非严格比较（`===`）。
- 使用 `strpos`、`in_array`、`md5` 等函数时未严格检查返回值。

## 常见绕过场景

### 1. 松散比较绕过
- `"123" == 123` → true
- `"abc" == 0` → true（字符串与数字比较，字符串转换为0）
- `"0e12345" == "0e67890"` → true（科学计数法，全为0）
- `"1admin" == 1` → true
- 利用 `NULL == 0`、`NULL == false` 等。

### 2. `strpos` 绕过
- `strpos($haystack, $needle) === false` 判断是否包含，但如果 `$needle` 在开头返回 `0`，`0 == false`，需用 `===`。
- 构造 `$needle` 开头位置绕过。

### 3. `md5` 弱碰撞
- `md5('240610708') == md5('QNKCDZO')` → 均以 `0e` 开头，弱比较相等。
- 利用 `0e` 哈希绕过。

### 4. `in_array` 绕过
- `in_array($value, $array, false)` 默认松散比较，若 `$array` 为 `[0, 1, 2]`，`$value = "abc"` 会被转换为0，绕过预期。

### 5. `preg_replace` 的 `/e` 修饰符
- 在PHP 7.0以下，`preg_replace('/abc/e', $_GET['cmd'], 'abc')` 会执行 `$_GET['cmd']` 作为PHP代码。

### 6. `extract` 和 `$$` 变量覆盖
- `extract($_GET)` 可能覆盖已有变量。
- `$$key = $value` 可动态覆盖全局变量。

## 利用方式
- 在登录时传入 `password=0`，若数据库存储的密码哈希以 `0e` 开头，可能弱比较通过。
- 在参数中利用 `?username=admin&password=0` 绕过MD5验证。
- 构造 `?admin=1` 覆盖 `$admin` 变量。

## 注意
- 严格比较 `===` 可防御大多数弱类型漏洞。
- 检查PHP版本，部分特性在旧版本中可用。