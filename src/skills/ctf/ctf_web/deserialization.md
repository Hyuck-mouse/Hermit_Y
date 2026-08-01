# 反序列化漏洞

## 描述
当应用程序反序列化不可信数据时，攻击者可能构造恶意对象，触发任意代码执行。

## 触发条件
- 存在接收序列化数据的接口（如PHP的 `unserialize()`、Python的 `pickle`、Java的 `readObject()`）。
- 参数值包含序列化字符串，且用户可控。

## 检测方法
1. **识别序列化格式**：PHP序列化以 `O:4:"User":1:{...}` 开头；Java序列化以 `AC ED 00 05` 开头；Python pickle以 `80 04` 开头。
2. **尝试触发错误**：修改序列化数据，观察是否出现异常信息，确认存在反序列化点。

## PHP反序列化协议详解
### 基础类型
- `i:` 整数 `i:1;`
- `d:` 浮点 `d:1.5;`
- `s:` 字符串 `s:4:"test";` (长度:内容)
- `a:` 数组 `a:2:{i:0;s:1:"a";i:1;s:1:"b";}`
- `O:` 对象 `O:4:"test":2:{s:1:"a";i:1;s:1:"b";i:2;}`
- `N;` NULL
- `R:` 引用 `R:2;` (引用第2个对象)

### 属性可见性编码
- `public $a` → `s:1:"a";`
- `protected $a` → `s:6:"\0*\0a";` (属性名前加\x00*\x00)
- `private $a` (类test中) → `s:11:"\0test\0a";` (属性名前加\x00类名\x00)

### 对象引用机制
当序列化多个对象时，每个对象会被分配一个引用ID（从2开始）。后续属性可以使用 `R:N;` 引用第N个对象。这在绕过 `__wakeup()` 等魔术方法时极为重要。

## 利用方式
- **PHP原生类利用**：
  - `Error` / `Exception` 类可触发 `__toString()`。
  - `SimpleXMLElement` 可读取文件。
  - `GlobIterator` 可目录遍历。
- **利用 `__destruct()`、`__wakeup()`、`__toString()` 等魔术方法**。
- **使用POP链**：通过已有的类方法组合，最终调用 `system()` 或 `eval()`。
- **Phar反序列化**：将恶意序列化数据写入Phar文件，通过 `phar://` 触发反序列化（需可上传文件）。
- **Python pickle**：构造 `__reduce__` 返回可执行命令的元组。
- **Java反序列化**：利用 Common Collections、Fastjson 等库的已知Gadget。

## PHP反序列化高级绕过技术

### 1. `__wakeup()` 绕过 — CVE-2016-7124 (属性数量法)
当序列化字符串中声明的属性数量 `>` 实际属性数量时，`__wakeup()` 不会被调用。
```
O:4:"test":4:{s:1:"a";s:20:"system('id');";s:1:"b";s:1:"2";s:1:"c";s:1:"3";s:1:"d";s:1:"4";}
```
注意：属性计数为4，但实际只有3个属性，第4个属性`d`是诱饵。

### 2. `__wakeup()` 绕过 — 引用法 (R: 引用)
**原理**：利用PHP序列化的引用机制，让 `$this->a` 引用另一个对象/属性。当 `__wakeup()` 清空 `$this->a` 时，由于引用关系，其他属性也会被影响。反序列化完成后，`__destruct()` 中的赋值操作会通过引用链恢复原命令。

**典型场景**：
```php
class test {
    public $a;  // __destruct() 中 eval($a)
    public $b;  // __destruct() 中 $this->b = $this->c
    public $c;
    __wakeup() { $this->a = ''; }  // 直接清空 $a
    __destruct() {
        $this->b = $this->c;  // 赋值操作
        eval($this->a);  // $a 通过引用恢复
    }
}
```

**Payload构造**（先用 `ls` 探测，不要直接猜flag位置）：
```
O:4:"test":3:{
    s:1:"b";O:8:"stdClass":0:{}    // b 为 stdClass 对象，引用ID=2
    s:1:"c";s:13:"ls -la /;"       // c 存放探测命令（先看根目录）
    s:1:"a";R:2;                   // a 引用 b (第2个对象)
}
```
确认flag文件位置后，再生成第二次payload读取：
```
O:4:"test":3:{
    s:1:"b";O:8:"stdClass":0:{}            // b 为 stdClass 对象
    s:1:"c";s:20:"cat /discovered_flag;"   // 根据搜索结果读取
    s:1:"a";R:2;
}
```

**执行流程**：
1. 反序列化时：`b` = stdClass对象(refID=2), `c` = "ls -la /;", `a` = 引用refID=2
2. `__wakeup()` 触发：`$this->a = ''`，由于 `a` 引用 `b`，`b` 也被置为空字符串
3. `__destruct()` 触发：
   - `$this->b = $this->c` → `b` 变为 "ls -la /;"，由于 `a` 引用 `b`，`a` 也同步变为 "ls -la /;"
   - `eval($this->a)` → 执行探测命令，根据返回结果定位flag

**关键点**：
- `stdClass` 可替换为其他任意类（如 `Exception`、`Error`），只要能生成对象引用
- 必须精确控制属性顺序和引用ID
- 该方法在 PHP 5.x 和 7.x 中均有效
- **反序列化RCE的第一步是信息收集（ls/find），不是直接cat /flag！**

### 3. `__wakeup()` + WAF 复合绕过
当同时存在 `__wakeup()` 和 WAF（正则过滤）时：
- WAF 可能要求 payload 中包含特定字符串（如 `test":3`）
- 如果用属性数量法绕过，声明数 > 实际数可能导致 WAF 检查失败
- 引用法可以在保持属性数量不变的同时绕过 `__wakeup()`

### 4. 属性顺序影响
PHP反序列化时，属性按序列化顺序赋值。`__wakeup()` 在所有属性赋值完成后调用。因此：
- 将关键属性放在后面赋值可能改变 `__wakeup()` 执行时的状态
- 引用法正是利用了"先赋值b/c，再通过引用让a关联b"的顺序

## WAF绕过策略
- **正则绕过**：
  - 若正则检查 `test":3`，确保 payload 中确实出现此字符串
  - 可将绕过字符串嵌入属性值中：`s:7:"test":3"`
- **长度绕过**：
  - 部分WAF限制payload长度，需精确计算序列化字符串长度
  - 可缩短属性名、使用短命令
- **关键字绕过**：
  - 过滤 `system/exec/shell_exec` 时，可用 `assert`、`preg_replace`、`include` 等替代
  - 过滤 `flag` 时，可用 `glob('*')`、`scandir('.')` 等间接获取

## 常见绕过
- **PHP `__wakeup()` 绕过（CVE-2016-7124）**：当属性数量大于实际数量时，`__wakeup()` 不会执行。
- **PHP 引用绕过（R:）**：利用引用关系让 `__wakeup()` 的清空操作不影响最终的 `eval` 执行。
- **Java 反序列化绕过**：使用 `ysoserial` 生成Payload，注意JDK版本。

## 附加提示
- 优先搜索目标使用的框架/库是否公开已知Gadget。
- 若无现成Gadget，需审计源码寻找可利用的类。
- 反序列化漏洞常结合文件上传（Phar）或SSRF（Java RMI）利用。
- 分析反序列化题目时，重点关注：
  1. **入口分析**：反序列化入口在哪里？`$_GET`/`$_POST`/`$_COOKIE`?
  2. **魔术方法链**：有哪些 `__wakeup()`/`__destruct()`/`__toString()` 方法？执行顺序？
  3. **赋值关系**：`__destruct()` 中的赋值操作是否会通过引用链传递？
  4. **WAF限制**：正则/黑名单/长度限制？如何绕过？
  5. **类名/属性**：类名长度、属性名长度、可见性（public/protected/private）？
- 工具生成的payload可能需要手动调整属性顺序和引用关系，特别是涉及引用绕过时。
- **RCE后信息收集流程**（反序列化获得eval/system等RCE能力后）：
  1. 第一步命令用 `ls -la /` 探测根目录，不要直接 `cat /flag`
  2. 第二步用 `find / -name "*flag*" 2>/dev/null` 全局搜索flag文件
  3. 第三步用 `env` 检查环境变量是否包含flag
  4. 根据搜索结果读取实际发现的flag文件，flag名可能是 f1ag、fl4g、secret 等