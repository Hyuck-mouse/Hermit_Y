# PWN基础概念

## 描述
PWN是二进制漏洞利用的简称，通过分析可执行文件（通常是ELF格式）中的内存安全漏洞（如栈溢出、格式化字符串、堆漏洞等），控制程序执行流以获取Shell或读取Flag。本篇为PWN解题的基础知识总览。

## ELF文件格式
ELF（Executable and Linkable Format）是Linux下主要的可执行文件格式，关键结构如下：

### ELF文件组成
- **ELF Header**：文件头，包含魔数 `\x7fELF`、架构（32/64位）、字节序、入口地址（entry point）等。
- **Program Headers**：程序头表，描述段（Segment）信息，用于加载和运行。
- **Section Headers**：节头表，描述节（Section）信息，用于链接和调试。

### 关键节（Section）
| 节名 | 作用 |
|------|------|
| `.text` | 可执行代码段（只读、可执行） |
| `.rodata` | 只读数据（字符串常量等） |
| `.data` | 已初始化的全局变量（可读写） |
| `.bss` | 未初始化的全局变量（运行时清零） |
| `.got` | 全局偏移表，存放动态链接函数的实际地址 |
| `.plt` | 过程链接表，动态函数的跳板代码 |
| `.dynamic` | 动态链接信息 |

### PLT/GOT 机制（动态链接核心）
- 程序调用 `printf` 等库函数时，先跳转到 `printf@plt`。
- `printf@plt` 从 `printf@got` 读取真实地址并跳转。
- 首次调用时，GOT 表项未解析，触发 `ld-linux` 进行惰性绑定（Lazy Binding）。
- **利用关键**：若能覆写 GOT 表项，即可劫持函数调用。

## 保护机制详解（checksec）
运行 `pwn_checksec` 工具可获取以下保护状态：

### NX（No-eXecute / DEP）
- **作用**：数据段（栈、堆、.bss）不可执行，shellcode 放在栈上无法执行。
- **绕过**：使用 ret2libc / ROP，复用已存在的可执行代码。
- **检测**：`elf.nx` 为 True 时开启。

### PIE（Position Independent Executable）
- **作用**：程序基址随机化，每次运行 `.text`、`.data` 等段地址变化。
- **绕过**：先泄漏程序地址计算基址，再利用已知偏移。
- **检测**：`elf.pie` 为 True 时开启；关闭时基址固定（如 0x400000）。

### Canary（栈金丝雀 / Stack Cookie）
- **作用**：函数序言在栈上插入随机值，返回前校验，被覆盖则调用 `__stack_chk_fail` 终止。
- **绕过**：泄漏 Canary 值（格式化字符串/信息泄漏），或爆破（fork 进程不重新随机化）。
- **检测**：`elf.canary` 为 True 时开启。

### RELRO（Relocation Read-Only）
- **No RELRO**：`.got` 可写，`.dynamic` 可写。
- **Partial RELRO**：`.got.plt` 可写（惰性绑定），其他部分只读（常见默认）。
- **Full RELRO**：`.got.plt` 在加载时全部解析并设为只读，无法覆写 GOT。
  - **绕过**：改用 `__malloc_hook` / `__free_hook` / `__libc_atexit` 等钩子。
- **检测**：`elf.relro` 返回 "Full"/"Partial"/"No"。

## 常用工具

### pwntools（Python 利用框架）
本系统集成以下 pwntools 封装工具（见 `src/tools/pwn_tools.py`）：

| 工具函数 | 用途 |
|---------|------|
| `pwn_checksec` | 检查保护机制、架构、关键函数地址、PLT/GOT 表 |
| `pwn_file_info` | file 命令、strings 提取关键字符串 |
| `pwn_disassemble` | 反汇编指定函数/地址 |
| `pwn_pattern_create` | 生成 cyclic pattern（定位溢出偏移） |
| `pwn_pattern_offset` | 计算地址在 pattern 中的偏移量 |
| `pwn_rop_gadgets` | 搜索 ROP gadgets（pop rdi/ret 等） |
| `pwn_rop_chain` | 自动构造调用指定函数的 ROP 链 |
| `pwn_shellcode_generate` | 生成 sh/exec/cat_flag 等 shellcode |
| `pwn_search_string` | 搜索二进制中字符串地址（如 `/bin/sh`） |
| `pwn_remote_exploit` | 连接远程服务发送 payload |
| `pwn_remote_interact` | 多条命令交互式交互 |
| `pwn_fmtstr_exploit` | 格式化字符串泄漏/写入 |

**pwntools 常用 API（本地脚本）**：
```python
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
io = process('./pwn')            # 本地进程
io = remote('host', port)        # 远程连接
io.sendline(b'A'*0x28)          # 发送一行
io.recvuntil(b'Input: ')        # 接收直到标记
io.interactive()                # 交互模式
elf = ELF('./pwn')              # 解析 ELF
libc = ELF('./libc.so.6')       # 加载 libc
rop = ROP(elf)                  # ROP 对象
```

### GDB（动态调试）
- `gdb ./pwn` 启动调试。
- 常用插件：**pwndbg** / **peda** / **gef**（推荐 pwndbg）。
- 关键命令：
  - `b *0x401234` 下断点；`b main` 按函数名断点。
  - `r < payload` 用文件输入运行；`c` 继续；`ni` 步过指令；`si` 步入指令。
  - `x/20gx $rsp` 查看栈；`x/20i $rip` 反汇编；`info reg` 查寄存器。
  - `checksec` 查看；`vmmap` 查看内存映射；`heap` 查看堆。
  - `got` 查看 GOT 表；`searchmem /bin/sh` 搜索内存。
- 调试 fork 程序：`set follow-fork-mode child`。

### objdump（静态反汇编）
- `objdump -d ./pwn` 反汇编所有代码段。
- `objdump -d ./pwn | grep main` 定位 main 函数。
- `objdump -R ./pwn` 查看重定位项（GOT）。
- `objdump -T ./pwn` 查看动态符号。
- `readelf -a ./pwn` 查看 ELF 全部信息。

### 其他辅助工具
- **ROPgadget**：`ROPgadget --binary ./pwn --only "pop|ret"` 查找 gadgets。
- **one_gadget**：`one_gadget ./libc.so.6` 查找 libc 中 execve("/bin/sh") 的 gadget。
- **LibcSearcher / libc-database**：通过泄漏的 libc 函数地址反查 libc 版本。
- **checksec**（脚本版）：`checksec --file=./pwn`。

## 解题流程（标准步骤）

1. **文件识别**：调用 `pwn_file_info` 获取文件类型、架构、字符串，初步判断题目类型。
2. **保护检查**：调用 `pwn_checksec` 获取 NX/PIE/Canary/RELRO 状态，决定利用方向。
3. **静态分析**：
   - `pwn_disassemble` 反汇编 `main`、`vuln` 等函数。
   - 用 `strings` / `objdump` 找危险函数（`gets`、`scanf("%s")`、`strcpy`、`printf`（无格式化参数））。
   - 查看 PLT/GOT 表，确认可用库函数（`system`、`puts`、`read` 等）。
4. **确定漏洞点与偏移**：
   - 栈溢出用 `pwn_pattern_create` 生成 pattern，`pwn_pattern_offset` 计算返回地址偏移。
   - 格式化字符串用 `%p.%p.%p` 泄漏栈确定参数偏移。
5. **构造 Payload**：根据保护机制选择利用技术（见后续各篇）。
6. **本地调试**：用 GDB 验证 payload，确认执行流控制成功。
7. **远程利用**：用 `pwn_remote_exploit` 或 `pwn_remote_interact` 打远程，获取 flag。

## 常见漏洞函数速查
| 函数 | 漏洞类型 | 说明 |
|------|---------|------|
| `gets(buf)` | 栈溢出 | 不限制读取长度 |
| `scanf("%s", buf)` | 栈溢出 | 不限制读取长度 |
| `strcpy(dst, src)` | 栈/堆溢出 | 不检查长度 |
| `strcat(dst, src)` | 栈/堆溢出 | 不检查长度 |
| `sprintf(buf, ...)` | 栈溢出 | 输出过长 |
| `printf(buf)` | 格式化字符串 | 用户控制格式 |
| `read(0, buf, n)` | 栈溢出 | n 大于 buf 大小 |
| `memcpy(dst, src, n)` | 堆/栈溢出 | n 过大 |

## 注意
- 32 位与 64 位调用约定不同：32 位参数压栈，64 位前 6 个参数用 RDI/RSI/RDX/RCX/R8/R9。
- 64 位地址含 `\x00`，写入时会被截断，注意 payload 顺序（地址放末尾）。
- 远程环境 libc 版本可能与本地不同，泄漏后务必用 `libc-database` 确认。
