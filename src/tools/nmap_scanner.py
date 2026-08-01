import subprocess
import os
import asyncio
import sys
import socket
from typing import Dict, Any, List


class NmapScanner:
    def __init__(self):
        self.nmap_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "thirdparty",
            "nmap"
        )
        self.nmap_bin = os.path.join(self.nmap_dir, "nmap")
        self.python_path = sys.executable

    def is_available(self) -> bool:
        return os.path.exists(self.nmap_bin) and os.access(self.nmap_bin, os.X_OK)

    async def scan(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        if self.is_available():
            return await self._scan_with_nmap(target, ports)
        else:
            return await self._scan_with_python(target, ports)

    async def _scan_with_nmap(self, target: str, ports: str) -> Dict[str, Any]:
        cmd = f"{self.nmap_bin} -sV -p {ports} {target}"

        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300
            )
            stdout, stderr = await process.communicate()
            
            result = stdout.decode("utf-8", errors="replace")
            if stderr:
                result += "\nSTDERR: " + stderr.decode("utf-8", errors="replace")
            
            if len(result) > 5000:
                result = result[:5000] + "\n\n[TRUNCATED] 输出过长，已截断"
            
            return {"success": True, "output": result, "tool": "nmap"}
        except asyncio.TimeoutError:
            return {"success": False, "error": "nmap 扫描超时", "tool": "nmap"}
        except Exception as e:
            return {"success": False, "error": str(e), "tool": "nmap"}

    async def _scan_with_python(self, target: str, ports: str) -> Dict[str, Any]:
        port_list = self._parse_ports(ports)

        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=1
                )

                banner = ""
                try:
                    writer.write(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(512), timeout=2)
                    banner = data.decode("utf-8", errors="ignore")[:200]
                except:
                    pass

                service = self._guess_service(port, banner)

                writer.close()
                await writer.wait_closed()

                return {
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": banner[:100] if banner else ""
                }
            except asyncio.TimeoutError:
                return {"port": port, "status": "filtered"}
            except ConnectionRefusedError:
                return {"port": port, "status": "closed"}
            except Exception:
                return {"port": port, "status": "error"}

        # 限制并发数，避免大范围扫描时资源耗尽
        semaphore = asyncio.Semaphore(100)

        async def limited_check(port):
            async with semaphore:
                return await check_port(port)

        tasks = [limited_check(port) for port in port_list]
        responses = await asyncio.gather(*tasks)

        open_ports = [r for r in responses if r.get("status") == "open"]
        open_ports.sort(key=lambda x: x["port"])

        return {
            "success": True,
            "target": target,
            "ports_scanned": len(port_list),
            "open_ports": open_ports,
            "tool": "python"
        }

    def _parse_ports(self, ports: str) -> List[int]:
        result = []
        
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                try:
                    start = int(start)
                    end = int(end)
                    result.extend(range(start, end + 1))
                except:
                    pass
            else:
                try:
                    result.append(int(part))
                except:
                    pass
        
        return list(set(result))

    def _guess_service(self, port: int, banner: str) -> str:
        if "HTTP" in banner or "Apache" in banner or "Nginx" in banner:
            return "http"
        if "SSH" in banner:
            return "ssh"
        if "FTP" in banner:
            return "ftp"
        if "MySQL" in banner:
            return "mysql"
        if "PostgreSQL" in banner:
            return "postgresql"
        if "Java" in banner or "JSP" in banner or "Servlet" in banner:
            return "java"
        if "Redis" in banner:
            return "redis"
        if "LDAP" in banner:
            return "ldap"
        if "RMI" in banner:
            return "rmi"
        
        common_ports = {
            21: "ftp",
            22: "ssh",
            80: "http",
            443: "https",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            1099: "rmi",
            389: "ldap",
            8080: "http-proxy",
            8443: "https",
        }
        
        return common_ports.get(port, "unknown")

    async def quick_scan(self, target: str) -> Dict[str, Any]:
        return await self.scan(target, "1-100")

    async def full_scan(self, target: str) -> Dict[str, Any]:
        return await self.scan(target, "1-65535")

    async def os_detection(self, target: str) -> Dict[str, Any]:
        if self.is_available():
            cmd = f"{self.nmap_bin} -O {target}"

            try:
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=300
                )
                stdout, stderr = await process.communicate()
                
                result = stdout.decode("utf-8", errors="replace")
                if stderr:
                    result += "\nSTDERR: " + stderr.decode("utf-8", errors="replace")
                
                if len(result) > 5000:
                    result = result[:5000] + "\n\n[TRUNCATED] 输出过长，已截断"
                
                return {"success": True, "output": result, "tool": "nmap"}
            except asyncio.TimeoutError:
                return {"success": False, "error": "nmap 扫描超时", "tool": "nmap"}
            except Exception as e:
                return {"success": False, "error": str(e), "tool": "nmap"}
        else:
            return {"success": False, "error": "nmap不可用，无法进行OS检测", "tool": "python"}
