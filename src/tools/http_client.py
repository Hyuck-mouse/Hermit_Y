import asyncio
import aiohttp
from typing import Dict, Any, Optional, Tuple
import urllib.parse


class HTTPClient:
    def __init__(self):
        pass

    async def _get_session(self) -> aiohttp.ClientSession:
        # 每次创建新会话，由调用方负责关闭，避免会话泄漏和并发污染
        timeout = aiohttp.ClientTimeout(total=5)
        return aiohttp.ClientSession(timeout=timeout)

    async def request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        session = await self._get_session()
        method = method.upper()

        try:
            async with session.request(method, url, **kwargs) as response:
                try:
                    content = await response.json()
                except Exception:
                    try:
                        content = await response.text()
                    except UnicodeDecodeError:
                        # 二进制响应无法用 utf-8 解码，返回 repr 避免空错误
                        raw = await response.read()
                        content = f"<binary {len(raw)} bytes>"

                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "content": content,
                    "url": str(response.url)
                }
        except asyncio.TimeoutError:
            return {"error": "HTTP请求超时: 5秒内无响应（端口可能不是HTTP服务）", "status": None}
        except aiohttp.ClientConnectorError as e:
            return {"error": f"HTTP连接失败: {str(e) or '连接被拒绝'}（端口可能未开放或非HTTP服务）", "status": None}
        except aiohttp.ServerDisconnectedError as e:
            return {"error": f"HTTP服务断开连接: {str(e) or '服务端主动关闭'}（可能非HTTP服务，建议用log4j_scan检测）", "status": None}
        except aiohttp.ClientResponseError as e:
            return {"error": f"HTTP响应错误: {str(e) or e.message}", "status": getattr(e, 'status', None)}
        except aiohttp.ClientError as e:
            # 兜底：避免 str(e) 返回空字符串导致 LLM 误判
            err_msg = str(e) or type(e).__name__
            return {"error": f"HTTP请求失败: {err_msg}（端口可能不是HTTP服务，建议用log4j_scan检测）", "status": None}
        except Exception as e:
            err_msg = str(e) or type(e).__name__
            return {"error": f"HTTP请求异常: {err_msg}", "status": None}
        finally:
            await session.close()

    async def get(self, url: str, params: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return await self.request("GET", url, params=params, headers=headers)

    async def post(self, url: str, data: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return await self.request("POST", url, data=data, json=json, headers=headers)

    async def put(self, url: str, data: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return await self.request("PUT", url, data=data, headers=headers)

    async def delete(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return await self.request("DELETE", url, headers=headers)

    async def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return await self.request("HEAD", url, headers=headers)

    async def options(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return await self.request("OPTIONS", url, headers=headers)

    async def close(self):
        # 兼容旧调用：现在 session 在每次 request 后自动关闭
        pass

    async def scan_endpoint(self, url: str) -> Dict[str, Any]:
        results = []
        
        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        tasks = [self.request(method, url) for method in methods]
        responses = await asyncio.gather(*tasks)
        
        for method, response in zip(methods, responses):
            if response.get("status"):
                results.append({
                    "method": method,
                    "status": response["status"],
                    "content_length": len(str(response.get("content", "")))
                })
        
        return {"url": url, "methods": results}
