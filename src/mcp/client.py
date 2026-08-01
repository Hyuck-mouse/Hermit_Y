import requests
from typing import Dict, Any, Optional


class MCPClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url

    # 获取MCP服务基础信息
    def get_server_info(self) -> Dict[str, Any]:
        try:
            response = requests.get(f"{self.base_url}/info")
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    # 查询MCP服务上注册的全部工具列表
    def list_tools(self) -> Dict[str, Any]:
        try:
            response = requests.get(f"{self.base_url}/tools")
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    # 调用指定工具，tool_name=工具名，**kwargs接收任意多工具入参
    def call_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.base_url}/call/{tool_name}",
                json=kwargs
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    # 判断MCP服务是否正常运行
    def health_check(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/health")
            return response.status_code == 200
        except:
            return False
