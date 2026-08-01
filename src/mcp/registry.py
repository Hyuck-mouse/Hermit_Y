from typing import Dict, Any, Callable, List
import json


class MCPRegistry:
    def __init__(self):
        # 空字典，存储所有注册的工具
        # key=工具名，value=工具详情（函数、描述、参数
        self.tools: Dict[str, Dict[str, Any]] = {}
        # 固定服务元信息，客户端调用/info接口时返回
        self.server_info = {
            "name": "Pentest Agent MCP Server",
            "version": "0.1.0",
            "description": "AI-powered penetration testing MCP server"
        }

    # 注册工具方法：把自定义函数存入registry管理
    # name:工具名称；func:要执行的函数；description:工具说明；parameters:参数定义
    def register_tool(self, name: str, func: Callable, description: str, parameters: Dict[str, str]):
        # 将工具信息存入self.tools字典
        self.tools[name] = {
            "func": func,
            "description": description,
            "parameters": parameters # 工具需要哪些入参
        }

    # 根据工具名查询单个工具完整信息
    def get_tool(self, name: str):
        return self.tools.get(name)

    # 输出所有工具对外展示信息（隐藏内部func，只给客户端看名称/描述/参数）
    def list_tools(self) -> List[Dict[str, Any]]:
        # 新建空列表存放工具对外信息
        tool_list = []
        # 遍历self.tools里所有注册的工具
        for name, tool in self.tools.items():
            tool_list.append({
                "name": name,
                "description": tool["description"],
                "parameters": tool["parameters"]
            })
        # 返回整理好的工具列表，给 /tools 接口调用
        return tool_list

    # 返回服务基础信息，给 /info 接口调用
    def get_server_info(self) -> Dict[str, str]:
        return self.server_info
