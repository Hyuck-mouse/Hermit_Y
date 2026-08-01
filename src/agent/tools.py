from typing import Dict, Any, Callable, Optional, List
import asyncio
import json


class ToolDispatcher:
    def __init__(self):
        self.tools: Dict[str, Dict[str, Any]] = {}

    def register_tool(self, name: str, func: Callable, description: str,
                      parameters: Dict[str, Any], required_params: List[str] = None):
        self.tools[name] = {
            "func": func,
            "description": description,
            "parameters": parameters,
            "required_params": required_params or list(parameters.keys())
        }

    async def call_tool(self, name: str, **kwargs) -> Any:
        if name not in self.tools:
            return f"工具 {name} 未注册"
        
        tool = self.tools[name]
        try:
            if asyncio.iscoroutinefunction(tool["func"]):
                return await tool["func"](**kwargs)
            else:
                return tool["func"](**kwargs)
        except Exception as e:
            return f"调用工具 {name} 时发生错误: {str(e)}"

    def get_tools_description(self) -> str:
        descriptions = []
        for name, tool in self.tools.items():
            params = ", ".join([f"{k}: {v}" for k, v in tool["parameters"].items()])
            req = tool.get("required_params", list(tool["parameters"].keys()))
            req_str = f" [必需: {', '.join(req)}]" if req else ""
            descriptions.append(f"- {name}: {tool['description']} (参数: {params}){req_str}")
        return "\n".join(descriptions)

    def get_tools_json(self) -> List[Dict[str, Any]]:
        tools_json = []
        for name, tool in self.tools.items():
            properties = {}
            required = tool.get("required_params", list(tool["parameters"].keys()))
            
            for param_name, param_type in tool["parameters"].items():
                if param_type == "array":
                    properties[param_name] = {"type": "array", "items": {"type": "string"}}
                else:
                    properties[param_name] = {"type": param_type}
            
            tool_entry = {
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool["description"],
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required
                    }
                }
            }
            tools_json.append(tool_entry)
        return tools_json

    def get_tool_names(self) -> List[str]:
        return list(self.tools.keys())

    def get_tool(self, name: str) -> Optional[Dict[str, Any]]:
        return self.tools.get(name)
