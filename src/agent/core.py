from typing import Optional, Dict, Any, List
from .context import ContextManager
from .loop import LoopController
from .tools import ToolDispatcher
from .anti_loop import AntiLoopDetector
from .llm_client import LLMClient
from ..config.settings import Settings
from ..config.providers import LLMProviderType


class PentestAgent:
    def __init__(self, settings: Optional[Settings] = None, provider_type: Optional[LLMProviderType] = None, mode: str = "pentest"):
        self.settings = settings or Settings()
        self.provider_type = provider_type or LLMProviderType(self.settings.provider.lower())
        self.llm_client = LLMClient(self.settings, self.provider_type)
        self.context_manager = ContextManager()
        self.tool_dispatcher = ToolDispatcher()
        self.anti_loop_detector = AntiLoopDetector()
        self.loop_controller = LoopController(
            llm_client=self.llm_client,
            context_manager=self.context_manager,
            tool_dispatcher=self.tool_dispatcher,
            anti_loop_detector=self.anti_loop_detector,
            mode=mode
        )

    def add_tool(self, name: str, func, description: str, parameters: Dict[str, Any],
                 required_params: List[str] = None):
        self.tool_dispatcher.register_tool(name, func, description, parameters, required_params)

    def set_context(self, key: str, value: Any):
        self.context_manager.set(key, value)

    async def run(self, prompt: str) -> str:
        return await self.loop_controller.run(prompt)

    async def analyze_intent(self, prompt: str) -> Dict[str, Any]:
        system_prompt = self._build_system_prompt()
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        response = await self.llm_client.chat_completion(messages)
        return response

    def _build_system_prompt(self) -> str:
        tools_desc = self.tool_dispatcher.get_tools_description()
        return f"""
你是一名专业的渗透测试工程师和安全研究员。

约束条件：
- 仅测试授权目标
- 不破坏系统正常运行
- 遵守法律法规

知识库规则：
- 涉及具体漏洞名、工具名、课程内容时，必须先调用 knowledge_search 检索本地知识库，拿到结果后再结合推理
- knowledge_search 返回 degraded=true 或 results 为空时，标注"未命中知识库"，再基于自身知识回答并说明不确定性，禁止编造具体漏洞细节

可用工具：
{tools_desc}

输出格式：
- 发现漏洞时输出: [VULN] 类型:XXX 证据:XXX
- 完成测试时输出: [COMPLETE] 总结:XXX

思考过程：
- 仔细分析用户的请求
- 选择最合适的工具来完成任务
- 如果需要多步操作，逐步执行
- 及时总结发现的信息
"""
