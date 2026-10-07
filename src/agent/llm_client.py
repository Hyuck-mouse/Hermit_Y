import logging
from typing import List, Dict, Any, Optional, Union
from openai import AsyncOpenAI
from ..config.settings import Settings
from ..config.providers import LLMProvider, LLMProviderType

logger = logging.getLogger(__name__)


class LLMBreakerError(Exception):
    """LLM 连续协议错误触发熔断(不可通过重试自愈),应终止任务。"""

    def __init__(self, consecutive_failures: int, reason: str, original_error: str = ""):
        self.consecutive_failures = consecutive_failures
        self.reason = reason
        self.original_error = original_error[:300]
        super().__init__(
            f"LLM熔断: 连续{consecutive_failures}次失败({reason}); 原始错误: {self.original_error}"
        )


class LLMClient:
    def __init__(self, settings: Settings, provider_type: LLMProviderType = LLMProviderType.OPENAI):
        self.settings = settings
        self.provider_type = provider_type
        
        provider = LLMProvider(
            provider_type=provider_type,
            api_key=settings.api_key,
            base_url=settings.base_url
        )
        self.client = provider.get_client()
        self._last_reasoning_content = None
        self._consecutive_400_count = 0  # 400熔断计数器

    async def chat_completion(self, messages: List[Dict[str, str]], model: Optional[str] = None) -> str:
        model = model or self.settings.default_model
        
        if self.provider_type in [LLMProviderType.OPENAI, LLMProviderType.AZURE, LLMProviderType.DEEPSEEK, LLMProviderType.OPENROUTER, LLMProviderType.LOCAL]:
            response = await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens
            )
            return response.choices[0].message.content or ""
        elif self.provider_type == LLMProviderType.ANTHROPIC:
            response = await self.client.messages.create(
                model=model,
                messages=messages,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens
            )
            return response.content[0].text or ""
        elif self.provider_type == LLMProviderType.GOOGLE:
            response = await self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens
            )
            return response.choices[0].message.content or ""
        else:
            raise NotImplementedError(f"Provider {self.provider_type} not implemented")

    async def tool_call_completion(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]], model: Optional[str] = None) -> Dict[str, Any]:
        model = model or self.settings.default_model
        
        logger.debug(f"LLM Provider: {self.provider_type}, Model: {model}")
        logger.debug(f"LLM Base URL: {self.settings.base_url}")
        logger.debug(f"LLM API Key: {self.settings.api_key[:10]}...")
        
        if self.provider_type in [LLMProviderType.OPENAI, LLMProviderType.AZURE, LLMProviderType.DEEPSEEK, LLMProviderType.OPENROUTER, LLMProviderType.LOCAL]:
            logger.debug(f"开始调用 chat.completions.create...")
            logger.debug(f"Tools JSON: {tools[:2]}")
            
            if self.provider_type == LLMProviderType.DEEPSEEK:
                messages = self._prepare_deepseek_messages(messages)

            # 400熔断:连续3次400则放弃当前迭代,避免无限重试烧API
            if self.provider_type == LLMProviderType.DEEPSEEK:
                try:
                    response = await self.client.chat.completions.create(
                        model=model,
                        messages=messages,
                        tools=tools,
                        tool_choice="auto",
                        temperature=self.settings.temperature,
                        max_tokens=self.settings.max_tokens
                    )
                    self._consecutive_400_count = 0  # 成功则重置
                except Exception as e:
                    if "400" in str(e) and "reasoning_content" in str(e):
                        self._consecutive_400_count += 1
                        logger.warning(f"DeepSeek 400 (reasoning_content), 第{self._consecutive_400_count}次")
                        if self._consecutive_400_count >= 3:
                            logger.error(f"DeepSeek 400熔断触发,连续{self._consecutive_400_count}次失败,放弃当前迭代")
                            fail_count = self._consecutive_400_count
                            self._consecutive_400_count = 0  # 归零,防止跨任务污染
                            raise LLMBreakerError(
                                consecutive_failures=fail_count,
                                reason="reasoning_content 400 协议错误",
                                original_error=str(e),
                            ) from e
                    raise
            else:
                response = await self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=self.settings.temperature,
                    max_tokens=self.settings.max_tokens
                )
            
            # 记录诊断信息：finish_reason 和 token usage
            choice = response.choices[0]
            finish_reason = getattr(choice, 'finish_reason', 'unknown')
            usage = getattr(response, 'usage', None)
            if usage:
                logger.debug(f"LLM诊断: finish_reason={finish_reason}, prompt_tokens={usage.prompt_tokens}, completion_tokens={usage.completion_tokens}, total_tokens={usage.total_tokens}")
            else:
                logger.debug(f"LLM诊断: finish_reason={finish_reason}, usage=None")
            
            # 如果finish_reason是length，说明输出被max_tokens截断
            if finish_reason == "length":
                logger.warning(f"LLM输出被截断(finish_reason=length), completion_tokens={usage.completion_tokens if usage else '?'}, max_tokens={self.settings.max_tokens}")
            
            logger.debug(f"LLM调用成功!")
            
            message = choice.message
            
            reasoning_content = getattr(message, 'reasoning_content', None)
            if reasoning_content:
                self._last_reasoning_content = reasoning_content
            
            return {
                "content": message.content or "",
                "tool_calls": message.tool_calls or [],
                "finish_reason": finish_reason,
                "usage": {
                    "prompt_tokens": usage.prompt_tokens if usage else 0,
                    "completion_tokens": usage.completion_tokens if usage else 0,
                    "total_tokens": usage.total_tokens if usage else 0,
                } if usage else None,
            }
        elif self.provider_type == LLMProviderType.ANTHROPIC:
            tool_list = []
            for tool in tools:
                if tool.get("type") == "function":
                    func = tool["function"]
                    tool_list.append({
                        "name": func["name"],
                        "description": func["description"],
                        "input_schema": {
                            "type": "object",
                            "properties": func.get("parameters", {})
                        }
                    })
            
            response = await self.client.messages.create(
                model=model,
                messages=messages,
                tools=tool_list,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens
            )
            
            tool_calls = []
            if response.tool_calls:
                for tc in response.tool_calls:
                    tool_calls.append({
                        "function": {
                            "name": tc.name,
                            "arguments": tc.input
                        }
                    })
            
            return {
                "content": response.content[0].text if response.content else "",
                "tool_calls": tool_calls
            }
        elif self.provider_type == LLMProviderType.GOOGLE:
            response = await self.client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens
            )
            return {
                "content": response.choices[0].message.content or "",
                "tool_calls": response.choices[0].message.tool_calls or []
            }
        else:
            raise NotImplementedError(f"Provider {self.provider_type} not implemented")

    def _prepare_deepseek_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """把 reasoning_content 附加到对应的 assistant 消息上,而非下一条 user。

        DeepSeek 协议要求: reasoning_content 必须属于产生它的 assistant 消息,
        否则长会话经过压缩/截断后位置错位,触发 400。
        """
        processed_messages = []
        for msg in messages:
            if self._last_reasoning_content and msg.get("role") == "assistant":
                msg_copy = dict(msg)
                msg_copy["reasoning_content"] = self._last_reasoning_content
                processed_messages.append(msg_copy)
                self._last_reasoning_content = None
            else:
                processed_messages.append(msg)
        return processed_messages
