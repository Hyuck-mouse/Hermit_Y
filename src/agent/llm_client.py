import logging
from typing import List, Dict, Any, Optional, Union
from openai import AsyncOpenAI
from ..config.settings import Settings
from ..config.providers import LLMProvider, LLMProviderType

logger = logging.getLogger(__name__)


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
            
            response = await self.client.chat.completions.create(
                model=model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens
            )
            
            logger.debug(f"LLM调用成功!")
            
            message = response.choices[0].message
            
            reasoning_content = getattr(message, 'reasoning_content', None)
            if reasoning_content:
                self._last_reasoning_content = reasoning_content
            
            return {
                "content": message.content or "",
                "tool_calls": message.tool_calls or []
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
        processed_messages = []
        for msg in messages:
            if self._last_reasoning_content and msg.get("role") == "user":
                processed_messages.append({
                    "role": "user",
                    "content": msg["content"],
                    "reasoning_content": self._last_reasoning_content
                })
                self._last_reasoning_content = None
            else:
                processed_messages.append(msg)
        return processed_messages
