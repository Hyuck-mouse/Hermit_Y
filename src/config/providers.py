from typing import List, Dict, Any, Optional
from enum import Enum


class LLMProviderType(str, Enum):
    OPENAI = "openai"
    AZURE = "azure"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OPENROUTER = "openrouter"
    DEEPSEEK = "deepseek"
    LOCAL = "local"


class LLMProvider:
    def __init__(self, provider_type: LLMProviderType, api_key: str, base_url: Optional[str] = None):
        self.provider_type = provider_type
        self.api_key = api_key
        self.base_url = base_url

    def get_client(self):
        if self.provider_type == LLMProviderType.OPENAI:
            from openai import AsyncOpenAI
            return AsyncOpenAI(
                api_key=self.api_key,
                base_url=self.base_url
            )
        elif self.provider_type == LLMProviderType.AZURE:
            from openai import AsyncAzureOpenAI
            return AsyncAzureOpenAI(
                api_key=self.api_key,
                azure_endpoint=self.base_url
            )
        elif self.provider_type == LLMProviderType.OPENROUTER:
            from openai import AsyncOpenAI
            return AsyncOpenAI(
                api_key=self.api_key,
                base_url="https://openrouter.ai/api/v1"
            )
        elif self.provider_type == LLMProviderType.DEEPSEEK:
            from openai import AsyncOpenAI
            return AsyncOpenAI(
                api_key=self.api_key,
                base_url="https://api.deepseek.com/v1"
            )
        elif self.provider_type == LLMProviderType.LOCAL:
            from openai import AsyncOpenAI
            return AsyncOpenAI(
                api_key="sk-local",
                base_url=self.base_url or "http://localhost:8080/v1"
            )
        elif self.provider_type == LLMProviderType.ANTHROPIC:
            from anthropic import AsyncAnthropic
            return AsyncAnthropic(api_key=self.api_key)
        elif self.provider_type == LLMProviderType.GOOGLE:
            import google.generativeai as genai
            from google.generativeai import chat
            genai.configure(api_key=self.api_key)
            return genai
        else:
            raise NotImplementedError(f"Provider {self.provider_type} not implemented")

    @staticmethod
    def from_settings(settings) -> "LLMProvider":
        provider_type = getattr(LLMProviderType, settings.provider.upper(), LLMProviderType.OPENAI)
        return LLMProvider(
            provider_type=provider_type,
            api_key=settings.api_key,
            base_url=settings.base_url
        )
