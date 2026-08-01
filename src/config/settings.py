from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    provider: str = "openai"
    api_key: str = ""
    base_url: Optional[str] = None
    default_model: str = "gpt-4o"
    temperature: float = 0.7
    max_tokens: int = 4096
    max_iterations: int = 50
    
    nmap_timeout: int = 60
    http_timeout: int = 30
    code_execution_timeout: int = 30
    
    knowledge_base_path: str = "./data/kb"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

    def validate_settings(self) -> bool:
        if not self.api_key:
            return False
        return True
