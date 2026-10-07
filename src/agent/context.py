from typing import Dict, Any, Optional, List
from datetime import datetime
import json
import os
import hashlib


class ContextManager:
    def __init__(self):
        self.context: Dict[str, Any] = {}
        self.history: List[Dict[str, Any]] = []

    def set(self, key: str, value: Any):
        self.context[key] = value

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        return self.context.get(key, default)

    def delete(self, key: str):
        if key in self.context:
            del self.context[key]

    def clear(self):
        self.context = {}
        self.history = []

    def add_history(self, role: str, content: Any):
        self.history.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })

    def get_history(self) -> List[Dict[str, Any]]:
        return self.history

    def get_recent_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.history[-limit:]

    def get_context_summary(self) -> str:
        summary = []
        for key, value in self.context.items():
            # 关键工具结果（如 nmap_scan 的开放端口列表）不能被截断，
            # 否则 LLM 看不到目标端口（如 4712）会误判攻击路径
            value_str = str(value)
            if len(value_str) > 1000:
                value_str = value_str[:1000] + "...(truncated)"
            summary.append(f"{key}: {value_str}")
        return "\n".join(summary)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "context": self.context,
            "history": self.history
        }

    def from_dict(self, data: Dict[str, Any]):
        self.context = data.get("context", {})
        self.history = data.get("history", [])

    def save_to_file(self, filepath: str) -> bool:
        """保存当前会话到文件"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"保存会话失败: {e}")
            return False

    def load_from_file(self, filepath: str) -> bool:
        """从文件加载会话"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.from_dict(data)
            return True
        except Exception as e:
            print(f"加载会话失败: {e}")
            return False

    @staticmethod
    def get_session_filepath(url: str) -> str:
        """根据URL生成会话文件路径"""
        # 用URL的MD5哈希作为文件名，避免特殊字符问题
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()[:12]
        return os.path.join("sessions", f"ctf_{url_hash}.json")
