import logging
from typing import List, Dict, Any
import hashlib
from collections import Counter, deque

logger = logging.getLogger(__name__)


class AntiLoopDetector:
    """循环检测器：检测Agent是否陷入重复操作"""

    def __init__(self):
        self.tool_call_history: deque = deque(maxlen=30)
        self.previous_tool_signatures = []

    def detect_loop(self, history: List[Dict[str, Any]]) -> bool:
        if len(history) < 10:
            return False

        recent_tool_calls = []
        for entry in history[-25:]:
            content = entry.get("content", "")
            if isinstance(content, str) and "工具执行结果" in content:
                for line in content.split("\n"):
                    if "(" in line and "):" in line:
                        tool_sig = line.split("):")[0]
                        recent_tool_calls.append(tool_sig)

        if len(recent_tool_calls) >= 15:
            counter = Counter(recent_tool_calls)
            for sig, count in counter.items():
                if count >= 15:
                    logger.warning(f"检测1触发：工具调用 {sig} 重复 {count} 次")
                    return True

        return False