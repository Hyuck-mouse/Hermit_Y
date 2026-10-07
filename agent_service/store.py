"""任务 JSON 文件持久化:线程安全,读-改-写。"""
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


class TaskStore:
    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("[]", encoding="utf-8")

    def _read(self) -> list[dict]:
        return json.loads(self._path.read_text(encoding="utf-8"))

    def _write(self, items: list[dict]):
        self._path.write_text(
            json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def add(self, task: dict) -> dict:
        with self._lock:
            items = self._read()
            task["id"] = uuid.uuid4().hex[:12]
            task["created_at"] = datetime.now(timezone.utc).isoformat()
            task["status"] = "pending"
            items.append(task)
            self._write(items)
            return task

    def list_all(self, task_type: str | None = None) -> list[dict]:
        items = self._read()
        if task_type:
            items = [t for t in items if t.get("task_type") == task_type]
        return sorted(items, key=lambda t: t.get("created_at", ""), reverse=True)

    def get(self, task_id: str) -> dict | None:
        for t in self._read():
            if t.get("id") == task_id:
                return t
        return None

    def remove(self, task_id: str) -> bool:
        with self._lock:
            items = self._read()
            new = [t for t in items if t.get("id") != task_id]
            if len(new) == len(items):
                return False
            self._write(new)
            return True

    def update(self, task_id: str, **fields) -> dict | None:
        """局部更新任务字段(含 payload 内部),返回更新后的任务。"""
        with self._lock:
            items = self._read()
            for t in items:
                if t.get("id") == task_id:
                    for k, v in fields.items():
                        if k == "payload" and isinstance(v, dict) and isinstance(t.get("payload"), dict):
                            t["payload"].update(v)
                        else:
                            t[k] = v
                    self._write(items)
                    return t
            return None

    def claim_pending(self) -> dict | None:
        """原子领取最早的 pending 任务:pending→running+started_at。"""
        with self._lock:
            items = self._read()
            pending = [t for t in items if t.get("status") == "pending"]
            if not pending:
                return None
            task = min(pending, key=lambda t: t.get("created_at", ""))
            task["status"] = "running"
            task["started_at"] = datetime.now(timezone.utc).isoformat()
            self._write(items)
            return task

    def recover_stale(self) -> int:
        """服务重启时把遗留的 running 任务标记为失败(子进程已不在)。"""
        with self._lock:
            items = self._read()
            n = 0
            for t in items:
                if t.get("status") == "running":
                    t["status"] = "failed"
                    if isinstance(t.get("payload"), dict):
                        t["payload"]["error"] = "服务重启,执行中断"
                    n += 1
            if n:
                self._write(items)
            return n
