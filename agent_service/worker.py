"""任务执行线程:领取 pending 任务,起 main.py 子进程,状态流转+结果提取。

设计约束(按用户确认的范围):
  - 单并发:一次只跑一个任务,跑完才领下一个
  - 无取消机制;服务重启时 running 任务由 recover_stale 标记失败
  - 不用 SSE,前端靠轮询

CLI 映射:
  ctf     → venv/bin/python src/main.py ctf "<challenge>"
  pentest → venv/bin/python src/main.py scan "<第一个目标值>"
"""
import logging
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

AGENT_SERVICE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = AGENT_SERVICE_DIR.parent
PYTHON = PROJECT_ROOT / "venv" / "bin" / "python"
LOG_DIR = AGENT_SERVICE_DIR / "data" / "task_logs"

POLL_INTERVAL = 3.0
TASK_TIMEOUT = 30 * 60  # 单任务上限30分钟
LOG_TAIL_BYTES = 12000

FLAG_RE = re.compile(r"\[FLAG\][^\S\n]*`?([^`\n]+)")
SESSION_RE = re.compile(r"会话已保存到:\s*(\S+)")
ERROR_RE = re.compile(r"\[ERROR\]")
MAX_ITER_RE = re.compile(r"达到最大迭代次数")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_command(task: dict) -> list[str] | None:
    """任务→CLI命令。返回 None 表示无法构造。"""
    payload = task.get("payload") or {}
    if task.get("task_type") == "ctf":
        remote_url = (payload.get("remoteUrl") or "").strip()
        title = (payload.get("title") or "").strip()
        desc = (payload.get("description") or "").strip()
        # 有URL直接用(实战验证过的形态);没URL用标题+描述让Agent自行分析
        challenge = remote_url or "\n".join(x for x in (title, desc[:500]) if x)
        if not challenge:
            return None
        return [str(PYTHON), "src/main.py", "ctf", challenge]
    if task.get("task_type") == "pentest":
        targets = payload.get("targets") or []
        first = next((t.get("value", "").strip() for t in targets if t.get("value")), "")
        if not first:
            return None
        return [str(PYTHON), "src/main.py", "scan", first]
    return None


class TaskWorker(threading.Thread):
    def __init__(self, store):
        super().__init__(daemon=True, name="task-worker")
        self.store = store
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log.info("worker started, polling every %ss", POLL_INTERVAL)
        while not self._stop.is_set():
            task = self.store.claim_pending()
            if not task:
                self._stop.wait(POLL_INTERVAL)
                continue
            log.info("claimed task %s (%s)", task["id"], task.get("task_type"))
            try:
                self._execute(task)
            except Exception:  # worker线程绝不能死
                log.exception("task %s crashed", task["id"])
                self.store.update(task["id"], status="failed",
                                  payload={"error": "worker内部异常,详见服务日志"})

    # ---------- 执行 ----------

    def _execute(self, task: dict):
        task_id = task["id"]
        cmd = build_command(task)
        if not cmd:
            self.store.update(task_id, status="failed",
                              payload={"error": "任务缺少可执行的目标(无URL/目标值)"})
            return

        log_path = LOG_DIR / f"{task_id}.log"
        with log_path.open("w", encoding="utf-8") as lf:
            lf.write(f"# cmd: {' '.join(cmd)}\n# started: {_now()}\n")
            lf.flush()
            try:
                proc = subprocess.Popen(
                    cmd, cwd=str(PROJECT_ROOT),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
            except Exception as e:
                self.store.update(task_id, status="failed",
                                  payload={"error": f"子进程启动失败: {e}"})
                return

            chunks: list[str] = []
            start = time.monotonic()
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    lf.write(line)
                    chunks.append(line)
                    if time.monotonic() - start > TASK_TIMEOUT:
                        proc.kill()
                        chunks.append(f"\n# 超时({TASK_TIMEOUT // 60}分钟),已终止\n")
                        break
                code = proc.wait(timeout=10)
            except Exception as e:
                proc.kill()
                code = -1
                chunks.append(f"\n# 执行异常: {e}\n")

        output = "".join(chunks)
        elapsed = time.monotonic() - start
        fields: dict = {"finished_at": _now()}
        payload_out: dict = {"log_path": str(log_path)}

        flag_m = FLAG_RE.search(output)
        if flag_m:
            payload_out["result"] = {"flag": flag_m.group(1).strip()}
        session_m = SESSION_RE.search(output)
        if session_m:
            payload_out["session_path"] = session_m.group(1)

        # 状态判定优先级:进程退出码 > [FLAG] > [ERROR] > 无标记默认done
        if code != 0:
            fields["status"] = "failed"
            payload_out["error"] = f"退出码 {code}" + ("(超时)" if "超时" in output else "")
        elif flag_m:
            fields["status"] = "done"
        elif MAX_ITER_RE.search(output) or (ERROR_RE.search(output) and not flag_m):
            fields["status"] = "failed"
            payload_out["error"] = "达到最大迭代次数" if MAX_ITER_RE.search(output) else "Agent报错但未提取到flag"
        else:
            fields["status"] = "done"  # exit 0 且无 [ERROR],视为成功(如信息收集类任务)
        fields["payload"] = payload_out
        self.store.update(task_id, **fields)
        log.info("task %s finished: %s (%.0fs)", task_id, fields["status"], elapsed)

    # ---------- 日志读取(供 server 调) ----------

    def read_log(self, task_id: str) -> dict:
        log_path = LOG_DIR / f"{task_id}.log"
        if not log_path.exists():
            return {"log": "", "size": 0, "truncated": False}
        data = log_path.read_text(encoding="utf-8", errors="replace")
        size = len(data)
        truncated = size > LOG_TAIL_BYTES
        return {"log": data[-LOG_TAIL_BYTES:] if truncated else data,
                "size": size, "truncated": truncated}


def start_worker(store) -> TaskWorker:
    """启动前先回收遗留 running 任务,再拉起常驻线程。"""
    stale = store.recover_stale()
    if stale:
        log.warning("recovered %s stale running task(s) as failed", stale)
    w = TaskWorker(store)
    w.start()
    return w
