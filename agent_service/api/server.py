"""任务收发服务:CTF / 渗透测试任务的提交、查询、删除、执行。

收发 + JSON 持久化 + worker 执行线程(pending→running→done/failed)。

启动(在 agent_service/ 目录下):
  python -m api.server
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from store import TaskStore
from worker import start_worker

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="任务收发服务", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

store = TaskStore(Path(__file__).resolve().parents[1] / "data" / "tasks.json")
worker = None


@app.on_event("startup")
def startup():
    global worker
    worker = start_worker(store)


@app.get("/health")
def health():
    return {"status": "ok", "tasks": len(store.list_all())}


@app.post("/tasks")
def create_task(task: dict):
    task_type = task.get("task_type")
    if task_type not in ("ctf", "pentest"):
        raise HTTPException(400, "task_type 必须是 ctf 或 pentest")
    saved = store.add(task)
    log.info("task created: %s (%s)", saved["id"], task_type)
    return saved


@app.get("/tasks")
def list_tasks(task_type: str | None = None):
    return store.list_all(task_type)


@app.get("/tasks/{task_id}")
def get_task(task_id: str):
    t = store.get(task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    return t


@app.get("/tasks/{task_id}/log")
def get_task_log(task_id: str):
    t = store.get(task_id)
    if not t:
        raise HTTPException(404, "任务不存在")
    return worker.read_log(task_id) if worker else {"log": "", "size": 0, "truncated": False}


@app.delete("/tasks/{task_id}")
def delete_task(task_id: str):
    if not store.remove(task_id):
        raise HTTPException(404, "任务不存在")
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8766)
