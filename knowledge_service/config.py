"""知识服务层全局配置。

所有路径相对 knowledge_service/ 目录;可通过环境变量覆盖关键项:
  KNOWLEDGE_SRC_DIR       外部原始资料目录(默认不设置,只扫项目内 data/raw/)
  KNOWLEDGE_EMBED_MODEL   嵌入模型(默认 BAAI/bge-large-zh-v1.5)
  KNOWLEDGE_EMBED_DEVICE  嵌入设备(cuda / mps / cpu,默认自动)
  KNOWLEDGE_API_PORT      API 端口(默认 8765)
  HF_ENDPOINT             HuggingFace 镜像(默认 hf-mirror.com,便于国内下载模型)

本机私有配置(如外部资料目录)写在与本文件同级的 .env.local 中(已被 .gitignore
排除,不会提交到 GitHub),格式为每行 KEY=VALUE。
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_env_local() -> None:
    """加载 .env.local(不入库),不覆盖已存在的环境变量。"""
    p = BASE_DIR / ".env.local"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_env_local()

# HuggingFace 国内镜像,需在 import sentence_transformers 之前设置
os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")

DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"                 # 手动投放的原始文档(项目内,可入库)
EXTRACTED_DIR = DATA_DIR / "extracted"     # 压缩包解压归档目录
CHROMA_DIR = DATA_DIR / "index" / "chroma"  # Chroma 持久化目录
MANIFEST_PATH = EXTRACTED_DIR / ".manifest.json"  # 解压/去重清单

# 外部资料目录:默认 None(GitHub 友好,不指向任何本机路径)。
# 本机使用时在 .env.local 里配置: KNOWLEDGE_SRC_DIR=/path/to/你的资料目录
_src_env = os.environ.get("KNOWLEDGE_SRC_DIR", "").strip()
SRC_DIR = Path(_src_env) if _src_env else None

# 摄入扫描的根目录:外部资料(可选) + 手动投放 + 解压产物
SCAN_ROOTS = [SRC_DIR, RAW_DIR, EXTRACTED_DIR]

# ---- 嵌入 / 向量库 ----
EMBEDDING_MODEL = os.environ.get("KNOWLEDGE_EMBED_MODEL", "BAAI/bge-large-zh-v1.5")
EMBEDDING_DEVICE = os.environ.get("KNOWLEDGE_EMBED_DEVICE") or None  # None=自动
# bge-large-zh 官方建议:查询侧加指令前缀,文档侧不加
QUERY_INSTRUCTION = "为这个句子生成表示以用于检索相关文章:"
COLLECTION_NAME = "knowledge_base"

# ---- 切片 ----
CHUNK_SIZE = int(os.environ.get("KNOWLEDGE_CHUNK_SIZE", "512"))
CHUNK_OVERLAP = int(os.environ.get("KNOWLEDGE_CHUNK_OVERLAP", "64"))

# ---- API ----
API_HOST = os.environ.get("KNOWLEDGE_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("KNOWLEDGE_API_PORT", "8765"))

# ---- 文件分类 ----
DOC_EXTS = {".md", ".pdf", ".docx", ".txt"}              # 知识文档
DATA_EXTS = {".json", ".yaml", ".yml", ".csv"}           # 配置/字典/payload
CODE_EXTS = {".py", ".go", ".js", ".java", ".c", ".cc",
             ".cpp", ".php", ".rb", ".sh", ".ps1"}       # 工具源码 → 技能卡
BINARY_EXTS = {".exe", ".bin", ".dll", ".so",
               ".dylib", ".jar", ".class"}               # 二进制工具 → 技能卡
ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz", ".tar", ".7z", ".rar")

# 扫描时忽略的目录
IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".idea",
               ".vscode", "venv", ".venv", "log", "logs",
               "wechat"}  # MFinder 的小程序运行时缓存,非课程知识

# ---- 摄入限制 ----
MAX_TEXT_BYTES = 5 * 1024 * 1024        # 单文件最多读取 5MB 文本
MAX_ARCHIVE_BYTES = 600 * 1024 * 1024   # 超过 600MB 的压缩包不解压(防止磁盘爆炸)
MAX_HASH_BYTES = 200 * 1024 * 1024      # 超过则用 size+mtime 伪哈希
MIN_TEXT_CHARS = 20                     # 提取文本过短则不摄入

# ---- 检索 ----
# 域外守门阈值:BM25 top1 原始分 / 查询有效token数(归一,消除查询长度影响)。
# 实测分布:域内查询归一分 1.78~5.17,域外(贪吃蛇/天气) 0.75~0.86,取中间值
BM25_GATE = float(os.environ.get("KNOWLEDGE_BM25_GATE", "1.3"))
