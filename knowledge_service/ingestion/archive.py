"""压缩包处理:解压到 data/extracted/ 并按内容哈希去重。

支持的格式: .zip / .tar.gz / .tgz / .tar(标准库)、.7z(py7zr 可选)、.rar(rarfile 可选)
原始压缩包保留不动;解压结果与原始目录结构对应,例如:
  src/009.第九天/zujian.zip  ->  data/extracted/009.第九天/zujian/

清单文件 data/extracted/.manifest.json 记录:
  archives: 每个压缩包的 size/mtime/解压目标/内部文件指纹(增量跳过未变化的包)
  hashes:   全局内容哈希 -> 首个来源路径(跨压缩包去重,pipeline 使用)
"""
import hashlib
import json
import logging
import shutil
import zipfile
import tarfile
from pathlib import Path
from typing import Any, Dict, Optional

import config

log = logging.getLogger(__name__)


def sha256_file(path: Path, max_bytes: Optional[int] = None) -> Optional[str]:
    """计算文件 sha256;超过 max_bytes 返回 None(由调用方降级为伪哈希)。"""
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(1 << 20)
            if not block:
                break
            h.update(block)
            read += len(block)
            if max_bytes and read >= max_bytes:
                return None
    return h.hexdigest()


def file_fingerprint(path: Path) -> str:
    """普通文件用内容 sha256;超大文件用 size+mtime 伪哈希保证速度。"""
    size = path.stat().st_size
    if size > config.MAX_HASH_BYTES:
        st = path.stat()
        return "size:%d:mtime:%d" % (st.st_size, int(st.st_mtime))
    return sha256_file(path) or "unhashable:%s" % path.name


def is_archive(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(s) for s in config.ARCHIVE_SUFFIXES)


def strip_archive_suffix(name: str) -> str:
    lower = name.lower()
    for s in config.ARCHIVE_SUFFIXES:
        if lower.endswith(s):
            return name[: -len(s)]
    return name


# ---------- 清单 ----------

def load_manifest() -> Dict[str, Any]:
    if config.MANIFEST_PATH.exists():
        try:
            with open(config.MANIFEST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.setdefault("archives", {})
            data.setdefault("hashes", {})
            return data
        except (json.JSONDecodeError, OSError):
            log.warning("清单文件损坏,将重建: %s", config.MANIFEST_PATH)
    return {"archives": {}, "hashes": {}}


def save_manifest(manifest: Dict[str, Any]) -> None:
    config.MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(config.MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)


# ---------- 安全解压 ----------

def _safe_target(dest: Path, member_name: str) -> Path:
    """防止路径穿越(Zip Slip)。"""
    target = (dest / member_name).resolve()
    if not str(target).startswith(str(dest.resolve()) + "/") and target != dest.resolve():
        raise ValueError("压缩包含非法路径: %s" % member_name)
    return target


def _decode_zip_name(name: str) -> str:
    """Windows 打包的 zip 常用 GBK 文件名,zipfile 会按 cp437 误解码,此处修正。"""
    try:
        return name.encode("cp437").decode("gbk")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return name


def _extract_zip(archive: Path, dest: Path) -> bool:
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = _decode_zip_name(info.filename)
            target = _safe_target(dest, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
            except (RuntimeError, NotImplementedError) as e:
                # 加密条目或未知压缩算法
                log.warning("跳过无法解压的条目 %s (%s): %s", name, archive.name, e)
    return True


def _extract_tar(archive: Path, dest: Path) -> bool:
    with tarfile.open(archive) as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            target = _safe_target(dest, m.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return True


def _extract_7z(archive: Path, dest: Path) -> bool:
    try:
        import py7zr
    except ImportError:
        log.warning("未安装 py7zr,跳过 7z 包: %s", archive)
        return False
    with py7zr.SevenZipFile(archive, "r") as z:
        z.extractall(dest)
    return True


def _extract_rar(archive: Path, dest: Path) -> bool:
    try:
        import rarfile
    except ImportError:
        log.warning("未安装 rarfile,跳过 rar 包: %s", archive)
        return False
    try:
        with rarfile.RarFile(archive) as rf:
            rf.extractall(dest)
    except rarfile.RarCannotExec:
        log.warning("系统缺少 unrar/bsdtar,跳过 rar 包: %s", archive)
        return False
    return True


def _dispatch(archive: Path, dest: Path) -> Optional[bool]:
    """返回 True=成功, False=缺少依赖跳过;异常向上抛。"""
    name = archive.name.lower()
    if name.endswith(".zip"):
        return _extract_zip(archive, dest)
    if name.endswith((".tar.gz", ".tgz", ".tar")):
        return _extract_tar(archive, dest)
    if name.endswith(".7z"):
        return _extract_7z(archive, dest)
    if name.endswith(".rar"):
        return _extract_rar(archive, dest)
    return False


# ---------- 主入口 ----------

def extract_archives(root: Path, dest_root: Path, manifest: Dict[str, Any],
                     root_tag: str = "src") -> Dict[str, int]:
    """扫描 root 下所有压缩包并解压到 dest_root,增量跳过未变化的包。

    manifest["archives"] 的 key 形如 "src:009.第九天/zujian.zip"。
    """
    stats = {"found": 0, "extracted": 0, "skipped_unchanged": 0,
             "skipped_too_big": 0, "failed": 0, "unsupported": 0}
    root = Path(root)
    if not root.exists():
        return stats

    for path in sorted(root.rglob("*")):
        if not path.is_file() or not is_archive(path):
            continue
        if any(part in config.IGNORE_DIRS for part in path.parts):
            continue
        # 不解压清单自身所在的已完成产物(二次扫描 extracted 时排除隐藏文件)
        if path.name.startswith("."):
            continue
        stats["found"] += 1
        rel = path.relative_to(root)
        key = "%s:%s" % (root_tag, rel.as_posix())
        st = path.stat()

        if st.st_size > config.MAX_ARCHIVE_BYTES:
            log.warning("压缩包过大(%.0fMB),跳过: %s", st.st_size / 1048576, path)
            stats["skipped_too_big"] += 1
            continue

        rec = manifest["archives"].get(key)
        if rec and rec.get("size") == st.st_size and rec.get("mtime") == int(st.st_mtime):
            stats["skipped_unchanged"] += 1
            continue

        dest = dest_root / rel.parent / strip_archive_suffix(path.name)
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)

        try:
            ok = _dispatch(path, dest)
        except (zipfile.BadZipFile, tarfile.TarError, ValueError, OSError) as e:
            log.warning("解压失败: %s (%s)", path, e)
            stats["failed"] += 1
            shutil.rmtree(dest, ignore_errors=True)
            continue

        if not ok:
            stats["unsupported"] += 1
            shutil.rmtree(dest, ignore_errors=True)
            continue

        files = {}
        for f in dest.rglob("*"):
            if f.is_file():
                files[f.relative_to(dest_root).as_posix()] = {
                    "sha256": file_fingerprint(f),
                    "size": f.stat().st_size,
                }
        manifest["archives"][key] = {
            "size": st.st_size,
            "mtime": int(st.st_mtime),
            "dest": dest.relative_to(dest_root).as_posix(),
            "files": files,
        }
        stats["extracted"] += 1
        log.info("已解压: %s -> %s (%d 个文件)", path.name, dest, len(files))

    return stats


def build_archive_index(manifest: Dict[str, Any]) -> Dict[str, str]:
    """dest 目录前缀 -> 压缩包标识,用于给解压产物标注来源。"""
    index = {}
    for key, rec in manifest.get("archives", {}).items():
        dest = rec.get("dest")
        if dest:
            index[dest] = key
    return index
