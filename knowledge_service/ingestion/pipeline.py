"""摄入主流程:扫描 -> 解压 -> 去重 -> 分类(文档/技能卡/二进制) -> 切片 -> 嵌入入库。

dry-run 模式:只做扫描/解压/分类/切片统计,不加载嵌入模型、不写 Chroma、不保存清单。
"""
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import config
from ingestion.archive import (build_archive_index, extract_archives,
                               file_fingerprint, load_manifest, save_manifest)
from ingestion.enricher import Chunk, enrich, ext_to_content_type, infer_category
from ingestion.loader import iter_files, load_text
from ingestion.tool_card import (build_binary_card, build_code_card,
                                 find_readme_upwards, is_readme, is_tool_context)

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def _locate(path: Path, src_dir: Path,
            archive_index: Dict[str, str]) -> Tuple[str, str, str]:
    """返回 (source 相对路径, origin, 所属压缩包 key)。"""
    p = str(path)
    if p.startswith(str(config.EXTRACTED_DIR)):
        rel = path.relative_to(config.EXTRACTED_DIR).as_posix()
        arc = ""
        for dest_prefix, key in archive_index.items():
            if rel == dest_prefix or rel.startswith(dest_prefix + "/"):
                if len(dest_prefix) > len(arc):
                    arc = key
        return "extracted/" + rel, "archive", arc
    if p.startswith(str(config.RAW_DIR)):
        return path.relative_to(config.RAW_DIR).as_posix(), "raw", ""
    try:
        if src_dir:
            return path.relative_to(src_dir).as_posix(), "src", ""
    except ValueError:
        pass
    return path.as_posix(), "src", ""


def collect_chunks(src_dir, dry_run: bool,
                   with_archives: bool) -> Tuple[List[Chunk], Dict]:
    """扫描 + 解压 + 去重 + 分类 + 切片,返回 Chunk 列表与统计。

    src_dir 可为 None(未配置外部资料目录),此时只扫 raw/ 与 extracted/。
    """
    stats = {"archives": {}, "files_found": 0, "docs": 0, "tool_cards": 0,
             "binary_cards": 0, "duplicates_skipped": 0, "too_short_skipped": 0,
             "chunks": 0}

    manifest = load_manifest()
    if with_archives:
        if src_dir:
            s1 = extract_archives(src_dir, config.EXTRACTED_DIR, manifest, root_tag="src")
        else:
            s1 = {}
        # 第二遍:处理压缩包内嵌套的压缩包
        s2 = extract_archives(config.EXTRACTED_DIR, config.EXTRACTED_DIR,
                              manifest, root_tag="nested")
        stats["archives"] = {k: s1.get(k, 0) + s2.get(k, 0) for k in s1}
        if not dry_run:
            save_manifest(manifest)

    archive_index = build_archive_index(manifest)
    seen_hashes = manifest.setdefault("hashes", {})

    roots = [r for r in (src_dir, config.RAW_DIR, config.EXTRACTED_DIR) if r]
    wanted = config.DOC_EXTS | config.DATA_EXTS | config.CODE_EXTS | config.BINARY_EXTS
    candidates = list(iter_files(roots, wanted))
    stats["files_found"] = len(candidates)
    log.info("候选文件 %d 个", len(candidates))

    chunks: List[Chunk] = []
    for path in candidates:
        ext = path.suffix.lower()
        source, origin, arc_key = _locate(path, src_dir, archive_index)

        fp = file_fingerprint(path)
        if fp in seen_hashes:
            stats["duplicates_skipped"] += 1
            continue

        category_override = None
        ctype_override = None

        if ext in config.BINARY_EXTS:
            if find_readme_upwards(path):   # 所属工具已有 README 覆盖用法
                continue
            text = build_binary_card(path, source, origin, arc_key)
            ctype_override, category_override = "binary", "tools"
            stats["binary_cards"] += 1
        elif ext in config.CODE_EXTS:
            if find_readme_upwards(path):
                continue
            text = build_code_card(path, source, origin, arc_key)
            ctype_override, category_override = "tool_card", "tools"
            stats["tool_cards"] += 1
        else:
            text = load_text(path)
            if not text or len(text.strip()) < config.MIN_TEXT_CHARS:
                stats["too_short_skipped"] += 1
                continue
            if is_readme(path) and is_tool_context(path.parent):
                # 工具目录里的 README/使用说明 → 技能卡
                ctype_override, category_override = "tool_card", "tools"
                stats["tool_cards"] += 1
            else:
                ctype = ext_to_content_type(ext)
                stats["docs"] += 1

        seen_hashes[fp] = source
        file_chunks = enrich(source, origin, text, ext,
                             category=category_override,
                             content_type=ctype_override,
                             archive=arc_key)
        chunks.extend(file_chunks)

    stats["chunks"] = len(chunks)
    if not dry_run:
        save_manifest(manifest)
    return chunks, stats


def run_ingest(src_dir=None, dry_run: bool = False,
               with_archives: bool = True, batch_size: int = 64) -> Dict:
    """完整摄入入口。dry_run=True 时不加载模型、不写库、不保存清单。

    src_dir=None 时使用 config.SRC_DIR(可能为 None,即只扫项目内目录)。
    """
    src_dir = Path(src_dir) if src_dir else config.SRC_DIR
    log.info("开始摄入: src=%s dry_run=%s", src_dir or "(未配置,仅扫 data/raw 与解压产物)", dry_run)

    chunks, stats = collect_chunks(src_dir, dry_run=dry_run,
                                   with_archives=with_archives)

    stats["samples"] = [
        {"source": c.source, "category": c.category,
         "content_type": c.content_type,
         "preview": c.text[:80].replace("\n", " ")}
        for c in chunks[:50]
    ]

    if dry_run:
        log.info("[dry-run] 跳过嵌入与入库")
        return stats
    if not chunks:
        log.warning("没有可摄入的内容")
        return stats

    from indexing.embedder import Embedder
    from indexing.store import VectorStore
    embedder = Embedder()
    store = VectorStore()
    written = store.add_chunks(chunks, embedder, batch_size=batch_size)
    stats["written"] = written
    stats["collection_count"] = store.count()
    log.info("灌库完成: 写入 %d 个片段, 库内共 %d 条", written, store.count())
    return stats
