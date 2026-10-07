"""灌库入口:扫描 src 目录 -> 解压压缩包 -> 切片 -> 嵌入 -> 写入 Chroma。

用法(在 knowledge_service/ 目录下,建议先激活 venv):
  python scripts/ingest.py                 # 正式灌库(增量)
  python scripts/ingest.py --dry-run       # 只扫描统计,不加载模型、不写库
  python scripts/ingest.py --src <目录>    # 覆盖默认扫描目录
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from ingestion.pipeline import run_ingest


def main():
    parser = argparse.ArgumentParser(description="知识库灌库")
    parser.add_argument("--src", default=None,
                        help="原始资料目录(默认取 config.SRC_DIR)")
    parser.add_argument("--dry-run", action="store_true",
                        help="只扫描/解压/统计,不加载嵌入模型、不写入向量库")
    parser.add_argument("--no-archives", action="store_true", help="跳过压缩包解压")
    args = parser.parse_args()

    src = Path(args.src) if args.src else config.SRC_DIR
    stats = run_ingest(src_dir=src, dry_run=args.dry_run,
                       with_archives=not args.no_archives)

    print("\n==== 摄入统计 ====")
    for k, v in stats.items():
        if k == "samples":
            continue
        print("  %s: %s" % (k, v))
    if args.dry_run and stats.get("samples"):
        print("\n==== 片段样例(前5条) ====")
        for s in stats["samples"][:5]:
            print("  - [%s|%s] %s: %s..." % (
                s["category"], s["content_type"], s["source"], s["preview"]))


if __name__ == "__main__":
    main()
