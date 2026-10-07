"""重建向量库:清空 Chroma 与解压清单后重新灌库。

用法: python scripts/rebuild.py [--yes]
"""
import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from ingestion.pipeline import run_ingest


def main():
    parser = argparse.ArgumentParser(description="重建知识库向量索引")
    parser.add_argument("--yes", action="store_true", help="跳过确认")
    args = parser.parse_args()

    if not args.yes:
        confirm = input("将删除 %s 与解压清单并重新灌库,确认? [y/N] " % config.CHROMA_DIR)
        if confirm.strip().lower() != "y":
            print("已取消")
            return

    if config.CHROMA_DIR.exists():
        shutil.rmtree(config.CHROMA_DIR, ignore_errors=True)
        print("已清空向量库: %s" % config.CHROMA_DIR)
    if config.MANIFEST_PATH.exists():
        config.MANIFEST_PATH.unlink()
        print("已清空清单: %s" % config.MANIFEST_PATH)

    stats = run_ingest(src_dir=config.SRC_DIR, dry_run=False, with_archives=True)
    print("\n重建完成: %s" % stats)


if __name__ == "__main__":
    main()
