"""检索质量评测:固化 4 个测试用例,与 2026-09-26 修复前基线对比。

用法: 服务启动后执行 venv/bin/python scripts/eval.py

基线(修复前,纯向量检索):
  测试1 若依未授权        top1=若依漏洞挖掘.md      score=0.4634(排序对,分数偏低)
  测试2 heapdump/binary   top1=JDumpSpider          score=0.2571(用途错标"扫描")
  测试3 未授权/vuln_kb    top2=垃圾碎片"Content-Type:..." score=0.4045
  测试4 负样本贪吃蛇      top1=swagger README       score=0.5523(比正样本还高!)
"""
import json
import sys
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:8765"

CASES = [
    {
        "name": "1.正样本:若依未授权访问",
        "query": "若依 未授权访问", "top_k": 3,
        "expect": "top1 source 含 '若依漏洞挖掘'",
        "check": lambda r: "若依漏洞挖掘" in (r["results"][0]["source"] if r["results"] else ""),
    },
    {
        "name": "2.工具卡:heapdump(binary 过滤)",
        "query": "heapdump", "top_k": 3, "content_type": "binary",
        "expect": "top1 是 JDumpSpider 且用途含 'heapdump'",
        "check": lambda r: (r["results"] and "JDumpSpider" in r["results"][0]["source"]
                            and "heapdump" in r["results"][0]["content"]),
    },
    {
        "name": "3.vuln_kb 过滤:未授权",
        "query": "未授权", "top_k": 3, "category": "vuln_kb",
        "expect": "结果中无 'Content-Type:' 单行垃圾碎片",
        "check": lambda r: all("Content-Type" not in h["content"] or len(h["content"]) > 60
                               for h in r["results"]),
    },
    {
        "name": "4.负样本:Python 贪吃蛇(硬指标)",
        "query": "如何用 Python 写贪吃蛇", "top_k": 3,
        "expect": "top1 不得是 swagger 工具 README(修复前 score=0.5523 反超正样本)",
        "check": lambda r: not (r["results"] and "swagger" in r["results"][0]["source"].lower()),
    },
]


def main():
    fails = 0
    for case in CASES:
        payload = {"query": case["query"], "top_k": case["top_k"]}
        if case.get("category"):
            payload["category"] = case["category"]
        if case.get("content_type"):
            payload["content_type"] = case["content_type"]
        try:
            resp = httpx.post(BASE + "/search", json=payload, timeout=30)
            data = resp.json()
        except Exception as e:
            print("[ERROR] %s: 服务不可达 %s" % (case["name"], e))
            fails += 1
            continue

        ok = case["check"](data)
        fails += 0 if ok else 1
        print("\n=== %s === %s" % (case["name"], "PASS" if ok else "FAIL"))
        print("    期望: %s" % case["expect"])
        for h in data["results"]:
            preview = h["content"][:60].replace("\n", " ")
            print("    [%.4f|%s|%s] %s | %s" % (
                h["score"], h["category"], h["content_type"],
                h["source"], preview))
    print("\n==== 总结: %d/%d 通过 ====" % (len(CASES) - fails, len(CASES)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
