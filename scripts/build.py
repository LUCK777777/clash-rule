#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "custom.ini"
DIST = ROOT / "dist" / "custom.ini"
SRC_FILE = ROOT / "sources.txt"
MIRROR_PREFIX = "https://raw.githubusercontent.com/{owner}/{repo}/gh-pages/".format(
    owner=ROOT.parts[-2] if len(ROOT.parts)>=2 else "owner",
    repo=ROOT.name
)

# 如果你不打算用 Pages，也可以把 MIRROR_PREFIX 改成：
# MIRROR_PREFIX = f"https://raw.githubusercontent.com/{GITHUB_REPOSITORY}/main/mirror/"

def url_map():
    """
    生成 {上游URL: 镜像URL} 映射（基于你后续工作流把 mirror/ 同步到 gh-pages 根目录）
    """
    m = {}
    for line in SRC_FILE.read_text(encoding="utf-8").splitlines():
        u = line.strip()
        if not u or u.startswith("#"): continue
        # mirror 的路径组织规则与 fetch.py 一致：netloc + path
        from urllib.parse import urlparse
        p = urlparse(u)
        rel = (p.netloc + p.path).lstrip("/")
        m[u] = MIRROR_PREFIX + rel
    return m

def main():
    DIST.parent.mkdir(parents=True, exist_ok=True)
    text = TEMPLATE.read_text(encoding="utf-8")
    mapping = url_map()
    replaced = 0
    for src, tgt in mapping.items():
        if src in text:
            text = text.replace(src, tgt)
            replaced += 1
    DIST.write_text(text, encoding="utf-8")
    print(f"Build done. Replaced {replaced} occurrences. Output: {DIST}")

if __name__ == "__main__":
    main()
