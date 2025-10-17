#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, re, hashlib, time
from pathlib import Path
from urllib.parse import urlparse
import requests

ROOT = Path(__file__).resolve().parents[1]
SRC_FILE = ROOT / "sources.txt"
MIRROR_DIR = ROOT / "mirror"

def path_for(url: str) -> Path:
    """
    将上游 URL 映射到 mirror/ 下的层级路径，保留末级文件名，目录用域名+路径组织。
    """
    u = urlparse(url)
    # e.g. raw.githubusercontent.com/owner/repo/...
    safe_path = (u.netloc + u.path).lstrip("/").replace("..","")
    return MIRROR_DIR / safe_path

def fetch(url: str, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    headers = {"User-Agent": "clash-rule-fetcher"}
    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        print(f"[WARN] {url} -> HTTP {r.status_code}")
        return False
    content = r.content
    # 如果已有且一致则不写
    if dest.exists() and dest.read_bytes() == content:
        return False
    dest.write_bytes(content)
    print(f"[OK] saved {url} -> {dest}")
    return True

def main():
    changed = False
    if not SRC_FILE.exists():
        print("sources.txt not found.")
        sys.exit(1)
    for line in SRC_FILE.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        dest = path_for(url)
        if fetch(url, dest):
            changed = True
    if changed:
        (ROOT / "MIRROR_UPDATED").write_text(time.strftime("%Y-%m-%d %H:%M:%S"), encoding="utf-8")
    print("Done.")

if __name__ == "__main__":
    main()
