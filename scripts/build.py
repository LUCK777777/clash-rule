#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, re, sys, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    (ROOT / "templates" / "custom.ini", ROOT / "dist" / "custom.ini"),
    (ROOT / "templates" / "egern.yaml", ROOT / "dist" / "egern.yaml"),
]
SRC_FILE = ROOT / "sources.txt"
DEFAULT_REPO = "LUCK777777/clash-rule"


def repo_slug() -> str:
    """Resolve the <owner>/<repo> slug for raw.githubusercontent.com."""
    env = os.environ.get("GITHUB_REPOSITORY")
    if env:
        return env
    try:
        url = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"], text=True
        ).strip()
    except Exception:
        return DEFAULT_REPO

    if url.endswith(".git"):
        url = url[:-4]
    if url.startswith("git@"):
        # git@github.com:owner/repo
        slug = url.split(":", 1)[-1]
    elif url.startswith("http://") or url.startswith("https://"):
        slug = url.split("//", 1)[-1]
        slug = slug.split("/", 1)[-1]
    else:
        slug = url

    parts = slug.split("/")
    return "/".join(parts[-2:]) if len(parts) >= 2 else DEFAULT_REPO


MIRROR_PREFIX = os.environ.get("MIRROR_PREFIX") or f"https://raw.githubusercontent.com/{repo_slug()}/main/mirror/"

def url_map():
    """
    生成 {上游URL: 镜像URL} 映射（mirror/ 路径与 fetch.py 同步的目录保持一致）。
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
    mapping = url_map()
    for template, dist in TARGETS:
        dist.parent.mkdir(parents=True, exist_ok=True)
        text = template.read_text(encoding="utf-8")
        replaced = 0
        for src, tgt in mapping.items():
            if src in text:
                text = text.replace(src, tgt)
                replaced += 1
        dist.write_text(text, encoding="utf-8")
        print(f"Build done. Replaced {replaced} occurrences. Output: {dist}")

if __name__ == "__main__":
    main()
