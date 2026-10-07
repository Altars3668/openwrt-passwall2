#!/usr/bin/env python3
"""从指定基线导出核心补丁，不修改源码仓库的 index 或提交历史。"""

from pathlib import Path
import subprocess
import sys


REPO = Path(__file__).resolve().parents[1]
CORES = (
    ("sing-box", "v1.14.2", "af6e64c3b69e6132ebaee0e1a3d24e93903f6709"),
    ("Xray-core", "v26.9.30", "b26a91de4f3294e26a0ad0a970b81a386a41f789"),
)


def export(source_root):
    destination = REPO / "patches/cores"
    destination.mkdir(parents=True, exist_ok=True)
    for name, version, revision in CORES:
        source = source_root / name
        head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if head != revision:
            raise SystemExit(f"{name} 基线不符：{head}")
        result = subprocess.check_output(["git", "-C", str(source), "diff", "--binary", "--no-ext-diff", "HEAD"])
        untracked = subprocess.check_output(["git", "-C", str(source), "ls-files", "--others", "--exclude-standard", "-z"]).split(b"\0")
        for path in sorted(p for p in untracked if p):
            filename = path.decode()
            if not filename.endswith(".go"):
                raise SystemExit(f"拒绝导出未知未跟踪文件：{name}/{filename}")
            diff = subprocess.run(["git", "diff", "--binary", "--no-index", "--no-ext-diff", "/dev/null", filename], cwd=source, capture_output=True)
            if diff.returncode != 1:
                raise SystemExit(f"新增文件导出失败：{name}/{filename}")
            result += diff.stdout
        target = destination / f"{name.lower()}-{version}-hot-reload.patch"
        target.write_bytes(result)
        print(target.relative_to(REPO), len(result), "bytes")


if __name__ == "__main__":
    export(Path(sys.argv[1]) if len(sys.argv) > 1 else REPO.parent)
