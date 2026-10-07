#!/usr/bin/env python3
"""生成路由器完整应用覆盖包；不包含任何现有用户配置。

PW2_OVERLAY_NAME 选择目标（默认 home，产物为 home-overlay*）；PW2_SINGBOX / PW2_XRAY 指定该目标架构的核心
（默认 WORK 下的 sing-box-<目标>、xray-<目标>）；PW2_LMO 指向 po2lmo 编译的中文翻译（可选）。
"""

from pathlib import Path
import os
import shutil
import tarfile

REPO = Path(__file__).resolve().parents[1]
WORK = Path("/tmp/passwall2-hot-reload")
NAME = os.environ.get("PW2_OVERLAY_NAME", "home")
if not NAME.isalnum():
    raise SystemExit("invalid overlay name")
DEST = WORK / f"{NAME}-overlay"
APP = REPO / "luci-app-passwall2"
# 每次从空目录生成，避免上一次的残留文件混入。
shutil.rmtree(DEST, ignore_errors=True)
DEST.mkdir(parents=True, exist_ok=True)
files = []
for source in sorted((APP / "root").rglob("*")):
    if not source.is_file():
        continue
    relative = source.relative_to(APP / "root")
    if relative.parts[:2] == ("etc", "config") or relative.parts[:2] == ("etc", "uci-defaults"):
        continue
    target = DEST / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    files.append(str(relative))
for source in sorted((APP / "luasrc").rglob("*")):
    if source.is_file():
        relative = Path("usr/lib/lua/luci") / source.relative_to(APP / "luasrc")
        target = DEST / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        files.append(str(relative))
for source in sorted((APP / "htdocs").rglob("*")):
    if source.is_file():
        relative = Path("www") / source.relative_to(APP / "htdocs")
        target = DEST / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        files.append(str(relative))
# 可选：用 po2lmo 编译好的中文翻译（设置 PW2_LMO 指向 passwall2.zh-cn.lmo）。
lmo = os.environ.get("PW2_LMO")
if lmo:
    target = DEST / "usr/lib/lua/luci/i18n/passwall2.zh-cn.lmo"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(lmo, target)
    files.append("usr/lib/lua/luci/i18n/passwall2.zh-cn.lmo")
for name, env in (("sing-box", "PW2_SINGBOX"), ("xray", "PW2_XRAY")):
    source = Path(os.environ.get(env, WORK / f"{name}-{NAME}"))
    target = DEST / "usr/bin" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(0o755)
    files.append(f"usr/bin/{name}")
for name in files:
    if any(character in name for character in "\r\n\t ") or name.startswith("/") or ".." in Path(name).parts:
        raise SystemExit("unsafe payload path")
manifest = "\n".join(files) + "\n"
(WORK / f"{NAME}-overlay.manifest").write_text(manifest)
with tarfile.open(WORK / f"{NAME}-overlay.tar.gz", "w:gz") as archive:
    for name in files:
        archive.add(DEST / name, arcname=name, recursive=False)
print(f"完整覆盖包：{len(files)} 个应用文件和核心；主动排除 /etc/config 与首次安装脚本。")
