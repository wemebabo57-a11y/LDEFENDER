"""
量盾安全 - 专业病毒防护软件
基于 ClamAV 引擎，自动配置、自动检测、自动更新病毒库

v5.5.0 修改清单：
  UI-1  : 进度条 start_pulse / stop_pulse 脉冲动画
  UI-2  : 扫描/更新启动自动脉冲，收到实际进度值自动切换 determinate
  UI-3  : 扫描完成/停止/出错自动停止脉冲
  UI-4  : 配色 accent #3b82f6, bg #0f172a, 整体降饱和度
  UI-5  : 进度条 thickness 6 → 12
  UI-6  : 全局字号 +1
  UI-7  : 全局 padding +50%
  UI-8  : 移除 emoji/几何符号图标前缀，只保留文字
  UI-9  : 标题栏按钮统一 Unicode 字符
  UI-10 : 卡片间距 12 → 20
  保留 v5.4.0 全部修复（FIX-1 ~ FIX-12）及 v5.3.0 / v5.2.5 修复

合规与功能增补 (2026-05):
  LEGAL-1: 首次启动强制 EULA 模态确认，同意/拒绝均审计留痕
  LEGAL-2: 关于页面增加数据透明声明与 GPL v2 开源许可证声明
  LEGAL-3: 全局年份更新至 2026
  FIX-AUTOSTART-1: 开机自启调用系统 API（注册表/LaunchAgent/DesktopEntry）
  FIX-AUTOSTART-2: 启动时同步外部自启状态，解决状态不一致
  AUDIT-1: 设置变更（处理方式、自启开关）写入审计日志
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import subprocess
import os
import sys
import time
import math
import json
import shutil
import platform
import re
import stat
import logging
from pathlib import Path
from datetime import datetime

if platform.system() == "Windows":
    import msvcrt
else:
    import fcntl

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  路径配置
# ─────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
CLAMAV_DIR = BASE_DIR / "clamav"
DB_DIR     = CLAMAV_DIR / "db"
LOG_DIR    = BASE_DIR / "logs"
CONF_DIR   = BASE_DIR / "conf"

IS_WIN = platform.system() == "Windows"
CLAMSCAN    = CLAMAV_DIR / ("clamscan.exe"   if IS_WIN else "clamscan")
FRESHCLAM   = CLAMAV_DIR / ("freshclam.exe"  if IS_WIN else "freshclam")
CLAMD       = CLAMAV_DIR / ("clamd.exe"      if IS_WIN else "clamd")
CLAMD_CONF  = CONF_DIR   / "clamd.conf"
FRESH_CONF  = CONF_DIR   / "freshclam.conf"

CVD_FILES   = ["main.cvd", "daily.cvd", "bytecode.cvd",
               "main.cld", "daily.cld", "bytecode.cld"]

QUARANTINE_DIR  = BASE_DIR / "quarantine"
QUARANTINE_META = QUARANTINE_DIR / ".meta.json"
QUAR_SUFFIX     = ".ld_quarantined"

AUDIT_LOG = LOG_DIR / "audit.jsonl"
AUDIT_LOG_MAX_SIZE = 10 * 1024 * 1024

# ── UI #12: 跨平台字体常量 ──
_PF = platform.system()
FONT_FAMILY      = "Microsoft YaHei UI" if _PF == "Windows" else (
                    "PingFang SC" if _PF == "Darwin" else "Noto Sans CJK SC")
FONT_FAMILY_BOLD = "Microsoft YaHei" if _PF == "Windows" else FONT_FAMILY
FONT_MONO        = "Consolas"

# ── UI #9: 日志最大行数 ──
MAX_LOG_LINES = 5000


# ─────────────────────────────────────────────
#  颜色主题  (UI-4: accent #3b82f6, bg #0f172a, 降饱和度)
# ─────────────────────────────────────────────
C = {
    "bg":        "#0f172a",
    "panel":     "#1e293b",
    "card":      "#273548",
    "border":    "#334155",
    "accent":    "#3b82f6",
    "accent2":   "#2563eb",
    "green":     "#22c55e",
    "warn":      "#f59e0b",
    "danger":    "#ef4444",
    "text":      "#cbd5e1",
    "dim":       "#64748b",
    "white":     "#ffffff",
    "glow":      "#3b82f633",
}


def _lighten(hex_color, factor=0.18):
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r = min(255, int(r + (255 - r) * factor))
    g = min(255, int(g + (255 - g) * factor))
    b = min(255, int(b + (255 - b) * factor))
    return f"#{r:02x}{g:02x}{b:02x}"

def _darken(hex_color, factor=0.18):
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r = max(0, int(r * (1 - factor)))
    g = max(0, int(g * (1 - factor)))
    b = max(0, int(b * (1 - factor)))
    return f"#{r:02x}{g:02x}{b:02x}"


def _truncate_path(path_str, max_len=60):
    if len(path_str) <= max_len:
        return path_str
    p = Path(path_str)
    name = p.name
    parent = str(p.parent)
    if len(name) >= max_len - 5:
        return "…" + name[:max_len - 5]
    remaining = max_len - len(name) - 4
    if remaining > 3:
        return "…" + parent[-remaining:] + os.sep + name
    return "…" + name[:max_len - 3]


# ══════════════════════════════════════════════
#  EULA 协议文本
# ══════════════════════════════════════════════
EULA_TEXT = """量盾安全软件 最终用户许可协议 (EULA)

重要提示：在使用本软件之前，请仔细阅读以下条款。点击“同意”即表示您接受本协议全部条款；如不同意，请立即退出本软件。

1. 许可授予
量盾安全团队（“开发者”）授予您（“用户”）一项有限的、非独占的、不可转让的许可，允许您在一台计算机上安装和使用本软件副本，用于个人或企业内部病毒防护目的。

2. 数据隐私与透明声明
• 本地扫描：所有文件扫描均在本地设备完成，不会上传任何用户文件、文档内容或文件元数据至远程服务器。
• 网络连接：软件仅连接 ClamAV 官方病毒库服务器（database.clamav.net 及 db.cn.clamav.net 等官方镜像）以下载病毒定义更新。
• 数据收集：本软件不收集用户个人身份信息、文件内容、扫描结果或系统使用习惯。审计日志仅保存在用户本地磁盘。
• 开源声明：本软件基于 ClamAV 引擎（GNU General Public License v2.0），病毒库遵循 ClamAV 官方分发条款。

3. 免责声明
本软件按“现状”提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性及非侵权的担保。开发者不对因使用或无法使用本软件导致的任何直接、间接、偶然、特殊或后果性损失承担责任。

4. 开源组件
本软件包含基于 GNU General Public License v2.0 授权的 ClamAV 引擎。ClamAV 相关源代码可从 https://www.clamav.net 官方渠道获取。用户有权根据 GPL v2 条款获取、修改和重新分发相应源代码。

5. 协议更新
开发者保留随时修订本协议的权利。继续使用本软件视为接受修订后的协议。如不同意修订条款，请立即停止使用并卸载本软件。

6. 终止
如用户违反本协议任何条款，本许可将自动终止。终止后，用户应立即销毁本软件的所有副本。

生效日期：2026年1月1日
版权所有 © 2026 量盾安全团队
"""


# ══════════════════════════════════════════════
#  审计日志
# ══════════════════════════════════════════════
def write_audit(entry: dict):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        if AUDIT_LOG.exists() and AUDIT_LOG.stat().st_size > AUDIT_LOG_MAX_SIZE:
            backup = AUDIT_LOG.with_suffix('.jsonl.1')
            try:
                if backup.exists():
                    backup.unlink()
                AUDIT_LOG.rename(backup)
            except Exception:
                pass
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception:
        pass


def strip_long_path_prefix(path_str: str) -> str:
    if not IS_WIN:
        return path_str
    if path_str.startswith('\\\\?\\UNC\\'):
        return '\\\\' + path_str[8:]
    if path_str.startswith('\\\\?\\'):
        return path_str[4:]
    return path_str


# ══════════════════════════════════════════════
#  隔离箱管理器
# ══════════════════════════════════════════════
class QuarantineManager:
    _meta_lock = threading.Lock()

    def __init__(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        self.log = lambda msg, tag="": None

    def _read_meta(self):
        try:
            if QUARANTINE_META.exists():
                text = QUARANTINE_META.read_text(encoding="utf-8")
                return json.loads(text)
        except json.JSONDecodeError as e:
            self.log(f"元数据 JSON 损坏: {e}", "danger")
            backup = QUARANTINE_META.with_suffix('.json.bak')
            if backup.exists():
                try:
                    text = backup.read_text(encoding="utf-8")
                    data = json.loads(text)
                    self.log("已从备份恢复元数据", "warn")
                    self._write_meta(data)
                    return data
                except Exception as e2:
                    self.log(f"备份元数据也损坏: {e2}", "danger")
            return {}
        except Exception as e:
            self.log(f"读取元数据异常: {type(e).__name__}: {e}", "danger")
            return {}
        return {}

    def _write_meta(self, data):
        with self._meta_lock:
            QUARANTINE_META.parent.mkdir(parents=True, exist_ok=True)
            tmp = QUARANTINE_META.with_suffix('.tmp')
            content = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            try:
                tmp.write_bytes(content)
                if QUARANTINE_META.exists():
                    backup = QUARANTINE_META.with_suffix('.json.bak')
                    try:
                        shutil.copy2(str(QUARANTINE_META), str(backup))
                    except Exception as e:
                        self.log(f"元数据备份失败（非致命）: {e}", "warn")
                replaced = False
                for attempt in range(5):
                    try:
                        tmp.replace(QUARANTINE_META)
                        replaced = True
                        break
                    except PermissionError:
                        if attempt < 4:
                            time.sleep(0.1 * (attempt + 1))
                        else:
                            raise
                if replaced:
                    self.log("元数据已原子更新", "dim")
            except Exception as e:
                self.log(f"元数据写入失败: {e}", "danger")
                try:
                    if tmp.exists():
                        tmp.unlink()
                except Exception:
                    pass
                raise

    def _secure_delete(self, path: Path) -> bool:
        try:
            if path.is_file():
                path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IWGRP)
                path.unlink()
                self.log(f"文件已删除: {path}", "info")
                return True
        except PermissionError as e:
            self.log(f"删除权限错误: {e}", "warn")
        except Exception as e:
            self.log(f"删除异常: {type(e).__name__}: {e}", "danger")
        return False

    def quarantine_file(self, src_path: str, threat_name: str = "Unknown") -> tuple:
        src = Path(src_path).resolve()
        if not src.exists():
            return False, f"源文件不存在：{src}"
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        qid   = src.name + f".{ts}" + QUAR_SUFFIX
        qfile = QUARANTINE_DIR / qid
        entry = {
            "qfile":  str(qfile),
            "orig":   str(src),
            "threat": threat_name,
            "time":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        tmp_file = qfile.with_suffix('.tmp')
        try:
            shutil.copy2(src, tmp_file)
            self.log(f"源文件已复制到临时位置: {tmp_file}", "info")
        except Exception as e:
            self.log(f"复制到隔离箱失败: {e}", "danger")
            return False, f"复制到隔离箱失败：{e}"
        deleted = self._secure_delete(src)
        if not deleted:
            try:
                tmp_file.unlink()
                self.log(f"回滚临时文件: {tmp_file}", "warn")
            except Exception:
                pass
            return False, f"无法删除源文件（可能被占用）：{src}"
        try:
            tmp_file.rename(qfile)
            self.log(f"隔离文件重命名成功: {qfile}", "info")
        except Exception as e:
            self.log(f"重命名失败: {tmp_file} -> {qfile}, 异常: {e}", "danger")
            try:
                backup_path = src.with_name(src.name + ".ld_backup")
                tmp_file.rename(backup_path)
                self.log(f"临时文件已重命名为 {backup_path}", "warn")
                entry["note"] = f"重命名失败，文件已恢复到 {backup_path}"
            except Exception as rename_err:
                self.log(f"恢复到原始名失败: {rename_err}", "danger")
                try:
                    incomplete = tmp_file.with_suffix('.incomplete' + QUAR_SUFFIX)
                    tmp_file.rename(incomplete)
                    entry["note"] = f"重命名失败，文件已置为 .incomplete"
                except Exception as final_err:
                    self.log(f"无法处理临时文件，残留: {tmp_file}, 错误: {final_err}", "danger")
                    entry["note"] = f"严重错误：临时文件残留 {tmp_file}，请手动处理"
            meta = self._read_meta()
            meta[qid] = entry
            self._write_meta(meta)
            return False, f"隔离完成但重命名失败: {e}"
        meta = self._read_meta()
        meta[qid] = entry
        self._write_meta(meta)
        self.log(f"隔离成功: {qid}", "success")
        return True, qid

    def list_items(self) -> list:
        meta  = self._read_meta()
        items = []
        for qid, info in meta.items():
            qfile = Path(info.get("qfile", ""))
            exists = qfile.exists()
            size   = ""
            if exists:
                try:
                    sz = qfile.stat().st_size
                    size = f"{sz/1024:.1f} KB" if sz < 1024*1024 else f"{sz/1024/1024:.2f} MB"
                except Exception:
                    size = "—"
            items.append({
                "qid":    qid,
                "qfile":  str(qfile),
                "orig":   info.get("orig", "—"),
                "threat": info.get("threat", "Unknown"),
                "time":   info.get("time", "—"),
                "size":   size,
                "exists": exists,
            })
        items.sort(key=lambda x: x["time"], reverse=True)
        return items

    def count_items(self) -> int:
        try:
            if QUARANTINE_META.exists():
                text = QUARANTINE_META.read_text(encoding="utf-8")
                return len(json.loads(text))
        except Exception:
            pass
        return 0

    def get_item_info(self, qid: str) -> dict:
        meta = self._read_meta()
        if qid not in meta:
            return {}
        info = meta[qid]
        qfile = Path(info.get("qfile", ""))
        return {
            "qid":    qid,
            "qfile":  str(qfile),
            "orig":   info.get("orig", "—"),
            "threat": info.get("threat", "Unknown"),
            "time":   info.get("time", "—"),
            "exists": qfile.exists(),
            "note":   info.get("note", ""),
        }

    def restore_item(self, qid: str) -> tuple:
        meta = self._read_meta()
        if qid not in meta:
            return False, "隔离记录不存在"
        info  = meta[qid]
        qfile = Path(info["qfile"])
        orig  = Path(info["orig"])
        if not qfile.exists():
            del meta[qid]
            self._write_meta(meta)
            return False, "隔离文件已丢失，无法恢复"
        if orig.exists():
            return False, f"目标位置已存在同名文件：{orig}\n请手动处理后再恢复"
        try:
            try:
                orig.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                return False, f"无法创建目标目录 {orig.parent}：权限不足 ({e})"
            except Exception as e:
                return False, f"无法创建目标目录 {orig.parent}：{e}"
            cross_fs = False
            try:
                if os.stat(qfile).st_dev != os.stat(orig.parent).st_dev:
                    cross_fs = True
            except Exception:
                cross_fs = True
                self.log("无法检测文件系统，使用复制策略", "warn")
            if cross_fs:
                self.log(f"跨文件系统恢复: {qfile} -> {orig}", "info")
                shutil.copy2(qfile, orig)
                qfile.unlink()
            else:
                shutil.move(str(qfile), str(orig))
                self.log(f"同文件系统移动: {qfile} -> {orig}", "info")
            del meta[qid]
            self._write_meta(meta)
            return True, str(orig)
        except Exception as e:
            self.log(f"恢复失败: {e}", "danger")
            try:
                if orig.exists():
                    orig.unlink()
            except Exception:
                pass
            return False, f"恢复失败：{e}"

    def delete_item(self, qid: str) -> tuple:
        meta = self._read_meta()
        if qid not in meta:
            return False, "隔离记录不存在"
        info  = meta[qid]
        qfile = Path(info["qfile"])
        if qfile.exists():
            if not self._secure_delete(qfile):
                return False, "删除隔离文件失败"
        del meta[qid]
        self._write_meta(meta)
        return True, "已彻底删除"

    def delete_items(self, qids: list) -> tuple:
        meta = self._read_meta()
        ok_count = 0
        fail_list = []
        for qid in qids:
            if qid not in meta:
                fail_list.append(f"{qid}: 记录不存在")
                continue
            info = meta[qid]
            qfile = Path(info["qfile"])
            if qfile.exists():
                if not self._secure_delete(qfile):
                    fail_list.append(f"{qid}: 删除文件失败")
                    continue
            del meta[qid]
            ok_count += 1
        if ok_count > 0:
            self._write_meta(meta)
        return ok_count, len(qids) - ok_count, fail_list

    def secure_delete_with_retry(self, path: Path, max_retries: int = 3, retry_delay: float = 1.0) -> bool:
        for attempt in range(max_retries):
            if self._secure_delete(path):
                return True
            if attempt < max_retries - 1:
                self.log(f"删除重试 ({attempt+1}/{max_retries}): {path}", "warn")
                time.sleep(retry_delay)
        self.log(f"删除最终失败: {path}", "danger")
        return False


# ══════════════════════════════════════════════
#  开机自启动管理器 (跨平台)
# ══════════════════════════════════════════════
class AutostartManager:
    APP_NAME = "LiangDunSecurity"

    def __init__(self):
        self._pf = platform.system()

    def is_enabled(self) -> bool:
        """检测系统级自启是否实际注册"""
        try:
            if self._pf == "Windows":
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    winreg.QueryValueEx(key, self.APP_NAME)
                    return True
            elif self._pf == "Darwin":
                plist_path = Path.home() / "Library/LaunchAgents/com.liangdun.security.plist"
                return plist_path.exists()
            else:
                desktop_path = Path.home() / ".config/autostart/liangdun.desktop"
                return desktop_path.exists()
        except (FileNotFoundError, OSError, ImportError):
            return False
        return False

    def enable(self) -> tuple:
        """注册系统级开机自启"""
        try:
            if getattr(sys, 'frozen', False):
                exe_path = sys.executable
            else:
                exe_path = f'{sys.executable} "{Path(__file__).resolve()}"'

            if self._pf == "Windows":
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    winreg.SetValueEx(key, self.APP_NAME, 0, winreg.REG_SZ, exe_path)
                return True, "已注册到 Windows 启动项"

            elif self._pf == "Darwin":
                plist_path = Path.home() / "Library/LaunchAgents/com.liangdun.security.plist"
                plist_path.parent.mkdir(parents=True, exist_ok=True)
                plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<<plist version="1.0">
<<dict>
    <key>Label</key>
    <string>com.liangdun.security</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{Path(__file__).resolve()}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>'''
                plist_path.write_text(plist_content, encoding="utf-8")
                os.system(f"launchctl load '{plist_path}' 2>/dev/null")
                return True, "已注册 macOS LaunchAgent"

            else:
                desktop_path = Path.home() / ".config/autostart/liangdun.desktop"
                desktop_path.parent.mkdir(parents=True, exist_ok=True)
                desktop_content = f"""[Desktop Entry]
Type=Application
Name=量盾安全
Exec={exe_path}
Icon=security-high
Comment=专业病毒防护软件
Categories=System;Security;
X-GNOME-Autostart-enabled=true
StartupNotify=false"""
                desktop_path.write_text(desktop_content, encoding="utf-8")
                desktop_path.chmod(0o755)
                return True, "已创建 Linux 桌面启动项"

        except Exception as e:
            return False, str(e)

    def disable(self) -> tuple:
        """注销系统级开机自启"""
        try:
            if self._pf == "Windows":
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, self.APP_NAME)
                return True, "已移除 Windows 启动项"

            elif self._pf == "Darwin":
                plist_path = Path.home() / "Library/LaunchAgents/com.liangdun.security.plist"
                if plist_path.exists():
                    os.system(f"launchctl unload '{plist_path}' 2>/dev/null")
                    plist_path.unlink()
                return True, "已移除 macOS LaunchAgent"

            else:
                desktop_path = Path.home() / ".config/autostart/liangdun.desktop"
                if desktop_path.exists():
                    desktop_path.unlink()
                return True, "已移除 Linux 桌面启动项"

        except Exception as e:
            return False, str(e)


# ══════════════════════════════════════════════
#  ClamAV 后端
# ══════════════════════════════════════════════
class ClamAVBackend:
    def __init__(self, log_cb):
        self.log = log_cb
        self._scan_proc   = None
        self._update_proc = None
        self._scan_cancel = threading.Event()

    def check_engine(self):
        if not CLAMAV_DIR.exists():
            return False, f"未找到 clamav 目录：{CLAMAV_DIR}"
        if not CLAMSCAN.exists():
            return False, f"未找到 clamscan：{CLAMSCAN}"
        if not FRESHCLAM.exists():
            return False, f"未找到 freshclam：{FRESHCLAM}"
        return True, "ClamAV 引擎就绪"

    def generate_configs(self):
        CONF_DIR.mkdir(parents=True, exist_ok=True)
        DB_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        # LEGAL-3: 配置文件注释年份更新为 2026
        clamd_content = f"""\
# 量盾安全 v5.5.0 (c) 2026 - clamd 自动生成配置
LogFile {LOG_DIR / 'clamd.log'}
LogTime yes
LogVerbose no
PidFile {LOG_DIR / 'clamd.pid'}
DatabaseDirectory {DB_DIR}
{"TCPSocket 3310" if IS_WIN else f"LocalSocket {LOG_DIR / 'clamd.sock'}"}
MaxConnectionQueueLength 30
MaxThreads 12
ReadTimeout 300
MaxFiles 10000
MaxFileSize 100M
MaxScanSize 400M
MaxRecursion 17
MaxDirectoryRecursion 15
FollowDirectorySymlinks yes
FollowFileSymlinks yes
DetectPUA yes
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanMail yes
ScanHTML yes
ScanArchive yes
"""
        CLAMD_CONF.write_text(clamd_content, encoding="utf-8")
        fresh_content = f"""\
# 量盾安全 v5.5.0 (c) 2026 - freshclam 自动生成配置
UpdateLogFile {LOG_DIR / 'freshclam.log'}
LogVerbose no
LogSyslog no
LogTime yes
DatabaseDirectory {DB_DIR}
DatabaseMirror database.clamav.net
DatabaseMirror db.cn.clamav.net
MaxAttempts 5
ScriptedUpdates yes
CompressLocalDatabase no
Checks 24
ConnectTimeout 30
ReceiveTimeout 60
"""
        FRESH_CONF.write_text(fresh_content, encoding="utf-8")
        self.log("配置文件已生成", "success")

    def check_database(self):
        if not DB_DIR.exists():
            return False
        for f in CVD_FILES:
            if (DB_DIR / f).exists():
                return True
        return False

    def get_db_info(self):
        info = []
        for f in CVD_FILES:
            p = DB_DIR / f
            if p.exists():
                size = p.stat().st_size / (1024 * 1024)
                mtime = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                info.append({"name": f, "size": f"{size:.1f} MB", "date": mtime, "ok": True})
        if not info:
            for name in ["main.cvd", "daily.cvd", "bytecode.cvd"]:
                info.append({"name": name, "size": "—", "date": "未安装", "ok": False})
        return info

    def update_database(self, progress_cb, done_cb):
        def run():
            self.log("开始更新病毒库...", "info")
            progress_cb(5)
            if not FRESH_CONF.exists():
                self.generate_configs()
            progress_cb(15)
            try:
                env = os.environ.copy()
                cmd = [str(FRESHCLAM), f"--config-file={FRESH_CONF}",
                       f"--datadir={DB_DIR}", "--stdout"]
                self._update_proc = proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, env=env,
                    creationflags=subprocess.CREATE_NO_WINDOW if IS_WIN else 0
                )
                pct = 20
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        self.log(f"  {line}", "dim")
                        if "%" in line:
                            m = re.search(r'(\d+)%', line)
                            if m:
                                pct = 20 + int(m.group(1)) * 0.75
                        progress_cb(min(int(pct), 95))
                try:
                    proc.wait(timeout=300)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=10)
                    self.log("更新进程超时，已终止", "warn")
                if proc.returncode == 0 or self.check_database():
                    progress_cb(100)
                    self.log("病毒库更新完成", "success")
                    done_cb(True, "病毒库更新成功")
                else:
                    self.log("更新过程中遇到问题", "warn")
                    done_cb(False, f"更新失败 (代码 {proc.returncode})")
            except FileNotFoundError:
                self.log("freshclam 未找到，请确认 clamav 目录", "danger")
                done_cb(False, "freshclam 未找到")
            except Exception as e:
                self.log(f"更新错误: {e}", "danger")
                done_cb(False, str(e))
            finally:
                self._update_proc = None
        threading.Thread(target=run, daemon=True).start()

    def cancel_scan(self):
        self._scan_cancel.set()
        if self._scan_proc and self._scan_proc.poll() is None:
            try:
                self._scan_proc.terminate()
            except Exception:
                pass

    @staticmethod
    def _decode_clamav_line(raw: bytes) -> str:
        raw = raw.replace(b'\x07', b'')
        if IS_WIN:
            candidates = ["utf-8", "mbcs", "cp936", "gbk", "latin-1"]
        else:
            candidates = ["utf-8", "latin-1"]
        for enc in candidates:
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("latin-1", errors="replace")

    @staticmethod
    def _normalize_and_verify_path(raw_path: str) -> tuple:
        if not raw_path or not raw_path.strip():
            return raw_path, False
        p_str = raw_path.strip()
        if IS_WIN:
            p_str = re.sub(r'^/+([A-Za-z]:)', r'\1', p_str)
            p_str = p_str.replace('/', '\\')
        try:
            p = Path(p_str).resolve()
        except Exception:
            return p_str, False
        if IS_WIN:
            abs_str = str(p)
            UNC_PREFIX  = '\\\\?\\'
            UNC_NETWORK = '\\\\?\\UNC\\'
            if not abs_str.startswith(UNC_PREFIX):
                if abs_str.startswith('\\\\'):
                    abs_str = UNC_NETWORK + abs_str[2:]
                else:
                    abs_str = UNC_PREFIX + abs_str
            exists = os.path.exists(abs_str)
            if exists:
                return abs_str, True
            exists = p.exists()
            return str(p), exists
        else:
            exists = p.exists()
            return str(p), exists

    # ── FIX-2: 重写扫描核心逻辑 ──────────────────────────────
    def scan(self, target, progress_cb, result_cb, log_file_cb=None):
        def run():
            if not self.check_database():
                result_cb(None, "病毒库未安装，请先更新病毒库")
                return

            try:
                resolved_target = str(Path(target).resolve())
                if not Path(resolved_target).exists():
                    result_cb(None, f"扫描目标不存在：{target}")
                    return
            except Exception as e:
                result_cb(None, f"扫描目标路径无效：{e}")
                return

            self.log(f"开始扫描：{resolved_target}", "info")
            self._scan_cancel.clear()
            # 删除入口 progress_cb(0)

            # ── 启动文件总数预计数线程（阶段2用）──
            self._total_estimate = None
            self._total_ready = threading.Event()

            def _count_files():
                count = 0
                try:
                    p = Path(resolved_target)
                    if p.is_file():
                        count = 1
                    else:
                        for root, dirs, files in os.walk(resolved_target):
                            if self._scan_cancel.is_set():
                                return
                            count += len(files)
                except Exception:
                    pass
                if count <= 0:
                    count = 1
                self._total_estimate = count
                self._total_ready.set()

            threading.Thread(target=_count_files, daemon=True).start()

            try:
                cmd = [
                    str(CLAMSCAN), "-r", "--verbose",
                    f"--database={DB_DIR}", "--stdout", resolved_target
                ]
                if log_file_cb:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    lf = LOG_DIR / f"scan_{ts}.log"
                    cmd += [f"--log={lf}"]
                    log_file_cb(str(lf))

                self._scan_proc = proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=False,
                    creationflags=subprocess.CREATE_NO_WINDOW if IS_WIN else 0
                )

                results = {"infected": [], "scanned": 0, "errors": 0}
                incremental_scanned = 0

                for raw_line in proc.stdout:
                    if self._scan_cancel.is_set():
                        proc.terminate()
                        self.log("扫描已取消", "warn")
                        return

                    line = self._decode_clamav_line(raw_line).rstrip()
                    if not line:
                        continue

                    self.log(f"  {line}", "dim")

                    if line.startswith("Scanning "):
                        incremental_scanned += 1
                        current_file = line[len("Scanning "):].strip()
                        truncated = _truncate_path(strip_long_path_prefix(current_file))

                        # 计算真实进度百分比（阶段2：5→90%）
                        if self._total_estimate is not None and self._total_estimate > 0:
                            pct = 5 + int((incremental_scanned / self._total_estimate) * 85)
                            pct = min(pct, 90)
                        else:
                            pct = -1  # 尚无真实 total，UI 启用伪进度

                        progress_cb(pct, truncated, incremental_scanned, self._total_estimate)

                    if "FOUND" in line:
                        clean = line.strip()
                        if clean.endswith(" FOUND"):
                            core = clean[:-6].strip()
                            if ': ' in core:
                                sep = core.rfind(': ')
                                raw_fpath = core[:sep].strip()
                                vname     = core[sep+2:].strip()
                            else:
                                raw_fpath = clean
                                vname     = "Unknown"
                            fpath, path_ok = self._normalize_and_verify_path(raw_fpath)
                            if not path_ok:
                                self.log(f"路径解析失败（已跳过隔离）: {raw_fpath!r}", "warn")
                                results["errors"] += 1
                            else:
                                display_path = strip_long_path_prefix(fpath)
                                results["infected"].append({
                                    "path": fpath, "display_path": display_path, "virus": vname
                                })
                                self.log(f"发现威胁: {display_path}  [{vname}]", "danger")

                    elif "ERROR" in line.upper():
                        results["errors"] += 1

                    if "Scanned files:" in line:
                        m = re.search(r'Scanned files:\s*(\d+)', line)
                        if m:
                            results["scanned"] = int(m.group(1))

                # 阶段3开始：stdout 读取完毕，进入 proc.wait()
                if results["scanned"] == 0 and incremental_scanned > 0:
                    results["scanned"] = incremental_scanned

                # 通知 UI 进入收尾阶段 90%
                progress_cb(90, None, results["scanned"], self._total_estimate)

                try:
                    proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    self.log("扫描进程超时，已终止", "warn")

                if self._scan_cancel.is_set():
                    return

                # 阶段3中间点 95%
                progress_cb(95, None, results["scanned"], self._total_estimate)

                result_cb(results, None)
                total_infected = len(results["infected"])
                self.log(
                    f"扫描完成 | 已扫描: {results['scanned']} | "
                    f"威胁: {total_infected} | 错误: {results['errors']}",
                    "success" if total_infected == 0 else "danger"
                )
            except FileNotFoundError:
                result_cb(None, "clamscan 未找到")
            except Exception as e:
                if not self._scan_cancel.is_set():
                    result_cb(None, str(e))
            finally:
                self._scan_proc = None

        threading.Thread(target=run, daemon=True).start()


# ══════════════════════════════════════════════
#  主界面
# ══════════════════════════════════════════════
class LiangDunApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("量盾安全")
        self.geometry("1080x720")
        self.minsize(900, 620)
        self.configure(bg=C["bg"])
        self.resizable(True, True)

        # === 自定义标题栏：去掉原生标题栏 ===
        self.overrideredirect(True)

        # 窗口控制状态
        self._drag_x = 0
        self._drag_y = 0
        self._is_maximized = False
        self._normal_geometry = None

        self._scan_target     = tk.StringVar(value="")
        self._status_text     = tk.StringVar(value="正在初始化…")
        self._scan_log_path   = None
        self._scanning        = False
        self._updating        = False
        self._scan_results    = None
        self._current_scan_file = tk.StringVar(value="等待扫描…")

        # UI-1: 脉冲状态标记（保留字段，但扫描进度已改为三阶段平滑）
        self._scan_pulsing    = False
        self._update_pulsing  = False

        self._settings_file   = BASE_DIR / "settings.json"
        self._virus_action    = tk.StringVar(value="quarantine")
        self._autostart       = tk.BooleanVar(value=False)

        # FIX-AUTOSTART: 初始化自启动管理器（必须在 _load_settings 之前）
        self._autostart_mgr = AutostartManager()

        # 加载设置（内部会同步真实自启状态）
        self._load_settings()

        self.backend    = ClamAVBackend(self._log)
        self.quar_mgr   = QuarantineManager()
        self.quar_mgr.log = self._log

        self._quar_selected = set()
        self._quar_search_timer = None
        self._anim_active = True
        self._pulse_timer = None
        self._quar_busy = False

        # UI #18: 隔离箱列表缓存
        self._quar_cached_items = None
        self._quar_cache_dirty = True

        # ── 三阶段进度条定时器 ──
        self._smooth_timer = None
        self._pseudo_timer = None
        self._scan_has_real_total = False
        self._pseudo_start_time = 0

        self._configure_styles()

        # UI #17: 窗口关闭确认
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Map>", self._on_map)

        self._build_ui()

        # LEGAL-1: EULA 强制确认（必须在 UI 构建完成后调用）
        self._check_eula()

        self.after(300, self._init_check)

        # UI #16: 键盘快捷键
        self.bind("<Control-s>", lambda e: self._start_scan())
        self.bind("<Control-q>", lambda e: self._on_close())
        self.bind("<Escape>",    lambda e: self._stop_scan() if self._scanning else None)

    # ── UI #10: 只配置一次 style ──
    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("default")
        # UI-5: thickness 6 → 12
        style.configure("ld.Horizontal.TProgressbar",
                        troughcolor=C["border"],
                        background=C["accent"],
                        thickness=12)
        style.configure("ld_up.Horizontal.TProgressbar",
                        troughcolor=C["border"],
                        background=C["accent2"],
                        thickness=12)

    # ══════════════════════════════════════════
    #  UI-1: 进度条脉冲动画
    # ══════════════════════════════════════════
    def start_pulse(self, pb):
        """启动 indeterminate 脉冲动画"""
        try:
            if pb.winfo_exists():
                pb.stop()
                pb.configure(mode="indeterminate")
                pb.start(30)
        except Exception:
            pass

    def stop_pulse(self, pb, value=0):
        """停止脉冲动画，切回 determinate 模式"""
        try:
            if pb.winfo_exists():
                pb.stop()
                pb.configure(mode="determinate")
                pb['value'] = value
        except Exception:
            pass

    # ── UI #17: 窗口关闭确认 ──
    def _on_close(self):
        if self._scanning:
            if not messagebox.askyesno("确认退出",
                    "正在扫描中，退出将中断扫描。\n确定要退出吗？"):
                return
            self.backend.cancel_scan()
        if self._updating:
            if not messagebox.askyesno("确认退出",
                    "正在更新病毒库，退出将中断更新。\n确定要退出吗？"):
                return
        self._anim_active = False
        self.destroy()

    # ── FIX-9: 设置持久化 ──────────────────────────────────
    def _load_settings(self):
        default = {
            "virus_action": "quarantine",
            "autostart": False,
            "eula_accepted": False,
            "eula_accepted_at": None,
        }
        try:
            if self._settings_file.exists():
                loaded = json.loads(self._settings_file.read_text(encoding="utf-8"))
                self._settings_data = {**default, **loaded}
            else:
                self._settings_data = dict(default)
        except Exception:
            self._settings_data = dict(default)

        # FIX-AUTOSTART-2: 同步外部自启状态（如用户在任务管理器手动关闭）
        real_autostart = self._autostart_mgr.is_enabled()
        if self._settings_data.get("autostart", False) != real_autostart:
            self._settings_data["autostart"] = real_autostart
            try:
                self._settings_file.write_text(
                    json.dumps(self._settings_data, ensure_ascii=False, indent=2),
                    encoding="utf-8")
            except Exception:
                pass

        self._virus_action.set(self._settings_data.get("virus_action", "quarantine"))
        self._autostart.set(self._settings_data.get("autostart", False))

    def _save_settings(self):
        try:
            new_data = {
                "virus_action": self._virus_action.get(),
                "autostart": self._autostart.get(),
                "eula_accepted": self._settings_data.get("eula_accepted", False),
                "eula_accepted_at": self._settings_data.get("eula_accepted_at", None),
            }
            self._settings_file.write_text(
                json.dumps(new_data, ensure_ascii=False, indent=2), encoding="utf-8")
            self._settings_data = new_data
        except Exception:
            pass

    # ══════════════════════════════════════════
    #  EULA 强制确认与留痕
    # ══════════════════════════════════════════
    def _check_eula(self):
        if self._settings_data.get("eula_accepted", False):
            return
        self._show_eula()

    def _show_eula(self):
        eula_win = tk.Toplevel(self)
        eula_win.title("最终用户许可协议 (EULA)")
        eula_win.geometry("800x580")
        eula_win.resizable(False, False)
        eula_win.transient(self)
        eula_win.grab_set()
        eula_win.configure(bg=C["bg"])
        eula_win.protocol("WM_DELETE_WINDOW", lambda: _decline())

        # 标题
        tk.Label(eula_win, text="量盾安全 - 最终用户许可协议 (EULA)",
                 bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 16, "bold")).pack(pady=(24, 12))

        # 协议文本框
        text_frame = tk.Frame(eula_win, bg=C["card"])
        text_frame.pack(fill="both", expand=True, padx=30, pady=(0, 18))

        txt = tk.Text(text_frame, bg=C["card"], fg=C["text"],
                      font=(FONT_FAMILY, 10), wrap="word",
                      relief="flat", bd=0, padx=15, pady=15, height=20)
        sb = tk.Scrollbar(text_frame, command=txt.yview,
                            bg=C["border"], troughcolor=C["card"],
                            relief="flat", bd=0)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        txt.insert("1.0", EULA_TEXT)
        txt.config(state="disabled")

        # 按钮区域
        btn_frame = tk.Frame(eula_win, bg=C["bg"])
        btn_frame.pack(pady=(0, 24))

        def _accept():
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._settings_data["eula_accepted"] = True
            self._settings_data["eula_accepted_at"] = ts
            self._save_settings()
            write_audit({
                "event": "eula_accepted",
                "action": "同意",
                "timestamp": ts,
                "version": "2026.1"
            })
            self._log(f"用户已同意 EULA ({ts})", "success")
            eula_win.destroy()

        def _decline():
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            write_audit({
                "event": "eula_declined",
                "action": "拒绝",
                "timestamp": ts,
                "version": "2026.1"
            })
            self._log(f"用户已拒绝 EULA ({ts})，程序即将退出", "danger")
            eula_win.destroy()
            self._on_close()
            sys.exit(0)

        self._btn(btn_frame, "同意并继续", _accept, color=C["green"]).pack(side="left", padx=(0, 12))
        self._btn(btn_frame, "拒绝并退出", _decline, color=C["danger"]).pack(side="left")

        # 居中于主窗口
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 800) // 2
        y = self.winfo_y() + (self.winfo_height() - 580) // 2
        eula_win.geometry(f"+{max(0, x)}+{max(0, y)}")

        self.wait_window(eula_win)

    # ══════════════════════════════════════════
    #  自定义标题栏  (UI-9: 统一 Unicode 字符)
    # ══════════════════════════════════════════
    def _create_title_btn(self, parent, text, command, hover_bg=None, fg=None):
        normal_bg = C["panel"]
        hover = hover_bg or _lighten(C["panel"], 0.12)
        color = fg or C["text"]
        # UI-6: 字号 10→11; UI-7: padx 14→21
        btn = tk.Button(parent, text=text, command=command,
                        bg=normal_bg, fg=color,
                        font=(FONT_FAMILY, 11),
                        relief="flat", bd=0, padx=21, pady=3,
                        cursor="hand2", activebackground=hover, activeforeground=color)
        btn.pack(side="left", fill="y")
        btn.bind("<Enter>", lambda e, b=btn, h=hover: b.config(bg=h))
        btn.bind("<Leave>", lambda e, b=btn, n=normal_bg: b.config(bg=n))
        return btn

    def _start_drag(self, event):
        w = getattr(event, 'widget', None)
        if w in (self._btn_min, self._btn_max, self._btn_close):
            return
        self._drag_x = event.x_root - self.winfo_x()
        self._drag_y = event.y_root - self.winfo_y()

    def _on_drag(self, event):
        w = getattr(event, 'widget', None)
        if w in (self._btn_min, self._btn_max, self._btn_close):
            return
        if self._is_maximized:
            self._toggle_maximize()
            self._drag_x = self.winfo_width() // 2
            self._drag_y = 18
        x = event.x_root - self._drag_x
        y = event.y_root - self._drag_y
        self.geometry(f"+{x}+{y}")

    def _minimize_window(self):
        self.state('withdrawn')

    def _on_map(self, event=None):
        if self.state() == 'withdrawn':
            self.state('normal')

    def _toggle_maximize(self, event=None):
        if self._is_maximized:
            if self._normal_geometry:
                self.geometry(self._normal_geometry)
            self._is_maximized = False
            # UI-9: 统一 Unicode 字符
            self._btn_max.config(text="☐")
        else:
            self._normal_geometry = self.geometry()
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            self.geometry(f"{screen_w}x{screen_h}+0+0")
            self._is_maximized = True
            self._btn_max.config(text="⊟")

    # ══════════════════════════════════════════
    #  UI 构建
    # ══════════════════════════════════════════
    def _build_ui(self):
        # === 自定义标题栏 ===
        self._title_bar = tk.Frame(self, bg=C["panel"], height=36, bd=0, highlightthickness=0)
        self._title_bar.pack(side="top", fill="x")
        self._title_bar.pack_propagate(False)

        # 左侧：标题 (UI-8: 移除 ◆ 图标)
        title_left = tk.Frame(self._title_bar, bg=C["panel"])
        title_left.pack(side="left", fill="y")
        # UI-7: padx (12,4) → (18,6)
        tk.Label(title_left, text="量盾安全", bg=C["panel"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 11, "bold")).pack(side="left", padx=(18, 6))

        # 右侧：窗口控制按钮 (UI-9: 统一 Unicode)
        ctrl_frame = tk.Frame(self._title_bar, bg=C["panel"])
        ctrl_frame.pack(side="right", fill="y")

        self._btn_min = self._create_title_btn(ctrl_frame, "─", self._minimize_window)
        self._btn_max = self._create_title_btn(ctrl_frame, "☐", self._toggle_maximize)
        self._btn_close = self._create_title_btn(ctrl_frame, "✕", self._on_close,
                                                   hover_bg=C["danger"], fg=C["white"])

        # 绑定拖动事件
        def _bind_drag_recursive(widget):
            if widget not in (self._btn_min, self._btn_max, self._btn_close):
                widget.bind("<Button-1>", self._start_drag)
                widget.bind("<B1-Motion>", self._on_drag)
                widget.bind("<Double-Button-1>", self._toggle_maximize)
            for child in widget.winfo_children():
                _bind_drag_recursive(child)

        _bind_drag_recursive(self._title_bar)
        for btn in (self._btn_min, self._btn_max, self._btn_close):
            btn.unbind("<Button-1>")
            btn.unbind("<B1-Motion>")
            btn.unbind("<Double-Button-1>")

        # === 内容区域容器 ===
        self._content = tk.Frame(self, bg=C["bg"])
        self._content.pack(side="top", fill="both", expand=True)

        nav = tk.Frame(self._content, bg=C["panel"], width=220)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)

        self._draw_logo(nav)
        self._nav_buttons(nav)

        self._main = tk.Frame(self._content, bg=C["bg"])
        self._main.pack(side="left", fill="both", expand=True)

        # UI-7: height 52→78; 顶栏
        topbar = tk.Frame(self._main, bg=C["panel"], height=78)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        # UI-6: 字号 10→11; UI-7: padx 20→30, pady 14→21
        tk.Label(topbar, textvariable=self._status_text,
                 bg=C["panel"], fg=C["accent"],
                 font=(FONT_FAMILY, 11)).pack(side="left", padx=30, pady=21)
        # UI-6: 字号 9→10; UI-7: padx 20→30
        self._time_lbl = tk.Label(topbar, text="", bg=C["panel"],
                                   fg=C["dim"], font=(FONT_FAMILY, 10))
        self._time_lbl.pack(side="right", padx=30)
        self._update_clock()

        self._nb = self._TabManager(self._main)

        self._page_home       = self._build_home(self._nb)
        self._page_scan       = self._build_scan(self._nb)
        self._page_update     = self._build_update(self._nb)
        self._page_log        = self._build_log(self._nb)
        self._page_quarantine = self._build_quarantine(self._nb)
        self._page_settings   = self._build_settings(self._nb)
        self._page_about      = self._build_about(self._nb)

        # UI-8: 移除图标参数，只保留文字
        self._nb.add_tab("首页",   self._page_home)
        self._nb.add_tab("扫描",   self._page_scan)
        self._nb.add_tab("更新",   self._page_update)
        self._nb.add_tab("日志",   self._page_log)
        self._nb.add_tab("隔离箱", self._page_quarantine)
        self._nb.add_tab("设置",   self._page_settings)
        self._nb.add_tab("关于",   self._page_about)

        self._switch_tab(0)

    class _TabManager(tk.Frame):
        def __init__(self, parent):
            super().__init__(parent, bg=C["bg"])
            self.pack(fill="both", expand=True)
            self._tabs   = []
            self._frames = []
            self._active = -1
        def add_tab(self, name, frame):
            self._tabs.append(name)
            self._frames.append(frame)
        def show(self, idx):
            for i, f in enumerate(self._frames):
                if i == idx:
                    f.pack(fill="both", expand=True)
                else:
                    f.pack_forget()
            self._active = idx

    # ── FIX-1: 现代几何盾牌 Logo ──────────────────────────
    def _draw_logo(self, parent):
        c = tk.Canvas(parent, width=220, height=110,
                      bg=C["panel"], highlightthickness=0)
        c.pack(pady=(30, 0))

        # 外层盾牌轮廓
        c.create_line(80, 22, 140, 22, fill=C["accent"], width=2)
        c.create_arc(68, 22, 92, 46, start=90, extent=90,
                     outline=C["accent"], width=2, style="arc")
        c.create_line(80, 34, 80, 70, fill=C["accent"], width=2)
        c.create_line(80, 70, 110, 95, fill=C["accent"], width=2)
        c.create_line(140, 70, 110, 95, fill=C["accent"], width=2)
        c.create_line(140, 34, 140, 70, fill=C["accent"], width=2)
        c.create_arc(128, 22, 152, 46, start=0, extent=90,
                     outline=C["accent"], width=2, style="arc")

        shield_pts = [90, 30, 130, 30, 130, 66, 110, 86, 90, 66]
        c.create_polygon(shield_pts, fill=C["accent2"], outline="", smooth=False)

        c.create_text(110, 54, text="LD",
                      font=("Consolas", 16, "bold"), fill=C["white"])

        # UI-6: 字号 15→16
        tk.Label(parent, text="量盾安全", bg=C["panel"],
                 fg=C["white"], font=(FONT_FAMILY_BOLD, 16, "bold")).pack()
        # UI-6: 字号 9→10; UI-7: pady (2,16) → (3,24)
        tk.Label(parent, text="专业病毒防护", bg=C["panel"],
                 fg=C["dim"], font=(FONT_FAMILY, 10)).pack(pady=(3, 24))
        # UI-7: padx 16→24
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=24)

    # ── UI-8: 导航按钮 — 只保留文字，移除几何符号 ────────
    def _nav_buttons(self, parent):
        btns = [
            ("首页概览", 0), ("病毒扫描", 1),
            ("更新病毒库", 2), ("扫描日志", 3),
            ("隔离箱", 4), ("系统设置", 5), ("关于软件", 6),
        ]
        self._nav_btns = []
        for label, idx in btns:
            b = tk.Button(
                parent, text=label, anchor="w",
                bg=C["panel"], fg=C["text"],
                # UI-6: 字号 10→11; UI-7: padx 22→33, pady 10→15
                font=(FONT_FAMILY, 11),
                relief="flat", bd=0, padx=33, pady=15,
                activebackground=C["card"], activeforeground=C["accent"],
                cursor="hand2",
                command=lambda i=idx: self._switch_tab(i)
            )
            b.pack(fill="x", pady=1)
            b.bind("<Enter>", lambda e, btn=b: self._on_nav_hover(btn, True))
            b.bind("<Leave>", lambda e, btn=b: self._on_nav_hover(btn, False))
            self._nav_btns.append(b)
        # UI-6: 字号 8→9; UI-7: pady 12→18
        tk.Label(parent, text="v5.5.0  |  引擎: ClamAV",
                 bg=C["panel"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack(side="bottom", pady=18)

    def _on_nav_hover(self, btn, entering):
        try:
            current_idx = self._nb._active
            btn_idx = self._nav_btns.index(btn)
            if btn_idx == current_idx:
                return
        except (ValueError, AttributeError):
            pass
        if entering:
            btn.config(bg=_lighten(C["panel"], 0.12), fg=C["accent"])
        else:
            btn.config(bg=C["panel"], fg=C["text"])

    def _switch_tab(self, idx):
        self._nb.show(idx)
        for i, b in enumerate(self._nav_btns):
            if i == idx:
                b.config(bg=C["card"], fg=C["accent"])
            else:
                b.config(bg=C["panel"], fg=C["text"])
        if idx == 4:
            self._refresh_quarantine()
        # FIX-AUTOSTART-2: 切换到设置页时同步外部自启状态
        if idx == 5:
            self._sync_autostart_state()

    def _sync_autostart_state(self):
        """同步外部对自启动状态的修改（如任务管理器手动关闭）"""
        real = self._autostart_mgr.is_enabled()
        current = self._autostart.get()
        if real != current:
            self._autostart.set(real)
            self._settings_data["autostart"] = real
            self._save_settings()
            self._log(f"开机自启状态已同步为: {'启用' if real else '禁用'}", "info")

    # ═════════════ 通用 UI 工具 ═════════════

    def _btn(self, parent, text, cmd, color=None):
        """创建统一风格按钮"""
        c = color or C["accent"]
        bg_normal   = c
        bg_hover    = _lighten(c, 0.15)
        fg_normal   = C["bg"] if c in (C["accent"], C["accent2"], C["green"],
                                        C["warn"], C["danger"]) else C["text"]
        fg_hover    = C["white"] if fg_normal == C["bg"] else C["white"]

        # UI-6: 字号 9→10; UI-7: padx 16→24, pady 7→10
        b = tk.Button(parent, text=text, command=cmd,
                      bg=bg_normal, fg=fg_normal,
                      activebackground=bg_hover, activeforeground=fg_hover,
                      font=(FONT_FAMILY, 10, "bold"),
                      relief="flat", bd=0, padx=24, pady=10,
                      cursor="hand2")
        b.bind("<Enter>", lambda e, btn=b, bh=bg_hover, fh=fg_hover:
               btn.config(bg=bh, fg=fh))
        b.bind("<Leave>", lambda e, btn=b, bn=bg_normal, fn=fg_normal:
               btn.config(bg=bn, fg=fn))
        return b

    def _progress_bar(self, parent, style="ld.Horizontal.TProgressbar"):
        pb = ttk.Progressbar(parent, style=style, mode="determinate", maximum=100)
        # UI-7: pady (6,0) → (9,0)
        pb.pack(fill="x", pady=(9, 0))
        return pb

    def _log_text(self, parent, height=10):
        """创建日志文本框，带行数限制"""
        frame = tk.Frame(parent, bg=C["card"], bd=0)
        # UI-6: 字号 9→10; UI-7: padx 12→18, pady 10→15
        txt = tk.Text(frame, bg=C["card"], fg=C["text"],
                      font=(FONT_MONO, 10), wrap="word",
                      relief="flat", bd=0, padx=18, pady=15,
                      insertbackground=C["accent"],
                      selectbackground=C["accent2"],
                      height=height, state="disabled",
                      cursor="arrow")
        sb = tk.Scrollbar(frame, command=txt.yview,
                          bg=C["border"], troughcolor=C["card"],
                          relief="flat", bd=0)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        txt._max_lines = MAX_LOG_LINES
        return txt

    def _append_log(self, text_widget, msg, tag=None):
        """向日志文本框追加内容，带行数限制"""
        text_widget.config(state="normal")
        text_widget.insert("end", msg + "\n")
        line_count = int(text_widget.index('end-1c').split('.')[0])
        if line_count > text_widget._max_lines:
            text_widget.delete("1.0", f"{line_count - text_widget._max_lines}.0")
        text_widget.see("end")
        text_widget.config(state="disabled")

    def _log(self, msg, tag="info"):
        """全局日志方法"""
        ts = datetime.now().strftime("%H:%M:%S")
        for log_widget in [getattr(self, '_scan_out', None),
                           getattr(self, '_upd_out', None),
                           getattr(self, '_main_log', None)]:
            if log_widget is not None and log_widget.winfo_exists():
                self._append_log(log_widget, f"[{ts}] {msg}")

    # ═════════════ 首页 ═════════════
    def _build_home(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        # UI-6: 字号 17→18; UI-7: padx 32→48, pady (24,4)→(36,6)
        tk.Label(frame, text="安全概览", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 18, "bold")).pack(anchor="w", padx=48, pady=(36, 6))
        # UI-6: 字号 10→11; UI-7: padx 32→48, pady (0,20)→(0,30)
        tk.Label(frame, text="系统防护状态与病毒库信息", bg=C["bg"],
                 fg=C["dim"], font=(FONT_FAMILY, 11)).pack(anchor="w", padx=48, pady=(0, 30))

        cards_frame = tk.Frame(frame, bg=C["bg"])
        # UI-7: padx 32→48, pady (0,20)→(0,30)
        cards_frame.pack(fill="x", padx=48, pady=(0, 30))
        for i in range(4):
            cards_frame.columnconfigure(i, weight=1, uniform="card")

        # UI-10: 卡片间距 12→20
        self._card_engine = self._status_card_grid(cards_frame, "引擎状态", "检测中…", C["warn"], 0)
        self._card_db     = self._status_card_grid(cards_frame, "病毒库",   "检测中…", C["warn"], 1)
        self._card_last   = self._status_card_grid(cards_frame, "上次扫描", "未扫描",  C["dim"],  2)
        self._card_quar   = self._status_card_grid(cards_frame, "隔离箱",   "0 个文件", C["dim"],  3)

        # UI-6: 字号 11→12; UI-7: padx 32→48, pady (0,8)→(0,12)
        tk.Label(frame, text="病毒库文件", bg=C["bg"], fg=C["text"],
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=48, pady=(0, 12))

        db_frame = tk.Frame(frame, bg=C["card"], bd=0)
        # UI-7: padx 32→48, pady (0,20)→(0,30)
        db_frame.pack(fill="x", padx=48, pady=(0, 30))
        headers = ["文件名", "大小", "更新时间", "状态"]
        for col, h in enumerate(headers):
            # UI-6: 字号 9→10; UI-7: padx 16→24, pady 8→12
            tk.Label(db_frame, text=h, bg=C["border"], fg=C["dim"],
                     font=(FONT_FAMILY, 10, "bold"),
                     padx=24, pady=12).grid(row=0, column=col, sticky="ew", padx=1, pady=1)
            db_frame.columnconfigure(col, weight=1)

        self._db_rows = []
        for r in range(6):
            row_labels = []
            for col in range(4):
                # UI-6: 字号 9→10; UI-7: padx 16→24, pady 7→10
                lbl = tk.Label(db_frame, text="—", bg=C["card"], fg=C["dim"],
                               font=(FONT_FAMILY, 10), padx=24, pady=10)
                lbl.grid(row=r+1, column=col, sticky="ew", padx=1, pady=1)
                row_labels.append(lbl)
            self._db_rows.append(row_labels)

        # UI-7: padx 32→48, pady 8→12
        btn_row = tk.Frame(frame, bg=C["bg"])
        btn_row.pack(padx=48, pady=12, anchor="w")
        # UI-7: padx (0,12)→(0,18)
        self._btn(btn_row, "快速扫描", lambda: self._quick_scan()).pack(side="left", padx=(0, 18))
        self._btn(btn_row, "更新病毒库", lambda: (self._switch_tab(2), self._start_update()),
                  color=C["accent2"]).pack(side="left", padx=(0, 18))
        self._btn(btn_row, "查看隔离箱", lambda: self._switch_tab(4),
                  color=C["warn"]).pack(side="left", padx=(0, 18))
        self._btn(btn_row, "刷新状态", self._init_check,
                  color=C["dim"]).pack(side="left")
        return frame

    # UI-10: 卡片间距 12→20
    def _status_card_grid(self, parent, title, value, color, col):
        padx_val = (0, 20) if col < 3 else (0, 0)
        # UI-7: pady 16→24, padx 20→30
        card = tk.Frame(parent, bg=C["card"], pady=24, padx=30)
        card.grid(row=0, column=col, sticky="ew", padx=padx_val)
        # UI-6: 字号 9→10
        tk.Label(card, text=title, bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(anchor="w")
        # UI-6: 字号 13→14; UI-7: pady (4,0)→(6,0)
        lbl = tk.Label(card, text=value, bg=C["card"], fg=color,
                       font=(FONT_FAMILY_BOLD, 14, "bold"),
                       wraplength=140, justify="left")
        lbl.pack(anchor="w", pady=(6, 0))

        def _adjust_wrap(event):
            try:
                new_wl = max(60, event.width - 60)
                lbl.config(wraplength=new_wl)
            except Exception:
                pass
        lbl.bind("<Configure>", _adjust_wrap)

        return lbl

    # ═════════════ 扫描页 ═════════════
    def _build_scan(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        # UI-6: 字号 17→18; UI-7: padx 32→48, pady (24,4)→(36,6)
        tk.Label(frame, text="病毒扫描", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 18, "bold")).pack(anchor="w", padx=48, pady=(36, 6))

        # UI-7: pady 14→21, padx 18→27
        target_frame = tk.Frame(frame, bg=C["card"], pady=21, padx=27)
        # UI-7: padx 32→48, pady (8,0)→(12,0)
        target_frame.pack(fill="x", padx=48, pady=(12, 0))
        # UI-6: 字号 9→10
        tk.Label(target_frame, text="扫描目标", bg=C["card"],
                 fg=C["dim"], font=(FONT_FAMILY, 10)).pack(anchor="w")
        row = tk.Frame(target_frame, bg=C["card"])
        # UI-7: pady (6,0)→(9,0)
        row.pack(fill="x", pady=(9, 0))
        self._target_entry = tk.Entry(
            row, textvariable=self._scan_target,
            bg=C["border"], fg=C["text"], insertbackground=C["accent"],
            # UI-6: 字号 10→11
            relief="flat", font=(FONT_FAMILY, 11),
            bd=0, highlightthickness=1, highlightbackground=C["border"],
            highlightcolor=C["accent"]
        )
        # UI-7: ipady 6→9, padx (0,8)→(0,12)
        self._target_entry.pack(side="left", fill="x", expand=True, ipady=9, padx=(0, 12))
        # UI-7: padx (0,6)→(0,9)
        self._btn(row, "选择文件", self._pick_file).pack(side="left", padx=(0, 9))
        self._btn(row, "选择目录", self._pick_dir).pack(side="left")

        # UI-7: padx 32→48, pady 12→18
        type_frame = tk.Frame(frame, bg=C["bg"])
        type_frame.pack(fill="x", padx=48, pady=18)
        self._scan_type = tk.StringVar(value="custom")
        types = [("自定义路径", "custom"), ("扫描主目录", "home"),
                 ("扫描全盘", "full"), ("扫描临时目录", "tmp")]
        for label, val in types:
            rb = tk.Radiobutton(
                type_frame, text=label, variable=self._scan_type, value=val,
                bg=C["bg"], fg=C["text"], selectcolor=C["card"],
                activebackground=C["bg"], activeforeground=C["accent"],
                # UI-6: 字号 10→11; UI-7: padx 12→18, pady 6→9
                font=(FONT_FAMILY, 11),
                indicatoron=True, padx=18, pady=9
            )
            rb.pack(side="left", padx=(0, 18))

        # 操作按钮行
        # UI-7: padx 32→48, pady 12→18
        action_frame = tk.Frame(frame, bg=C["bg"])
        action_frame.pack(fill="x", padx=48, pady=18)
        self._scan_btn = self._btn(action_frame, "开始扫描", self._start_scan)
        self._scan_btn.pack(side="left", padx=(0, 12))
        self._stop_btn = self._btn(action_frame, "停止扫描", self._stop_scan, color=C["danger"])
        self._stop_btn.pack(side="left", padx=(0, 12))
        self._stop_btn.config(state="disabled")

        # 进度条区域
        # UI-7: padx 32→48, pady (0,6)→(0,9)
        prog_frame = tk.Frame(frame, bg=C["bg"])
        prog_frame.pack(fill="x", padx=48, pady=(0, 9))
        self._scan_pb = self._progress_bar(prog_frame, "ld.Horizontal.TProgressbar")
        # UI-6: 字号 9→10
        self._scan_file_lbl = tk.Label(prog_frame, textvariable=self._current_scan_file,
                                        bg=C["bg"], fg=C["dim"],
                                        font=(FONT_FAMILY, 10))
        self._scan_file_lbl.pack(anchor="w", pady=(6, 0))

        # 扫描结果区域
        # UI-6: 字号 11→12; UI-7: padx 32→48, pady (12,6)→(18,9)
        tk.Label(frame, text="扫描结果", bg=C["bg"], fg=C["text"],
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=48, pady=(18, 9))

        result_outer = tk.Frame(frame, bg=C["card"])
        # UI-7: padx 32→48, pady (0,12)→(0,18)
        result_outer.pack(fill="both", expand=True, padx=48, pady=(0, 18))
        self._scan_out = self._log_text(result_outer, height=12)

        return frame

    # ═════════════ 更新页 ═════════════
    def _build_update(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        # UI-6: 字号 17→18; UI-7: padx 32→48, pady (24,4)→(36,6)
        tk.Label(frame, text="更新病毒库", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 18, "bold")).pack(anchor="w", padx=48, pady=(36, 6))
        # UI-6: 字号 10→11
        tk.Label(frame, text="从官方镜像服务器下载最新病毒定义", bg=C["bg"],
                 fg=C["dim"], font=(FONT_FAMILY, 11)).pack(anchor="w", padx=48, pady=(0, 24))

        # 操作按钮行
        # UI-7: padx 32→48, pady 12→18
        action_frame = tk.Frame(frame, bg=C["bg"])
        action_frame.pack(fill="x", padx=48, pady=18)
        self._upd_btn = self._btn(action_frame, "开始更新", self._start_update)
        self._upd_btn.pack(side="left")

        # 进度条
        # UI-7: padx 32→48, pady (0,12)→(0,18)
        prog_frame = tk.Frame(frame, bg=C["bg"])
        prog_frame.pack(fill="x", padx=48, pady=(0, 18))
        self._upd_pb = self._progress_bar(prog_frame, "ld_up.Horizontal.TProgressbar")
        self._upd_pct_lbl = tk.Label(prog_frame, text="", bg=C["bg"], fg=C["dim"],
                                      font=(FONT_FAMILY, 10))
        self._upd_pct_lbl.pack(anchor="w", pady=(6, 0))

        # 更新日志
        # UI-6: 字号 11→12; UI-7: padx 32→48, pady (12,6)→(18,9)
        tk.Label(frame, text="更新日志", bg=C["bg"], fg=C["text"],
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=48, pady=(18, 9))

        log_outer = tk.Frame(frame, bg=C["card"])
        # UI-7: padx 32→48, pady (0,12)→(0,18)
        log_outer.pack(fill="both", expand=True, padx=48, pady=(0, 18))
        self._upd_out = self._log_text(log_outer, height=14)

        return frame

    # ═════════════ 日志页 ═════════════
    def _build_log(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        # UI-6: 字号 17→18; UI-7: padx 32→48, pady (24,4)→(36,6)
        tk.Label(frame, text="扫描日志", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 18, "bold")).pack(anchor="w", padx=48, pady=(36, 6))
        # UI-6: 字号 10→11
        tk.Label(frame, text="查看所有扫描与系统活动记录", bg=C["bg"],
                 fg=C["dim"], font=(FONT_FAMILY, 11)).pack(anchor="w", padx=48, pady=(0, 18))

        # 清除按钮
        # UI-7: padx 32→48
        btn_frame = tk.Frame(frame, bg=C["bg"])
        btn_frame.pack(fill="x", padx=48)
        self._btn(btn_frame, "清除日志", self._clear_main_log, color=C["danger"]).pack(side="left")

        log_outer = tk.Frame(frame, bg=C["card"])
        # UI-7: padx 32→48, pady (12,12)→(18,18)
        log_outer.pack(fill="both", expand=True, padx=48, pady=(18, 18))
        self._main_log = self._log_text(log_outer, height=22)

        return frame

    # ═════════════ 隔离箱页 ═════════════
    def _build_quarantine(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        # UI-6: 字号 17→18; UI-7: padx 32→48, pady (24,4)→(36,6)
        tk.Label(frame, text="隔离箱", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 18, "bold")).pack(anchor="w", padx=48, pady=(36, 6))
        # UI-6: 字号 10→11
        tk.Label(frame, text="管理被隔离的威胁文件", bg=C["bg"],
                 fg=C["dim"], font=(FONT_FAMILY, 11)).pack(anchor="w", padx=48, pady=(0, 18))

        # 搜索 + 操作按钮
        # UI-7: padx 32→48
        top_row = tk.Frame(frame, bg=C["bg"])
        top_row.pack(fill="x", padx=48)
        # UI-6: 字号 10→11
        tk.Label(top_row, text="搜索:", bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 11)).pack(side="left")
        self._quar_search_var = tk.StringVar()
        self._quar_search_var.trace_add("write", self._on_quar_search)
        search_entry = tk.Entry(top_row, textvariable=self._quar_search_var,
                                bg=C["border"], fg=C["text"],
                                insertbackground=C["accent"],
                                relief="flat", font=(FONT_FAMILY, 11),
                                bd=0, highlightthickness=1,
                                highlightbackground=C["border"],
                                highlightcolor=C["accent"])
        # UI-7: padx (6,0)→(9,0), ipady 6→9
        search_entry.pack(side="left", fill="x", expand=True, padx=(9, 0), ipady=9)

        # 操作按钮
        # UI-7: padx 32→48, pady 12→18
        btn_row = tk.Frame(frame, bg=C["bg"])
        btn_row.pack(fill="x", padx=48, pady=18)
        self._btn(btn_row, "恢复选中", self._restore_selected, color=C["green"]).pack(side="left", padx=(0, 9))
        self._btn(btn_row, "删除选中", self._delete_selected, color=C["danger"]).pack(side="left", padx=(0, 9))
        self._btn(btn_row, "刷新列表", self._refresh_quarantine, color=C["dim"]).pack(side="left")

        # 隔离箱列表（Canvas + Scrollbar）
        list_outer = tk.Frame(frame, bg=C["card"])
        # UI-7: padx 32→48, pady (0,18)→(0,27)
        list_outer.pack(fill="both", expand=True, padx=48, pady=(0, 27))

        self._quar_canvas = tk.Canvas(list_outer, bg=C["card"], highlightthickness=0)
        quar_sb = tk.Scrollbar(list_outer, orient="vertical", command=self._quar_canvas.yview,
                               bg=C["border"], troughcolor=C["card"])
        self._quar_inner = tk.Frame(self._quar_canvas, bg=C["card"])
        self._quar_inner.bind("<Configure>",
            lambda e: self._quar_canvas.configure(scrollregion=self._quar_canvas.bbox("all")))
        self._quar_canvas_window = self._quar_canvas.create_window((0, 0), window=self._quar_inner,
                                                                     anchor="nw")
        # FIX-5: Canvas <Configure> 绑定
        self._quar_canvas.bind("<Configure>", self._on_quar_canvas_configure)
        self._quar_canvas.configure(yscrollcommand=quar_sb.set)
        quar_sb.pack(side="right", fill="y")
        self._quar_canvas.pack(side="left", fill="both", expand=True)

        # FIX-6: 鼠标滚轮
        self._quar_canvas.bind("<MouseWheel>", self._on_quar_mousewheel)
        self._quar_canvas.bind("<Button-4>", self._on_quar_mousewheel)
        self._quar_canvas.bind("<Button-5>", self._on_quar_mousewheel)

        # 空状态提示
        self._quar_empty_lbl = tk.Label(self._quar_inner, text="隔离箱为空",
                                         bg=C["card"], fg=C["dim"],
                                         font=(FONT_FAMILY, 11))
        self._quar_empty_lbl.pack(pady=30)

        return frame

    def _on_quar_canvas_configure(self, event):
        try:
            self._quar_canvas.itemconfig(self._quar_canvas_window, width=event.width)
        except Exception:
            pass

    def _on_quar_mousewheel(self, event):
        try:
            if event.num == 4:
                self._quar_canvas.yview_scroll(-3, "units")
            elif event.num == 5:
                self._quar_canvas.yview_scroll(3, "units")
            else:
                self._quar_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except Exception:
            pass

    def _on_quar_search(self, *args):
        if self._quar_search_timer:
            self.after_cancel(self._quar_search_timer)
        # FIX-8: 搜索 debounce
        self._quar_search_timer = self.after(300, self._refresh_quarantine)

    def _refresh_quarantine(self):
        if self._quar_busy:
            return
        self._quar_busy = True

        try:
            search = self._quar_search_var.get().strip().lower()
            items = self.quar_mgr.list_items()

            if search:
                items = [it for it in items
                         if search in it["orig"].lower()
                         or search in it["threat"].lower()
                         or search in it["time"].lower()]

            # 清除现有内容
            for w in self._quar_inner.winfo_children():
                w.destroy()
            self._quar_selected.clear()

            if not items:
                self._quar_empty_lbl = tk.Label(self._quar_inner, text="隔离箱为空",
                                                 bg=C["card"], fg=C["dim"],
                                                 font=(FONT_FAMILY, 11))
                self._quar_empty_lbl.pack(pady=30)
            else:
                # 表头
                hdr = tk.Frame(self._quar_inner, bg=C["border"])
                hdr.pack(fill="x", padx=3, pady=(3, 1))
                # UI-6: 字号 9→10; UI-7: padx 8→12, pady 6→9
                tk.Label(hdr, text="", width=3, bg=C["border"]).pack(side="left", padx=12, pady=9)
                tk.Label(hdr, text="威胁名称", bg=C["border"], fg=C["dim"],
                         font=(FONT_FAMILY, 10, "bold"), width=18, anchor="w").pack(side="left", padx=12, pady=9)
                tk.Label(hdr, text="原路径", bg=C["border"], fg=C["dim"],
                         font=(FONT_FAMILY, 10, "bold"), anchor="w").pack(side="left", fill="x", expand=True, padx=12, pady=9)
                tk.Label(hdr, text="大小", bg=C["border"], fg=C["dim"],
                         font=(FONT_FAMILY, 10, "bold"), width=10, anchor="e").pack(side="left", padx=12, pady=9)
                tk.Label(hdr, text="时间", bg=C["border"], fg=C["dim"],
                         font=(FONT_FAMILY, 10, "bold"), width=18, anchor="e").pack(side="left", padx=12, pady=9)

                for item in items:
                    row = tk.Frame(self._quar_inner, bg=C["card"])
                    row.pack(fill="x", padx=3, pady=1)

                    var = tk.BooleanVar(value=False)
                    qid = item["qid"]
                    cb = tk.Checkbutton(row, variable=var,
                                        bg=C["card"], fg=C["text"],
                                        selectcolor=C["border"],
                                        activebackground=C["card"],
                                        # UI-6: 字号 9→10
                                        font=(FONT_FAMILY, 10))
                    cb.pack(side="left", padx=12, pady=9)

                    def _on_check(v=var, q=qid):
                        if v.get():
                            self._quar_selected.add(q)
                        else:
                            self._quar_selected.discard(q)
                    cb.config(command=_on_check)

                    threat_color = C["danger"] if item["exists"] else C["dim"]
                    tk.Label(row, text=item["threat"], bg=C["card"], fg=threat_color,
                             font=(FONT_FAMILY, 10), width=18, anchor="w").pack(side="left", padx=12, pady=9)
                    tk.Label(row, text=_truncate_path(item["orig"], 50), bg=C["card"], fg=C["text"],
                             font=(FONT_FAMILY, 10), anchor="w").pack(side="left", fill="x", expand=True, padx=12, pady=9)
                    tk.Label(row, text=item["size"], bg=C["card"], fg=C["dim"],
                             font=(FONT_FAMILY, 10), width=10, anchor="e").pack(side="left", padx=12, pady=9)
                    tk.Label(row, text=item["time"], bg=C["card"], fg=C["dim"],
                             font=(FONT_FAMILY, 10), width=18, anchor="e").pack(side="left", padx=12, pady=9)
        except Exception as e:
            self._log(f"刷新隔离箱失败: {e}", "danger")
        finally:
            self._quar_busy = False

    def _restore_selected(self):
        if not self._quar_selected:
            messagebox.showinfo("提示", "请先选择要恢复的文件")
            return
        if not messagebox.askyesno("确认恢复",
                f"确定要恢复 {len(self._quar_selected)} 个文件吗？\n"
                "文件将还原到原始位置。"):
            return
        for qid in list(self._quar_selected):
            ok, msg = self.quar_mgr.restore_item(qid)
            self._log(f"恢复 {qid}: {msg}", "success" if ok else "danger")
        self._quar_selected.clear()
        self._refresh_quarantine()

    def _delete_selected(self):
        if not self._quar_selected:
            messagebox.showinfo("提示", "请先选择要删除的文件")
            return
        if not messagebox.askyesno("确认删除",
                f"确定要彻底删除 {len(self._quar_selected)} 个文件吗？\n"
                "此操作不可撤销！"):
            return
        ok_count, fail_count, fail_list = self.quar_mgr.delete_items(list(self._quar_selected))
        self._log(f"删除完成: 成功 {ok_count}, 失败 {fail_count}", 
                  "success" if fail_count == 0 else "warn")
        self._quar_selected.clear()
        self._refresh_quarantine()

    # ═════════════ 设置页 ═════════════
    def _build_settings(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        # UI-6: 字号 17→18; UI-7: padx 32→48, pady (24,4)→(36,6)
        tk.Label(frame, text="系统设置", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 18, "bold")).pack(anchor="w", padx=48, pady=(36, 6))
        # UI-6: 字号 10→11
        tk.Label(frame, text="配置扫描行为与系统选项", bg=C["bg"],
                 fg=C["dim"], font=(FONT_FAMILY, 11)).pack(anchor="w", padx=48, pady=(0, 24))

        # 威胁处理方式
        # UI-7: padx 32→48, pady 12→18
        card1 = tk.Frame(frame, bg=C["card"], pady=21, padx=30)
        card1.pack(fill="x", padx=48, pady=18)
        # UI-6: 字号 11→12
        tk.Label(card1, text="发现威胁时", bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w")
        # UI-7: padx (18,0)→(27,0), pady (9,0)→(14,0)
        for text, val in [("自动隔离", "quarantine"), ("仅报告", "report"),
                          ("删除文件", "delete")]:
            rb = tk.Radiobutton(
                card1, text=text, variable=self._virus_action, value=val,
                bg=C["card"], fg=C["text"], selectcolor=C["border"],
                activebackground=C["card"], activeforeground=C["accent"],
                # UI-6: 字号 10→11; UI-7: padx 12→18, pady 6→9
                font=(FONT_FAMILY, 11), padx=18, pady=9
            )
            rb.pack(anchor="w", padx=(27, 0), pady=(6, 0))

        # 自动启动
        # UI-7: padx 32→48, pady 12→18
        card2 = tk.Frame(frame, bg=C["card"], pady=21, padx=30)
        card2.pack(fill="x", padx=48, pady=18)
        # UI-6: 字号 11→12
        tk.Label(card2, text="系统选项", bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w")
        autostart_cb = tk.Checkbutton(
            card2, text="开机自动启动", variable=self._autostart,
            bg=C["card"], fg=C["text"], selectcolor=C["border"],
            activebackground=C["card"], activeforeground=C["accent"],
            # UI-6: 字号 10→11; UI-7: padx 12→18, pady 6→9
            font=(FONT_FAMILY, 11), padx=18, pady=9
        )
        autostart_cb.pack(anchor="w", padx=(27, 0), pady=(9, 0))

        # 保存按钮
        # UI-7: padx 32→48, pady 18→27
        self._btn(frame, "保存设置", self._save_and_confirm, color=C["green"]).pack(
            anchor="w", padx=48, pady=27)

        return frame

    def _save_and_confirm(self):
        """保存设置并审计留痕（含自启系统级注册/注销）"""
        old_data = dict(self._settings_data)

        # 先持久化基础配置（确保即使自启失败，其他设置也已保存）
        self._save_settings()

        # 处理自启动变更（调用系统 API）
        old_autostart = old_data.get("autostart", False)
        new_autostart = self._autostart.get()

        if old_autostart != new_autostart:
            if new_autostart:
                ok, msg = self._autostart_mgr.enable()
                if not ok:
                    messagebox.showerror("注册失败", f"无法设置开机自启：{msg}\n请检查系统权限。")
                    self._autostart.set(False)
                    self._settings_data["autostart"] = False
                    self._save_settings()
                    write_audit({
                        "event": "settings_change",
                        "key": "autostart",
                        "old_value": old_autostart,
                        "new_value": new_autostart,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "result": "failed",
                        "error": msg
                    })
                    self._log("开机自启启用失败", "danger")
                    return
                self._log(f"开机自启已启用: {msg}", "success")
            else:
                ok, msg = self._autostart_mgr.disable()
                if ok:
                    self._log(f"开机自启已禁用: {msg}", "info")
                else:
                    self._log(f"开机自启禁用失败: {msg}", "danger")

            write_audit({
                "event": "settings_change",
                "key": "autostart",
                "old_value": old_autostart,
                "new_value": new_autostart,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "result": "success" if ok else "failed"
            })

        # 处理病毒处理方式变更审计
        old_action = old_data.get("virus_action", "quarantine")
        new_action = self._virus_action.get()
        if old_action != new_action:
            write_audit({
                "event": "settings_change",
                "key": "virus_action",
                "old_value": old_action,
                "new_value": new_action,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            self._log(f"威胁处理方式已变更为: {new_action}", "info")

        self._log("设置已保存", "success")
        messagebox.showinfo("设置", "设置已保存")

    # ═════════════ 关于页 ═════════════
    def _build_about(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        # UI-6: 字号 17→18; UI-7: padx 32→48, pady (24,4)→(36,6)
        tk.Label(frame, text="关于软件", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 18, "bold")).pack(anchor="w", padx=48, pady=(36, 6))

        # UI-7: padx 32→48, pady 12→18
        card = tk.Frame(frame, bg=C["card"], pady=30, padx=36)
        card.pack(fill="x", padx=48, pady=18)

        # UI-6: 字号 15→16
        tk.Label(card, text="量盾安全", bg=C["card"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 16, "bold")).pack(anchor="w")
        # UI-6: 字号 10→11; UI-7: pady (6,0)→(9,0)
        tk.Label(card, text="v5.5.0", bg=C["card"], fg=C["accent"],
                 font=(FONT_FAMILY, 11)).pack(anchor="w", pady=(9, 0))
        # UI-6: 字号 9→10; UI-7: pady (12,0)→(18,0)
        tk.Label(card, text="基于 ClamAV 引擎的专业病毒防护软件", bg=C["card"],
                 fg=C["dim"], font=(FONT_FAMILY, 10), wraplength=500,
                 justify="left").pack(anchor="w", pady=(18, 0))
        tk.Label(card, text="自动配置、自动检测、自动更新病毒库", bg=C["card"],
                 fg=C["dim"], font=(FONT_FAMILY, 10), wraplength=500,
                 justify="left").pack(anchor="w")

        # LEGAL-2: 数据透明与隐私声明
        tk.Label(card, text="数据透明与隐私声明", bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", pady=(27, 9))
        privacy_text = (
            "• 本地扫描：所有文件扫描均在本地完成，不会上传任何用户文件至远程服务器。\n"
            "• 网络连接：软件仅连接 ClamAV 官方病毒库服务器（database.clamav.net 及镜像）以下载更新。\n"
            "• 数据收集：不收集用户个人身份信息、文件内容或扫描结果，审计日志仅保存在本地。\n"
            "• 开源引擎：基于 ClamAV 开源引擎（GPL v2），病毒库遵循官方分发条款。"
        )
        tk.Label(card, text=privacy_text, bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), wraplength=500, justify="left").pack(anchor="w")

        # LEGAL-2: 开源许可证声明
        tk.Label(card, text="开源组件许可证", bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", pady=(27, 9))
        license_text = (
            "本软件包含基于 GNU General Public License v2.0 (GPL v2) 授权的 ClamAV 引擎。\n"
            "ClamAV 版权归 © Cisco Systems, Inc. 所有。相关源代码可从 https://www.clamav.net 获取。\n"
            "本软件遵循 GPL v2 许可证条款进行分发与使用。"
        )
        tk.Label(card, text=license_text, bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), wraplength=500, justify="left").pack(anchor="w")

        # 引擎信息
        # UI-6: 字号 11→12; UI-7: pady (18,6)→(27,9)
        tk.Label(card, text="引擎信息", bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", pady=(27, 9))
        self._engine_info_lbl = tk.Label(card, text="检测中…", bg=C["card"], fg=C["dim"],
                                          font=(FONT_FAMILY, 10), wraplength=500,
                                          justify="left")
        self._engine_info_lbl.pack(anchor="w")

        # LEGAL-3: 版权年份更新为 2026
        tk.Label(card, text="© 2026 量盾安全团队", bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(anchor="w", pady=(27, 0))

        return frame

    # ═════════════ 扫描逻辑 ═════════════

    def _pick_file(self):
        f = filedialog.askopenfilename(title="选择扫描文件")
        if f:
            self._scan_target.set(f)
            self._scan_type.set("custom")

    def _pick_dir(self):
        d = filedialog.askdirectory(title="选择扫描目录")
        if d:
            self._scan_target.set(d)
            self._scan_type.set("custom")

    def _quick_scan(self):
        """快速扫描 - 扫描主目录"""
        self._scan_type.set("home")
        self._switch_tab(1)
        self.after(100, self._start_scan)

    def _resolve_scan_target(self):
        """解析扫描目标路径"""
        stype = self._scan_type.get()
        if stype == "home":
            return str(Path.home())
        elif stype == "full":
            if IS_WIN:
                return "C:\\"
            else:
                return "/"
        elif stype == "tmp":
            # FIX-11: 跨平台临时目录
            if IS_WIN:
                return os.environ.get("TEMP", os.environ.get("TMP", "C:\\Temp"))
            else:
                return "/tmp"
        else:  # custom
            target = self._scan_target.get().strip()
            if not target:
                return None
            return target

    def _start_scan(self):
        if self._scanning:
            return
        target = self._resolve_scan_target()
        if not target:
            messagebox.showwarning("提示", "请选择扫描目标")
            return
        if not Path(target).exists():
            messagebox.showwarning("提示", f"扫描目标不存在：{target}")
            return

        self._scanning = True
        self._scan_results = None
        self._scan_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._current_scan_file.set("正在启动扫描…")
        self._status_text.set("扫描中…")
        self._scan_has_real_total = False

        # 重置进度条并进入阶段1：0 → 5%，约1秒
        try:
            if self._scan_pb.winfo_exists():
                self._scan_pb.stop()
                self._scan_pb.configure(mode="determinate")
                self._scan_pb['value'] = 0
        except Exception:
            pass
        self._smooth_progress_to(5, 1000)

        # 1秒后启动阶段2伪进度（若真实进度尚未到达）
        self._pseudo_start_time = time.time()
        self.after(1000, self._start_pseudo_progress)

        self.backend.scan(
            target,
            progress_cb=self._update_scan_progress,
            result_cb=self._scan_done,
            log_file_cb=self._set_scan_log
        )

    def _start_pseudo_progress(self):
        """阶段1结束后启动阶段2伪进度曲线"""
        if not self._scanning or self._scan_has_real_total:
            return
        self._pseudo_progress_tick()

    def _smooth_progress_to(self, target, duration):
        """用 after(30ms) 把当前进度条值线性插值到 target（duration 单位 ms）"""
        if self._smooth_timer:
            self.after_cancel(self._smooth_timer)
            self._smooth_timer = None

        try:
            start_val = self._scan_pb['value'] if self._scan_pb.winfo_exists() else 0
        except Exception:
            start_val = 0

        start_time = time.time()

        def _step():
            if not self._scanning:
                return
            elapsed = time.time() - start_time
            if elapsed >= duration / 1000:
                try:
                    if self._scan_pb.winfo_exists():
                        self._scan_pb['value'] = target
                except Exception:
                    pass
                return
            ratio = elapsed / (duration / 1000)
            current = start_val + (target - start_val) * ratio
            try:
                if self._scan_pb.winfo_exists():
                    self._scan_pb['value'] = current
            except Exception:
                pass
            self._smooth_timer = self.after(30, _step)

        self._smooth_timer = self.after(30, _step)

    def _pseudo_progress_tick(self):
        """渐进曲线定时器：仅在未收到真实 total 估算时启用"""
        if not self._scanning or self._scan_has_real_total:
            return
        elapsed = time.time() - self._pseudo_start_time
        # 公式: 90 * (1 - exp(-elapsed/30))
        target = 90 * (1 - math.exp(-elapsed / 30))
        # 保证不低于当前值，避免回退
        try:
            current = self._scan_pb['value'] if self._scan_pb.winfo_exists() else 0
        except Exception:
            current = 0
        target = max(target, current, 5.0)  # 不低于阶段1结束值 5%
        target = min(target, 90.0)
        self._smooth_progress_to(target, 200)
        self._pseudo_timer = self.after(200, self._pseudo_progress_tick)

    def _stop_scan(self):
        if not self._scanning:
            return
        self.backend.cancel_scan()
        self._scanning = False
        self._scan_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._current_scan_file.set("扫描已停止")
        self._status_text.set("扫描已停止")

        # 清理所有进度定时器
        if self._smooth_timer:
            self.after_cancel(self._smooth_timer)
            self._smooth_timer = None
        if self._pseudo_timer:
            self.after_cancel(self._pseudo_timer)
            self._pseudo_timer = None
        self._scan_has_real_total = False

        # 重置进度条
        try:
            if self._scan_pb.winfo_exists():
                self._scan_pb.stop()
                self._scan_pb.configure(mode="determinate")
                self._scan_pb['value'] = 0
        except Exception:
            pass

        self._log("扫描已手动停止", "warn")

    def _update_scan_progress(self, val, filename=None, scanned=None, total=None):
        """扫描进度回调（扩展签名）"""
        if val >= 0:
            # 收到真实进度，标记并取消伪进度
            self._scan_has_real_total = True
            if self._pseudo_timer:
                self.after_cancel(self._pseudo_timer)
                self._pseudo_timer = None

            if val == 90:
                # 阶段3开始：stdout 读完，proc.wait 期间从90平滑爬到95
                self._smooth_progress_to(95, 3000)
            elif val == 95:
                self._smooth_progress_to(95, 200)
            else:
                self._smooth_progress_to(val, 200)

        if filename:
            # 更新文件名与计数文本
            if scanned is not None and total is not None and total > 0:
                self._current_scan_file.set(
                    f"正在扫描: {filename}  (已扫描 {scanned} / 估计 {total} 个文件)"
                )
            elif scanned is not None:
                self._current_scan_file.set(
                    f"正在扫描: {filename}  (已扫描 {scanned} 个文件)"
                )
            else:
                self._current_scan_file.set(f"正在扫描: {filename}")

    def _set_scan_log(self, path):
        self._scan_log_path = path

    def _scan_done(self, results, error):
        """扫描完成回调"""
        self._scanning = False
        self._scan_btn.config(state="normal")
        self._stop_btn.config(state="disabled")

        # 清理进度定时器
        if self._smooth_timer:
            self.after_cancel(self._smooth_timer)
            self._smooth_timer = None
        if self._pseudo_timer:
            self.after_cancel(self._pseudo_timer)
            self._pseudo_timer = None
        self._scan_has_real_total = False

        # 确保进度条 determinate
        try:
            if self._scan_pb.winfo_exists():
                self._scan_pb.stop()
                self._scan_pb.configure(mode="determinate")
        except Exception:
            pass

        if error:
            self._current_scan_file.set(f"扫描出错: {error}")
            self._status_text.set("扫描出错")
            self._log(f"扫描错误: {error}", "danger")
            try:
                if self._scan_pb.winfo_exists():
                    self._scan_pb['value'] = 0
            except Exception:
                pass
            return

        if results is None:
            self._current_scan_file.set("扫描失败")
            self._status_text.set("扫描失败")
            return

        # result_cb 时一次性跳 100
        try:
            if self._scan_pb.winfo_exists():
                self._scan_pb['value'] = 100
        except Exception:
            pass

        self._scan_results = results
        total = results["scanned"]
        infected = len(results["infected"])
        errors = results["errors"]

        self._current_scan_file.set(
            f"扫描完成 | 已扫描: {total} | 威胁: {infected} | 错误: {errors}")

        if infected == 0:
            self._status_text.set("扫描完成 - 安全")
        else:
            self._status_text.set(f"扫描完成 - 发现 {infected} 个威胁")

        # 处理威胁
        if infected > 0:
            action = self._virus_action.get()
            for item in results["infected"]:
                if action == "quarantine":
                    ok, msg = self.quar_mgr.quarantine_file(item["path"], item["virus"])
                    self._log(f"隔离: {item['display_path']} → {msg}",
                              "success" if ok else "danger")
                elif action == "delete":
                    try:
                        Path(item["path"]).unlink()
                        self._log(f"已删除: {item['display_path']}", "success")
                    except Exception as e:
                        self._log(f"删除失败: {item['display_path']} - {e}", "danger")
                else:  # report
                    self._log(f"发现威胁（仅报告）: {item['display_path']} [{item['virus']}]",
                              "warn")

        # 更新首页卡片
        self._card_last.config(text=f"威胁: {infected}")
        self._update_quar_count()

    # ═════════════ 更新逻辑 ═════════════

    def _start_update(self):
        if self._updating:
            return

        self._updating = True
        self._upd_btn.config(state="disabled")
        self._status_text.set("正在更新病毒库…")

        # UI-1: 启动更新时自动进入脉冲动画
        self._update_pulsing = True
        self.start_pulse(self._upd_pb)

        self.backend.update_database(
            progress_cb=self._update_progress,
            done_cb=self._update_done
        )

    def _update_progress(self, val):
        """更新进度回调"""
        # UI-2: 收到实际进度值(>5%)时自动切换回 determinate 模式
        if val > 5 and self._update_pulsing:
            self._update_pulsing = False
            self.stop_pulse(self._upd_pb, val)
        elif not self._update_pulsing:
            try:
                if self._upd_pb.winfo_exists():
                    self._upd_pb['value'] = val
            except Exception:
                pass

        try:
            if self._upd_pct_lbl.winfo_exists():
                self._upd_pct_lbl.config(text=f"{val}%")
        except Exception:
            pass

    def _update_done(self, success, msg):
        """更新完成回调"""
        self._updating = False
        self._upd_btn.config(state="normal")

        # UI-3: 更新完成时自动停止脉冲
        self._update_pulsing = False
        self.stop_pulse(self._upd_pb, 100 if success else 0)

        if success:
            self._status_text.set("病毒库更新成功")
            self._upd_pct_lbl.config(text="100% - 完成")
        else:
            self._status_text.set(f"更新失败: {msg}")
            self._upd_pct_lbl.config(text=f"失败: {msg}")

        self._init_check()

    # ═════════════ 初始化与时钟 ═════════════

    def _init_check(self):
        """启动时检查引擎和病毒库状态"""
        def check():
            ok, msg = self.backend.check_engine()
            self.after(0, lambda: self._update_engine_status(ok, msg))
        threading.Thread(target=check, daemon=True).start()

    def _update_engine_status(self, ok, msg):
        if ok:
            self._card_engine.config(text="就绪", fg=C["green"])
            self._engine_info_lbl.config(text=msg, fg=C["text"])
        else:
            self._card_engine.config(text="未就绪", fg=C["danger"])
            self._engine_info_lbl.config(text=msg, fg=C["danger"])

        db_ok = self.backend.check_database()
        if db_ok:
            db_info = self.backend.get_db_info()
            self._card_db.config(text="已安装", fg=C["green"])
            # 更新数据库表格
            for r, row_labels in enumerate(self._db_rows):
                if r < len(db_info):
                    info = db_info[r]
                    row_labels[0].config(text=info["name"], fg=C["text"])
                    row_labels[1].config(text=info["size"], fg=C["text"])
                    row_labels[2].config(text=info["date"], fg=C["text"])
                    row_labels[3].config(
                        text="✓ 正常" if info["ok"] else "✗ 异常",
                        fg=C["green"] if info["ok"] else C["danger"])
                else:
                    for lbl in row_labels:
                        lbl.config(text="—", fg=C["dim"])
        else:
            self._card_db.config(text="未安装", fg=C["warn"])
            for row_labels in self._db_rows:
                for lbl in row_labels:
                    lbl.config(text="—", fg=C["dim"])

        self._update_quar_count()
        self._status_text.set("系统就绪")

    def _update_quar_count(self):
        try:
            count = self.quar_mgr.count_items()
            self._card_quar.config(text=f"{count} 个文件")
        except Exception:
            self._card_quar.config(text="未知")

    def _update_clock(self):
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if self._time_lbl.winfo_exists():
                self._time_lbl.config(text=now)
        except Exception:
            return
        self.after(1000, self._update_clock)

    def _clear_main_log(self):
        try:
            if self._main_log.winfo_exists():
                self._main_log.config(state="normal")
                self._main_log.delete("1.0", "end")
                self._main_log.config(state="disabled")
        except Exception:
            pass


# ══════════════════════════════════════════════
#  入口
# ══════════════════════════════════════════════
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler()]
    )
    app = LiangDunApp()
    # 居中窗口
    app.update_idletasks()
    sw = app.winfo_screenwidth()
    sh = app.winfo_screenheight()
    w = app.winfo_width()
    h = app.winfo_height()
    x = (sw - w) // 2
    y = (sh - h) // 2
    app.geometry(f"+{x}+{y}")
    app.mainloop()
