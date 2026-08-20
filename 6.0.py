"""
量盾安全 - 专业病毒防护软件
基于 ClamAV 引擎，自动配置、自动检测、自动更新病毒库

v6.0.0 修改清单：
  OPT-1: 新增扫描历史记录管理器 (SQLite)
  OPT-2: 新增扫描白名单管理器 (JSON)
  OPT-3: 新增定时扫描管理器 (JSON)
  OPT-4: 新增 Toast 通知系统
  OPT-5: 新增实时文件监控 (watchdog/轮询)
  OPT-6: 新增威胁详情弹窗
  OPT-7: 新增辅助绘图函数 (圆角矩形、颜色插值、脉冲颜色)
  OPT-8: ClamAV 扫描支持排除列表
  保留 v5.5.3 全部 FIX/LEGAL/UI 条目
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
import struct
import ctypes
import atexit
import hashlib
import sqlite3
import tempfile
import signal
import io
import base64
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

APP_VERSION = "v6.0.0"

# ─────────────────────────────────────────────
#  路径配置（FIX: 支持 PyInstaller 打包后的路径）
# ─────────────────────────────────────────────
def get_base_dir():
    """获取程序基础目录（支持开发环境和 PyInstaller 打包后）"""
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包后，使用 exe 所在目录
        return Path(sys.executable).parent
    else:
        # 开发环境，使用脚本所在目录
        return Path(__file__).parent

BASE_DIR   = get_base_dir()
CLAMAV_DIR = BASE_DIR / "clamav"

# ══════════════════════════════════════════════
#  【FIX-USERDIR-1】用户数据目录（跨平台）
#  将运行时数据（设置、日志、隔离箱、配置、病毒库）
#  从程序安装目录迁移到用户可写目录，避免 Windows
#  Program Files / macOS Applications 等系统目录权限问题
# ══════════════════════════════════════════════
def get_user_data_dir():
    """获取用户数据目录（跨平台）"""
    app_name = "LiangDunSecurity"
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    elif system == "Darwin":
        base = Path.home() / "Library/Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    path = base / app_name
    path.mkdir(parents=True, exist_ok=True)
    return path

USER_DATA_DIR = get_user_data_dir()

# 运行时数据目录（用户可写）
DB_DIR         = USER_DATA_DIR / "db"   # FIX: 病毒库迁至用户可写目录
LOG_DIR        = USER_DATA_DIR / "logs"
CONF_DIR       = USER_DATA_DIR / "conf"
QUARANTINE_DIR = USER_DATA_DIR / "quarantine"

# FIX-BUG-10: 设置文件统一存到用户数据目录，避免权限问题
# 不再使用程序同目录存储设置文件
SETTINGS_DIR  = USER_DATA_DIR
SETTINGS_FILE = SETTINGS_DIR / "settings.json"

# 【FIX-USERDIR-2】迁移旧版数据（从程序目录 → 用户目录）
# 【FIX】设置文件反向迁回程序目录
def _migrate_old_data():
    migrations = [
        (BASE_DIR / "logs",          LOG_DIR),
        (BASE_DIR / "quarantine",    QUARANTINE_DIR),
        (BASE_DIR / "conf",          CONF_DIR),          # FIX: 补迁旧配置
        (CLAMAV_DIR / "db",          DB_DIR),            # FIX: 补迁旧病毒库
    ]
    for old_path, new_path in migrations:
        if old_path.exists() and not new_path.exists():
            try:
                if old_path.is_file():
                    shutil.copy2(str(old_path), str(new_path))
                else:
                    shutil.copytree(str(old_path), str(new_path))
            except Exception:
                pass

    # FIX-BUG-10: 移除设置文件迁回程序目录的逻辑
    # 设置文件统一存到用户数据目录

_migrate_old_data()

IS_WIN = platform.system() == "Windows"
CLAMSCAN    = CLAMAV_DIR / ("clamscan.exe"   if IS_WIN else "clamscan")
FRESHCLAM   = CLAMAV_DIR / ("freshclam.exe"  if IS_WIN else "freshclam")
CLAMD       = CLAMAV_DIR / ("clamd.exe"      if IS_WIN else "clamd")
CLAMD_CONF  = CONF_DIR   / "clamd.conf"
FRESH_CONF  = CONF_DIR   / "freshclam.conf"

CVD_FILES   = ["main.cvd", "daily.cvd", "bytecode.cvd",
               "main.cld", "daily.cld", "bytecode.cld"]

# YARA 规则配置
YARA_NDB_FILE = "yara-rules.ndb"  # 转换后的 YARA 签名文件
YARA_ENABLED  = True               # 是否启用 YARA 规则

# MD5 自定义签名数据库配置
MD5_HDB_FILE = "custom-md5.hsb"    # 自定义 MD5 哈希签名文件（.hsb 格式支持大小通配符）
MD5_ENABLED  = True                 # 是否启用 MD5 签名检测

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
    # v6.0.0 新增颜色主题键
    "card_hover": "#2f3f54",
    "success_bg": "#0d3320",
    "danger_bg":  "#3b1111",
    "warn_bg":    "#3b2a0a",
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
#  v6.0.0 新增辅助函数
# ══════════════════════════════════════════════

def _rounded_rect(canvas, x1, y1, x2, y2, radius, **kwargs):
    """
    在 Canvas 上绘制圆角矩形
    :param canvas: tkinter Canvas 对象
    :param x1, y1: 左上角坐标
    :param x2, y2: 右下角坐标
    :param radius: 圆角半径
    :param **kwargs: 传递给 create_polygon 的额外参数（fill, outline, width 等）
    :return: 创建的 Canvas item id
    """
    points = [
        x1 + radius, y1,                    # 左上角圆弧起点
        x2 - radius, y1,                    # 上边右端
        x2, y1,                             # 右上角圆弧起点
        x2, y1 + radius,                    # 右上角圆弧终点
        x2, y2 - radius,                    # 右下角圆弧起点
        x2, y2,                             # 右下角
        x2 - radius, y2,                    # 下边左端
        x1 + radius, y2,                    # 左下角圆弧起点
        x1, y2,                             # 左下角
        x1, y2 - radius,                    # 左上角下方
        x1, y1 + radius,                    # 左上角
        x1, y1,                             # 回到起点
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)


def _interpolate_color(c1, c2, t):
    """
    在两个十六进制颜色之间进行线性插值
    :param c1: 起始颜色（十六进制字符串，如 "#3b82f6"）
    :param c2: 目标颜色（十六进制字符串）
    :param t: 插值因子，0.0 返回 c1，1.0 返回 c2
    :return: 插值后的十六进制颜色字符串
    """
    t = max(0.0, min(1.0, t))
    h1 = c1.lstrip('#')
    h2 = c2.lstrip('#')
    r1, g1, b1 = int(h1[0:2], 16), int(h1[2:4], 16), int(h1[4:6], 16)
    r2, g2, b2 = int(h2[0:2], 16), int(h2[2:4], 16), int(h2[4:6], 16)
    r = int(r1 + (r2 - r1) * t)
    g = int(g1 + (g2 - g1) * t)
    b = int(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _pulse_color(hex_color, step, total_steps=10):
    """
    计算脉冲动画颜色（在原色和亮色之间来回变化）
    :param hex_color: 基础颜色（十六进制字符串）
    :param step: 当前步骤（0 ~ total_steps-1）
    :param total_steps: 总步骤数（默认 10）
    :return: 当前步骤对应的脉冲颜色
    """
    # 使用正弦函数产生平滑的脉冲效果：0 -> 1 -> 0
    import math as _math
    t = _math.sin(_math.pi * step / total_steps)
    return _interpolate_color(hex_color, _lighten(hex_color, 0.3), t)


# FIX: Windows 下尝试获取 8.3 短路径，失败则返回原路径
# 注意：ctypes 已在文件顶部导入
def _get_short_path(path: Path) -> str:
    if not IS_WIN:
        return str(path)
    try:
        from ctypes import wintypes
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        rv = ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, wintypes.MAX_PATH)
        if rv and rv < wintypes.MAX_PATH:
            return buf.value
    except Exception:
        pass
    return str(path)


# ══════════════════════════════════════════════
#  EULA 协议文本
# ══════════════════════════════════════════════
EULA_TEXT = """量盾安全软件 最终用户许可协议 (EULA)

重要提示：在使用本软件之前，请仔细阅读以下条款。点击"同意"即表示您接受本协议全部条款；如不同意，请立即退出本软件。

1. 许可授予
量盾安全团队（"开发者"）授予您（"用户"）一项有限的、非独占的、不可转让的许可，允许您在一台计算机上安装和使用本软件副本，用于个人或企业内部病毒防护目的。

2. 数据隐私与透明声明
• 本地扫描：所有文件扫描均在本地设备完成，不会上传任何用户文件、文档内容或文件元数据至远程服务器。
• 网络连接：软件仅连接 ClamAV 官方病毒库服务器（database.clamav.net 及 db.cn.clamav.net 等官方镜像）以下载病毒定义更新。
• 数据收集：本软件不收集用户个人身份信息、文件内容、扫描结果或系统使用习惯。审计日志仅保存在用户本地磁盘。
• 开源声明：本软件基于 ClamAV 引擎（GNU General Public License v2.0），病毒库遵循 ClamAV 官方分发条款。

3. 免责声明
本软件按"现状"提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性及非侵权的担保。开发者不对因使用或无法使用本软件导致的任何直接、间接、偶然、特殊或后果性损失承担责任。

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
_audit_lock = threading.Lock()

def write_audit(entry: dict):
    with _audit_lock:
        try:
            AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            if AUDIT_LOG.exists() and AUDIT_LOG.stat().st_size > AUDIT_LOG_MAX_SIZE:
                backup = AUDIT_LOG.parent / (AUDIT_LOG.name + '.1')
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
#  v6.0.0 新增：扫描历史记录管理器 (SQLite)
# ══════════════════════════════════════════════
class ScanHistory:
    """
    扫描历史记录管理器
    使用 SQLite 数据库存储扫描记录，支持按时间查询和统计
    """

    def __init__(self):
        """初始化扫描历史数据库"""
        self._db_path = USER_DATA_DIR / "scan_history.db"
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """初始化数据库表结构"""
        with self._lock:
            try:
                conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT    NOT NULL,
                        scan_type   TEXT    NOT NULL,
                        target      TEXT    NOT NULL,
                        scanned     INTEGER DEFAULT 0,
                        infected    INTEGER DEFAULT 0,
                        errors      INTEGER DEFAULT 0,
                        duration    REAL    DEFAULT 0.0
                    )
                """)
                # 创建索引加速按时间查询
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timestamp
                    ON scan_history(timestamp DESC)
                """)
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"扫描历史数据库初始化失败: {e}")

    def add_record(self, scan_type, target, scanned, infected, errors, duration):
        """
        添加一条扫描记录
        :param scan_type: 扫描类型（如 "快速扫描", "全盘扫描", "自定义扫描"）
        :param target: 扫描目标路径
        :param scanned: 已扫描文件数
        :param infected: 发现威胁数
        :param errors: 错误数
        :param duration: 扫描耗时（秒）
        """
        with self._lock:
            try:
                conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scan_history
                        (timestamp, scan_type, target, scanned, infected, errors, duration)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    scan_type, target, scanned, infected, errors, duration
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"添加扫描记录失败: {e}")

    def get_records(self, limit=50):
        """
        获取最近的扫描记录
        :param limit: 最大返回条数
        :return: 记录列表（字典格式）
        """
        with self._lock:
            try:
                conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, timestamp, scan_type, target, scanned, infected, errors, duration
                    FROM scan_history
                    ORDER BY id DESC
                    LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                conn.close()
                return [dict(row) for row in rows]
            except Exception as e:
                logger.error(f"获取扫描记录失败: {e}")
                return []

    def get_stats(self):
        """
        获取扫描统计信息
        :return: 字典包含 total_scans, total_scanned, total_infected, total_errors
        """
        with self._lock:
            try:
                conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT
                        COUNT(*)              AS total_scans,
                        COALESCE(SUM(scanned), 0)  AS total_scanned,
                        COALESCE(SUM(infected), 0) AS total_infected,
                        COALESCE(SUM(errors), 0)   AS total_errors
                    FROM scan_history
                """)
                row = cursor.fetchone()
                conn.close()
                return {
                    "total_scans":   row[0] if row else 0,
                    "total_scanned": row[1] if row else 0,
                    "total_infected": row[2] if row else 0,
                    "total_errors":  row[3] if row else 0,
                }
            except Exception as e:
                logger.error(f"获取扫描统计失败: {e}")
                return {"total_scans": 0, "total_scanned": 0, "total_infected": 0, "total_errors": 0}

    def clear_records(self):
        """清空所有扫描记录"""
        with self._lock:
            try:
                conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_history")
                cursor.execute("VACUUM")
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"清空扫描记录失败: {e}")


# ══════════════════════════════════════════════
#  v6.0.0 新增：扫描白名单管理器
# ══════════════════════════════════════════════
class ExclusionManager:
    """
    扫描白名单管理器
    管理扫描时需要排除的文件/目录列表，存储为 JSON 格式
    """

    def __init__(self):
        """初始化白名单管理器"""
        self._file_path = USER_DATA_DIR / "exclusions.json"
        self._lock = threading.Lock()
        self._exclusions = []
        self.load()

    def load(self):
        """从 JSON 文件加载白名单"""
        with self._lock:
            try:
                if self._file_path.exists():
                    text = self._file_path.read_text(encoding="utf-8")
                    data = json.loads(text)
                    if isinstance(data, list):
                        self._exclusions = data
                    else:
                        self._exclusions = []
                else:
                    self._exclusions = []
            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"加载白名单失败: {e}")
                self._exclusions = []

    def save(self):
        """将白名单保存到 JSON 文件"""
        with self._lock:
            try:
                self._file_path.parent.mkdir(parents=True, exist_ok=True)
                content = json.dumps(self._exclusions, ensure_ascii=False, indent=2)
                self._file_path.write_text(content, encoding="utf-8")
            except Exception as e:
                logger.error(f"保存白名单失败: {e}")

    def add(self, path):
        """
        添加路径到白名单
        :param path: 要排除的文件或目录路径
        :return: (成功与否, 消息)
        """
        path = str(Path(path).resolve())
        with self._lock:
            if path in self._exclusions:
                return False, "该路径已在白名单中"
            self._exclusions.append(path)
        self.save()
        return True, f"已添加到白名单：{path}"

    def remove(self, path):
        """
        从白名单中移除路径
        :param path: 要移除的路径
        :return: (成功与否, 消息)
        """
        path = str(Path(path).resolve())
        with self._lock:
            if path not in self._exclusions:
                return False, "该路径不在白名单中"
            self._exclusions.remove(path)
        self.save()
        return True, f"已从白名单移除：{path}"

    def list_all(self):
        """
        获取所有白名单路径
        :return: 白名单路径列表
        """
        with self._lock:
            return list(self._exclusions)

    def is_excluded(self, path):
        """
        检查路径是否在白名单中
        :param path: 要检查的文件或目录路径
        :return: True 表示已排除，False 表示未排除
        """
        path = str(Path(path).resolve())
        # FIX-BUG-8: Windows 路径不区分大小写，统一使用 normcase 处理
        if IS_WIN:
            path = os.path.normcase(path)
        with self._lock:
            for excl in self._exclusions:
                excl_cmp = excl
                if IS_WIN:
                    excl_cmp = os.path.normcase(excl)
                # 如果白名单条目是目录，检查路径是否在其下
                if path.startswith(excl_cmp + os.sep) or path == excl_cmp:
                    return True
            return False


# ══════════════════════════════════════════════
#  v6.0.0 新增：定时扫描管理器
# ══════════════════════════════════════════════
class ScheduleManager:
    """
    定时扫描管理器
    管理定时扫描任务，支持每日/每周/每月间隔
    """

    def __init__(self):
        """初始化定时扫描管理器"""
        self._file_path = USER_DATA_DIR / "schedules.json"
        self._lock = threading.Lock()
        self._schedules = []
        self._next_id = 1
        self.load()

    def load(self):
        """从 JSON 文件加载定时任务"""
        with self._lock:
            try:
                if self._file_path.exists():
                    text = self._file_path.read_text(encoding="utf-8")
                    data = json.loads(text)
                    if isinstance(data, list):
                        self._schedules = data
                        # 计算下一个可用 ID
                        if self._schedules:
                            self._next_id = max(s.get("id", 0) for s in self._schedules) + 1
                        else:
                            self._next_id = 1
                    else:
                        self._schedules = []
                        self._next_id = 1
                else:
                    self._schedules = []
                    self._next_id = 1
            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"加载定时任务失败: {e}")
                self._schedules = []
                self._next_id = 1

    def save(self):
        """将定时任务保存到 JSON 文件"""
        with self._lock:
            try:
                self._file_path.parent.mkdir(parents=True, exist_ok=True)
                content = json.dumps(self._schedules, ensure_ascii=False, indent=2)
                self._file_path.write_text(content, encoding="utf-8")
            except Exception as e:
                logger.error(f"保存定时任务失败: {e}")

    def add_schedule(self, name, target, scan_type, interval_type, enabled=True):
        """
        添加定时扫描任务
        :param name: 任务名称
        :param target: 扫描目标路径
        :param scan_type: 扫描类型（"快速扫描", "全盘扫描", "自定义扫描"）
        :param interval_type: 间隔类型（"daily", "weekly", "monthly"）
        :param enabled: 是否启用
        :return: 新任务的 ID
        """
        with self._lock:
            try:
                schedule = {
                    "id":             self._next_id,
                    "name":           name,
                    "target":         target,
                    "scan_type":      scan_type,
                    "interval_type":  interval_type,
                    "enabled":        enabled,
                    "created_at":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "last_run":       None,
                }
                self._schedules.append(schedule)
                self._next_id += 1
                task_id = schedule["id"]
            except Exception:
                task_id = None
        self.save()
        return task_id

    def remove_schedule(self, schedule_id):
        """
        移除定时扫描任务
        :param schedule_id: 任务 ID
        :return: (成功与否, 消息)
        """
        with self._lock:
            original_len = len(self._schedules)
            self._schedules = [s for s in self._schedules if s.get("id") != schedule_id]
            if len(self._schedules) == original_len:
                return False, f"未找到 ID 为 {schedule_id} 的定时任务"
        self.save()
        return True, "定时任务已删除"

    def toggle_schedule(self, schedule_id):
        """
        切换定时任务的启用/禁用状态
        :param schedule_id: 任务 ID
        :return: (成功与否, 消息, 新状态)
        """
        with self._lock:
            for s in self._schedules:
                if s.get("id") == schedule_id:
                    s["enabled"] = not s.get("enabled", True)
                    new_state = s["enabled"]
                    self.save()
                    return True, f"定时任务已{'启用' if new_state else '禁用'}", new_state
            return False, f"未找到 ID 为 {schedule_id} 的定时任务", None

    def get_schedules(self):
        """
        获取所有定时任务
        :return: 定时任务列表
        """
        with self._lock:
            return list(self._schedules)

    def check_and_run(self, callback):
        """
        检查是否有到期的定时任务并执行
        :param callback: 回调函数，接收 (schedule_info) 参数
        :return: 是否执行了任务
        """
        now = datetime.now()
        ran = False
        schedules_to_run = []  # 收集所有需要执行的任务

        with self._lock:
            for s in self._schedules:
                if not s.get("enabled", True):
                    continue

                last_run_str = s.get("last_run")
                if last_run_str:
                    try:
                        last_run = datetime.strptime(last_run_str, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        last_run = None
                else:
                    last_run = None

                should_run = False
                interval = s.get("interval_type", "daily")

                if last_run is None:
                    # 从未运行过，立即执行
                    should_run = True
                elif interval == "daily":
                    # 每日：距上次运行超过 24 小时
                    if (now - last_run).total_seconds() >= 86400:
                        should_run = True
                elif interval == "weekly":
                    # 每周：距上次运行超过 7 天
                    if (now - last_run).total_seconds() >= 86400 * 7:
                        should_run = True
                elif interval == "monthly":
                    # 每月：距上次运行超过 30 天
                    if (now - last_run).total_seconds() >= 86400 * 30:
                        should_run = True

                if should_run:
                    s["last_run"] = now.strftime("%Y-%m-%d %H:%M:%S")
                    ran = True
                    # 在锁内只收集任务，锁外执行回调
                    schedules_to_run.append(dict(s))

        # 锁外保存和执行回调，避免死锁
        if ran:
            self.save()
            for schedule_copy in schedules_to_run:
                try:
                    callback(schedule_copy)
                except Exception as e:
                    logger.error(f"执行定时扫描回调失败: {e}")

        return ran


# ══════════════════════════════════════════════
#  v6.0.0 新增：Toast 通知系统
# ══════════════════════════════════════════════
class ToastNotification:
    """
    Toast 通知弹窗
    在屏幕右下角显示临时通知，支持自动消失和淡入淡出效果
    """

    # 图标与颜色映射
    _ICON_COLORS = {
        "info":    C["accent"],
        "success": C["green"],
        "warning": C["warn"],
        "error":   C["danger"],
    }

    # 图标符号
    _ICON_SYMBOLS = {
        "info":    "i",
        "success": "\u2713",   # 对勾
        "warning": "!",
        "error":   "\u2717",   # 叉号
    }

    def __init__(self, parent=None):
        """
        初始化 Toast 通知管理器
        :param parent: 父窗口（用于定位），默认为 None（使用屏幕定位）
        """
        self._parent = parent
        self._toast_window = None
        self._fade_timer = None
        self._close_timer = None
        self._current_alpha = 0.0
        self._fade_steps = 8          # 淡入/淡出总步数
        self._fade_interval = 30      # 每步间隔（毫秒）

    def show(self, title, message, duration=5000, icon_type="info"):
        """
        显示 Toast 通知
        :param title: 通知标题
        :param message: 通知内容
        :param duration: 显示时长（毫秒），默认 5000
        :param icon_type: 图标类型（"info", "success", "warning", "error"）
        """
        # 如果已有通知窗口，先关闭
        self._close_current()

        icon_color = self._ICON_COLORS.get(icon_type, C["accent"])
        icon_symbol = self._ICON_SYMBOLS.get(icon_type, "i")

        # 创建通知窗口
        self._toast_window = tw = tk.Toplevel(self._parent)
        tw.overrideredirect(True)
        tw.attributes("-topmost", True)

        # 尝试设置窗口透明度（仅 Windows/macOS 支持）
        try:
            tw.attributes("-alpha", 0.0)
        except Exception:
            pass

        tw.configure(bg=C["card"], highlightbackground=C["border"],
                     highlightthickness=1)

        # 主容器
        main_frame = tk.Frame(tw, bg=C["card"])
        main_frame.pack(fill="both", expand=True, padx=2, pady=2)

        # 左侧图标区域
        icon_canvas = tk.Canvas(main_frame, width=36, height=36,
                                bg=C["card"], highlightthickness=0)
        icon_canvas.pack(side="left", padx=(12, 8), pady=10)
        # 绘制圆形图标背景
        icon_canvas.create_oval(4, 4, 32, 32, fill=icon_color, outline="")
        icon_canvas.create_text(18, 18, text=icon_symbol,
                                font=(FONT_FAMILY_BOLD, 14, "bold"),
                                fill=C["white"])

        # 右侧文本区域
        text_frame = tk.Frame(main_frame, bg=C["card"])
        text_frame.pack(side="left", fill="both", expand=True, padx=(0, 12), pady=10)

        tk.Label(text_frame, text=title, bg=C["card"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 10, "bold"), anchor="w").pack(fill="x")
        tk.Label(text_frame, text=message, bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 9), anchor="w", wraplength=280,
                 justify="left").pack(fill="x", pady=(2, 0))

        # 关闭按钮
        close_btn = tk.Button(main_frame, text="\u2715", bg=C["card"],
                              fg=C["dim"], font=(FONT_FAMILY, 9),
                              relief="flat", bd=0, padx=4, pady=0,
                              cursor="hand2", activebackground=C["card"],
                              activeforeground=C["white"],
                              command=self._close_current)
        close_btn.pack(side="right", padx=(0, 4), pady=10)
        close_btn.bind("<Enter>", lambda e, b=close_btn: b.config(fg=C["white"]))
        close_btn.bind("<Leave>", lambda e, b=close_btn: b.config(fg=C["dim"]))

        # 计算窗口大小并定位到屏幕右下角
        tw.update_idletasks()
        w = tw.winfo_reqwidth()
        h = tw.winfo_reqheight()
        screen_w = tw.winfo_screenwidth()
        screen_h = tw.winfo_screenheight()
        x = screen_w - w - 20
        y = screen_h - h - 60
        tw.geometry(f"+{x}+{y}")

        # 启动淡入效果
        self._current_alpha = 0.0
        self._fade_in(0)

        # 设置自动关闭定时器
        self._close_timer = tw.after(duration, self._start_fade_out)

    def _fade_in(self, step):
        """淡入效果：逐步增加窗口透明度"""
        if self._toast_window is None or not self._toast_window.winfo_exists():
            return
        step += 1
        alpha = min(1.0, step / self._fade_steps)
        try:
            self._toast_window.attributes("-alpha", alpha)
        except Exception:
            pass
        if step < self._fade_steps:
            self._fade_timer = self._toast_window.after(
                self._fade_interval, self._fade_in, step)

    def _start_fade_out(self):
        """启动淡出效果"""
        if self._toast_window is None or not self._toast_window.winfo_exists():
            return
        self._fade_out(self._fade_steps)

    def _fade_out(self, step):
        """淡出效果：逐步降低窗口透明度"""
        if self._toast_window is None or not self._toast_window.winfo_exists():
            return
        step -= 1
        alpha = max(0.0, step / self._fade_steps)
        try:
            self._toast_window.attributes("-alpha", alpha)
        except Exception:
            pass
        if step > 0:
            self._fade_timer = self._toast_window.after(
                self._fade_interval, self._fade_out, step)
        else:
            self._close_current()

    def _close_current(self):
        """关闭当前通知窗口"""
        if self._fade_timer is not None:
            try:
                if self._toast_window and self._toast_window.winfo_exists():
                    self._toast_window.after_cancel(self._fade_timer)
            except Exception:
                pass
            self._fade_timer = None
        if self._close_timer is not None:
            try:
                if self._toast_window and self._toast_window.winfo_exists():
                    self._toast_window.after_cancel(self._close_timer)
            except Exception:
                pass
            self._close_timer = None
        if self._toast_window is not None:
            try:
                if self._toast_window.winfo_exists():
                    self._toast_window.destroy()
            except Exception:
                pass
            self._toast_window = None


# ══════════════════════════════════════════════
#  v6.0.0 新增：实时文件监控
# ══════════════════════════════════════════════
class FileMonitor:
    """
    实时文件监控器
    优先使用 watchdog 库进行文件系统事件监控，
    如果 watchdog 不可用则退化为轮询方式
    """

    def __init__(self, backend, log_cb=None):
        """
        初始化文件监控器
        :param backend: ClamAVBackend 实例，用于执行扫描
        :param log_cb: 日志回调函数
        """
        self._backend = backend
        self._log = log_cb or (lambda msg, tag="": None)
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()
        self._watch_paths = []
        self._callback = None
        self._poll_interval = 5.0       # 轮询间隔（秒）
        self._scan_queue = []           # 待扫描文件队列
        self._scan_lock = threading.Lock()
        self._scanned_files = set()     # 已扫描文件缓存（避免重复扫描）
        self._use_watchdog = False
        self._watchdog_observer = None

        # 尝试导入 watchdog
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            self._Observer = Observer
            self._FileSystemEventHandler = FileSystemEventHandler
            self._use_watchdog = True
            self._log("已加载 watchdog 库，将使用原生文件系统监控", "success")
        except ImportError:
            self._log("watchdog 库不可用，将使用轮询方式监控文件变化", "warn")
            self._use_watchdog = False

    def start(self, paths, callback):
        """
        启动文件监控
        :param paths: 要监控的路径列表
        :param callback: 发现新文件时的回调函数，接收 (file_path) 参数
        """
        if self._running:
            self.stop()

        self._watch_paths = [str(Path(p).resolve()) for p in paths]
        self._callback = callback
        self._stop_event.clear()
        self._running = True
        self._scanned_files.clear()

        # 确保监控路径存在
        valid_paths = []
        for p in self._watch_paths:
            if os.path.exists(p):
                valid_paths.append(p)
            else:
                self._log(f"监控路径不存在，已跳过：{p}", "warn")

        if not valid_paths:
            self._log("没有有效的监控路径，文件监控未启动", "warn")
            self._running = False
            return

        self._watch_paths = valid_paths

        if self._use_watchdog:
            self._start_watchdog()
        else:
            self._start_polling()

        self._log(f"文件监控已启动，监控 {len(self._watch_paths)} 个路径", "success")

    def _start_watchdog(self):
        """使用 watchdog 启动文件系统监控"""
        class _Handler(self._FileSystemEventHandler):
            def __init__(self, monitor):
                super().__init__()
                self._monitor = monitor

            def on_created(self, event):
                if not event.is_directory:
                    self._monitor._enqueue_scan(event.src_path)

            def on_modified(self, event):
                if not event.is_directory:
                    self._monitor._enqueue_scan(event.src_path)

        try:
            self._watchdog_observer = self._Observer()
            handler = _Handler(self)
            for path in self._watch_paths:
                self._watchdog_observer.schedule(handler, path, recursive=True)
            self._watchdog_observer.start()

            # 启动扫描处理线程
            self._thread = threading.Thread(target=self._process_scan_queue,
                                            daemon=True)
            self._thread.start()
        except Exception as e:
            self._log(f"watchdog 启动失败，回退到轮询模式：{e}", "warn")
            self._use_watchdog = False
            self._start_polling()

    def _start_polling(self):
        """使用轮询方式启动文件监控"""
        # 首先记录当前文件快照
        self._file_snapshot = {}
        for path in self._watch_paths:
            self._walk_and_record(path)

        self._thread = threading.Thread(target=self._poll_scan, daemon=True)
        self._thread.start()

    def _walk_and_record(self, path):
        """遍历目录并记录所有文件的修改时间"""
        try:
            if os.path.isfile(path):
                try:
                    mtime = os.path.getmtime(path)
                    self._file_snapshot[path] = mtime
                except OSError:
                    pass
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    if self._stop_event.is_set():
                        return
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            mtime = os.path.getmtime(fpath)
                            self._file_snapshot[fpath] = mtime
                        except OSError:
                            pass
        except Exception as e:
            self._log(f"遍历目录失败：{e}", "warn")

    def _poll_scan(self):
        """轮询扫描：定期检查文件变化"""
        while not self._stop_event.is_set():
            self._stop_event.wait(self._poll_interval)
            if self._stop_event.is_set():
                break

            for path in self._watch_paths:
                if self._stop_event.is_set():
                    break
                self._check_changes(path)

            # 处理扫描队列
            self._process_pending_scans()

    def _check_changes(self, path):
        """检查目录中的文件变化"""
        try:
            if os.path.isfile(path):
                try:
                    mtime = os.path.getmtime(path)
                    if path not in self._file_snapshot or \
                       self._file_snapshot[path] != mtime:
                        self._enqueue_scan(path)
                        self._file_snapshot[path] = mtime
                except OSError:
                    pass
            elif os.path.isdir(path):
                current_files = set()
                for root, dirs, files in os.walk(path):
                    if self._stop_event.is_set():
                        return
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        current_files.add(fpath)
                        try:
                            mtime = os.path.getmtime(fpath)
                            if fpath not in self._file_snapshot or \
                               self._file_snapshot[fpath] != mtime:
                                self._enqueue_scan(fpath)
                                self._file_snapshot[fpath] = mtime
                        except OSError:
                            pass

                # 清理已删除文件的记录
                # FIX-BUG-12: 修复路径前缀匹配缺边界问题
                removed = set(self._file_snapshot.keys()) - current_files
                for fpath in removed:
                    if fpath == path or fpath.startswith(path + os.sep):
                        del self._file_snapshot[fpath]

        except Exception as e:
            self._log(f"检查文件变化失败：{e}", "warn")

    def _enqueue_scan(self, file_path):
        """将文件加入扫描队列"""
        with self._scan_lock:
            # 避免重复扫描同一文件（5分钟内）
            file_key = file_path
            if file_key in self._scanned_files:
                return
            self._scan_queue.append(file_path)
            self._scanned_files.add(file_key)

    def _process_scan_queue(self):
        """watchdog 模式下的扫描队列处理线程"""
        while not self._stop_event.is_set():
            self._stop_event.wait(2.0)
            if self._stop_event.is_set():
                break
            self._process_pending_scans()

    def _process_pending_scans(self):
        """处理待扫描文件队列"""
        with self._scan_lock:
            if not self._scan_queue:
                return
            # 取出队列中的文件（最多一次处理 10 个）
            batch = self._scan_queue[:10]
            self._scan_queue = self._scan_queue[10:]

        for fpath in batch:
            if self._stop_event.is_set():
                break
            self.scan_file(fpath)

    def scan_file(self, path):
        """
        扫描单个文件
        :param path: 文件路径
        """
        try:
            if not os.path.isfile(path):
                return

            # 跳过过大的文件（> 100MB）
            try:
                size = os.path.getsize(path)
                if size > 100 * 1024 * 1024:
                    self._log(f"文件过大，跳过实时扫描：{_truncate_path(path)}", "warn")
                    return
            except OSError:
                return

            self._log(f"实时扫描：{_truncate_path(path)}", "info")

            # 实际执行扫描
            try:
                result = self._backend.scan_file(path)
                if result and result.get("infected"):
                    threat_name = result.get("virus", "未知威胁")
                    if self._callback:
                        try:
                            self._callback(path, threat_name)
                        except Exception as e:
                            self._log(f"实时扫描回调失败：{e}", "warn")
            except Exception as e:
                self._log(f"实时扫描执行失败：{e}", "warn")

        except Exception as e:
            self._log(f"实时扫描异常：{e}", "warn")

    def stop(self):
        """停止文件监控"""
        self._stop_event.set()
        self._running = False

        # 停止 watchdog
        if self._watchdog_observer is not None:
            try:
                self._watchdog_observer.stop()
                self._watchdog_observer.join(timeout=5)
            except Exception:
                pass
            self._watchdog_observer = None

        # 等待线程结束
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

        # 清理
        with self._scan_lock:
            self._scan_queue.clear()
        self._scanned_files.clear()
        self._log("文件监控已停止", "info")


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
            # FIX-BUG-17: 重命名失败时更新 entry["qfile"] 指向实际落盘的路径
            try:
                backup_path = src.with_name(src.name + ".ld_backup")
                tmp_file.rename(backup_path)
                self.log(f"临时文件已重命名为 {backup_path}", "warn")
                entry["qfile"] = str(backup_path)  # 更新 qfile 指向实际路径
                entry["note"] = f"重命名失败，文件已恢复到 {backup_path}"
            except Exception as rename_err:
                self.log(f"恢复到原始名失败: {rename_err}", "danger")
                try:
                    incomplete = tmp_file.with_suffix('.incomplete' + QUAR_SUFFIX)
                    tmp_file.rename(incomplete)
                    entry["qfile"] = str(incomplete)  # 更新 qfile 指向实际路径
                    entry["note"] = f"重命名失败，文件已置为 .incomplete"
                except Exception as final_err:
                    self.log(f"无法处理临时文件，残留: {tmp_file}, 错误: {final_err}", "danger")
                    entry["qfile"] = str(tmp_file)  # 更新 qfile 指向实际路径
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
        # FIX-BUG-18: 使用 _read_meta 以利用损坏保护（从备份恢复）
        meta = self._read_meta()
        return len(meta)

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
        """检测系统级自启是否实际注册（FIX: Windows 校验路径是否指向当前 exe）"""
        try:
            if self._pf == "Windows":
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    try:
                        value, _ = winreg.QueryValueEx(key, self.APP_NAME)
                        if not value:
                            return False
                        expected = sys.executable.lower().replace('"', '')
                        actual = value.lower().replace('"', '').strip()
                        if actual.startswith(expected):
                            return True
                        return False
                    except FileNotFoundError:
                        return False
            elif self._pf == "Darwin":
                plist_path = Path.home() / "Library/LaunchAgents/com.liangdun.security.plist"
                return plist_path.exists()
            else:
                desktop_path = Path.home() / ".config/autostart/liangdun.desktop"
                return desktop_path.exists()
        except ImportError:
            return False
        except (FileNotFoundError, OSError):
            return False
        return False

    def enable(self) -> tuple:
        """注册系统级开机自启（FIX: 路径加引号，追加 --silent，修复 macOS plist XML）"""
        try:
            if getattr(sys, 'frozen', False):
                exe_path = f'"{sys.executable}" --silent'
            else:
                exe_path = f'"{sys.executable}" "{Path(__file__).resolve()}" --silent'

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
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.liangdun.security</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{Path(__file__).resolve()}</string>
        <string>--silent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>'''
                plist_path.write_text(plist_content, encoding="utf-8")
                # FIX-BUG-11: 使用 subprocess.run 替代 os.system，避免命令注入
                subprocess.run(["launchctl", "load", str(plist_path)],
                               capture_output=True, check=False)
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
StartupNotify=false
Hidden=false
Terminal=false
"""
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
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, self.APP_NAME)
                    return True, "已移除 Windows 启动项"
                except FileNotFoundError:
                    # 本来就不存在，也算成功
                    return True, "Windows 启动项未注册"

            elif self._pf == "Darwin":
                plist_path = Path.home() / "Library/LaunchAgents/com.liangdun.security.plist"
                if plist_path.exists():
                    # FIX-BUG-11: 使用 subprocess.run 替代 os.system，避免命令注入
                    subprocess.run(["launchctl", "unload", str(plist_path)],
                                   capture_output=True, check=False)
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
        """FIX: 仅在配置文件不存在时生成，避免覆盖用户手动修改；使用 Windows 短路径"""
        CONF_DIR.mkdir(parents=True, exist_ok=True)
        DB_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)

        generated = False

        if not CLAMD_CONF.exists():
            # 预先创建日志文件，确保能获取 8.3 短路径
            (LOG_DIR / 'clamd.log').touch(exist_ok=True)
            (LOG_DIR / 'clamd.pid').touch(exist_ok=True)
            clamd_content = f"""\
# 量盾安全 {APP_VERSION} (c) 2026 - clamd 自动生成配置
LogFile {_get_short_path(LOG_DIR / 'clamd.log')}
LogTime yes
LogVerbose no
PidFile {_get_short_path(LOG_DIR / 'clamd.pid')}
DatabaseDirectory {_get_short_path(DB_DIR)}
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
            generated = True

        if not FRESH_CONF.exists():
            (LOG_DIR / 'freshclam.log').touch(exist_ok=True)
            fresh_content = f"""\
# 量盾安全 {APP_VERSION} (c) 2026 - freshclam 自动生成配置
UpdateLogFile {_get_short_path(LOG_DIR / 'freshclam.log')}
LogVerbose no
LogSyslog no
LogTime yes
DatabaseDirectory {_get_short_path(DB_DIR)}
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
            generated = True

        if generated:
            self.log("配置文件已生成", "success")

    def check_database(self):
        if not DB_DIR.exists():
            return False
        for f in CVD_FILES:
            if (DB_DIR / f).exists():
                return True
        # 检查 MD5 签名数据库
        if MD5_ENABLED and (DB_DIR / MD5_HDB_FILE).exists():
            return True
        return False

    def check_yara_rules(self):
        """检查 YARA 规则文件是否存在"""
        yara_path = DB_DIR / YARA_NDB_FILE
        if yara_path.exists():
            try:
                size = yara_path.stat().st_size
                lines = 0
                with open(yara_path, 'r', encoding='utf-8') as f:
                    for _ in f:
                        lines += 1
                return True, lines, size
            except Exception as e:
                return False, 0, 0
        return False, 0, 0

    def check_md5_database(self):
        """检查 MD5 签名数据库是否存在并返回统计信息"""
        md5_path = DB_DIR / MD5_HDB_FILE
        if md5_path.exists():
            try:
                size = md5_path.stat().st_size
                lines = 0
                with open(md5_path, 'r', encoding='utf-8') as f:
                    for _ in f:
                        lines += 1
                return True, lines, size
            except Exception as e:
                return False, 0, 0
        return False, 0, 0

    def get_db_info(self):
        info = []
        for f in CVD_FILES:
            p = DB_DIR / f
            if p.exists():
                size = p.stat().st_size / (1024 * 1024)
                mtime = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                info.append({"name": f, "size": f"{size:.1f} MB", "date": mtime, "ok": True})
        # 添加 YARA 规则信息
        if YARA_ENABLED:
            yara_ok, yara_lines, yara_size = self.check_yara_rules() if YARA_ENABLED else (False, 0, 0)
            if yara_ok:
                info.append({
                    "name": YARA_NDB_FILE,
                    "size": f"{yara_size/1024:.1f} KB",
                    "date": f"{yara_lines} 条签名",
                    "ok": True
                })
            else:
                info.append({
                    "name": YARA_NDB_FILE,
                    "size": "—",
                    "date": "未安装",
                    "ok": False
                })
        # 添加 MD5 签名数据库信息
        if MD5_ENABLED:
            md5_ok, md5_lines, md5_size = self.check_md5_database()
            if md5_ok:
                info.append({
                    "name": MD5_HDB_FILE,
                    "size": f"{md5_size/1024/1024:.1f} MB",
                    "date": f"{md5_lines:,} 条签名",
                    "ok": True
                })
            else:
                info.append({
                    "name": MD5_HDB_FILE,
                    "size": "—",
                    "date": "未安装",
                    "ok": False
                })
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
                cmd = [str(FRESHCLAM), f"--config-file={_get_short_path(FRESH_CONF)}",
                       f"--datadir={_get_short_path(DB_DIR)}", "--stdout"]

                kwargs = {}
                if IS_WIN:
                    kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

                self._update_proc = proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, env=env, **kwargs
                )
                pct = 20
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        self.log(f"  {line}", "dim")
                        if "%" in line:
                            # FIX-BUG-22: 使用 findall 取最后一个百分比，避免进度跳动
                            matches = re.findall(r'(\d+)%', line)
                            if matches:
                                pct = 20 + int(matches[-1]) * 0.75
                        progress_cb(min(int(pct), 95))
                # FIX-BUG-21: 增加超时时间到 600 秒（10分钟），首次下载 main.cvd 可能较慢
                try:
                    proc.wait(timeout=600)
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
                self._scan_proc.wait(timeout=5)
            except Exception:
                try:
                    self._scan_proc.kill()
                    self._scan_proc.wait(timeout=3)
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
    # ── v6.0.0: 新增 exclusions 参数支持排除列表 ─────────────
    def scan(self, target, progress_cb, result_cb, log_file_cb=None, exclusions=None):
        def run():
            if not self.check_database():
                result_cb(None, "病毒库未安装，请先更新病毒库")
                return

            # FIX: 统一使用 _normalize_and_verify_path，保留长路径前缀
            resolved_target, path_ok = self._normalize_and_verify_path(target)
            if not path_ok:
                result_cb(None, f"扫描目标不存在或无效：{target}")
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
                # FIX: 合并数据库参数为单 -d <DB_DIR>
                cmd = [str(CLAMSCAN), "-r", "--verbose", "--stdout", f"--database={_get_short_path(DB_DIR)}"]

                # v6.0.0: 添加排除列表支持
                # FIX-BUG-7: 使用 re.escape 处理路径中的特殊字符
                if exclusions:
                    for excl_path in exclusions:
                        excl_resolved = str(Path(excl_path).resolve())
                        # clamscan 的 --exclude-dir 和 --exclude 接受 POSIX 正则表达式
                        # 需要对路径中的特殊字符进行转义，并添加 ^ 锚定
                        excl_escaped = re.escape(excl_resolved)
                        if os.path.isdir(excl_resolved):
                            cmd.append(f"--exclude-dir=^{excl_escaped}")
                        else:
                            cmd.append(f"--exclude=^{excl_escaped}")
                    self.log(f"已加载 {len(exclusions)} 条排除规则", "info")

                # 记录 YARA 规则加载状态（不再重复传 -d）
                if YARA_ENABLED:
                    yara_path = DB_DIR / YARA_NDB_FILE
                    if yara_path.exists():
                        self.log(f"已加载 YARA 规则: {YARA_NDB_FILE}", "info")
                    else:
                        self.log("YARA 规则文件不存在，跳过加载", "warn")

                # 记录 MD5 签名数据库加载状态
                if MD5_ENABLED:
                    md5_path = DB_DIR / MD5_HDB_FILE
                    if md5_path.exists():
                        md5_ok, md5_lines, md5_size = self.check_md5_database()
                        self.log(f"已加载 MD5 签名库: {MD5_HDB_FILE} ({md5_lines:,} 条签名)", "info")
                    else:
                        self.log("MD5 签名库文件不存在，跳过加载", "warn")

                if log_file_cb:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    lf = LOG_DIR / f"scan_{ts}.log"
                    cmd += [f"--log={_get_short_path(lf)}"]
                    log_file_cb(str(lf))

                cmd.append(resolved_target)

                kwargs = {}
                if IS_WIN:
                    kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

                self._scan_proc = proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=False, **kwargs
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

        # FIX: 支持 --silent / --autostart 启动参数
        self._silent_mode = "--silent" in sys.argv or "--autostart" in sys.argv

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

        # 【FIX-USERDIR-1】设置文件迁移到用户数据目录
        self._settings_file   = SETTINGS_FILE
        self._virus_action    = tk.StringVar(value="quarantine")
        self._autostart       = tk.BooleanVar(value=False)

        # FIX-AUTOSTART: 初始化自启动管理器（必须在 _load_settings 之前）
        self._autostart_mgr = AutostartManager()

        # FIX-SETTINGS-UI: 设置变更脏标记
        self._settings_dirty = False

        # FIX-BUG-2: 先加载设置数据，获取 realtime_protection 值
        default_settings = {
            "virus_action": "quarantine",
            "autostart": False,
            "realtime_protection": False,
            "eula_accepted": False,
            "eula_accepted_at": None,
        }
        try:
            if self._settings_file.exists():
                loaded = json.loads(self._settings_file.read_text(encoding="utf-8"))
                self._settings_data = {**default_settings, **loaded}
            else:
                self._settings_data = dict(default_settings)
        except Exception:
            self._settings_data = dict(default_settings)

        # FIX-BUG-2: 提前创建 _realtime_var，使用设置中的值
        self._realtime_var = tk.BooleanVar(
            value=self._settings_data.get("realtime_protection", False))

        # 加载设置（内部会同步真实自启状态）
        self._load_settings()

        self.backend    = ClamAVBackend(self._log)
        self.quar_mgr   = QuarantineManager()
        self.quar_mgr.log = self._log

        # v6.0.0: 初始化新增管理器
        self._scan_history  = ScanHistory()
        self._exclusion_mgr = ExclusionManager()
        self._schedule_mgr  = ScheduleManager()
        self._toast         = ToastNotification(parent=self)
        self._file_monitor  = FileMonitor(self.backend, self._log)

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

        # v6.0.0: 扫描计时器
        self._scan_start_time = None

        self._configure_styles()

        # UI #17: 窗口关闭确认
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Map>", self._on_map)

        self._build_ui()

        # FIX: 静默启动时最小化到任务栏（而非 withdrawn 导致丢失）
        if self._silent_mode:
            self.after(100, self.iconify)

        # LEGAL-1: EULA 强制确认（必须在 UI 构建完成后调用）
        self._check_eula()

        # FIX: 移除此处 after(300)，避免 EULA 嵌套循环时后台提前初始化
        # self.after(300, self._init_check)

        # UI #16: 键盘快捷键
        self.bind("<Control-s>", lambda e: self._start_scan())
        self.bind("<Control-q>", lambda e: self._on_close())
        self.bind("<Escape>",    lambda e: self._stop_scan() if self._scanning else None)

        # v6.0.0: 注册退出清理
        atexit.register(self._on_atexit)

    def _on_atexit(self):
        """程序退出时的清理工作"""
        try:
            self._file_monitor.stop()
        except Exception:
            pass

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
        # v6.0.0: 停止文件监控
        try:
            self._file_monitor.stop()
        except Exception:
            pass

        # FIX-SETTINGS-UI: 关闭前检查未保存设置
        if self._settings_dirty:
            if not messagebox.askyesno("未保存的更改",
                    "您在「系统设置」中有未保存的更改，退出将丢失这些更改。\n"
                    "确定要退出吗？"):
                return
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
            "realtime_protection": False,
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

        # FIX-AUTOSTART-2: 启动时检测外部自启状态，但不再覆盖用户设置文件
        # 避免 is_enabled() 误检或权限问题导致"刷新一下就没了"
        real_autostart = self._autostart_mgr.is_enabled()
        user_autostart = self._settings_data.get("autostart", False)
        if user_autostart != real_autostart:
            self._log(
                f"开机自启外部状态({'启用' if real_autostart else '禁用'})"
                f"与设置({'启用' if user_autostart else '禁用'})不一致，"
                f"保留用户设置", "warn"
            )

        self._virus_action.set(self._settings_data.get("virus_action", "quarantine"))
        self._autostart.set(self._settings_data.get("autostart", False))

        # 加载实时防护状态并同步首页卡片
        # 注意：_realtime_var 在 _build_settings() 中才创建，此处需守卫
        realtime_enabled = self._settings_data.get("realtime_protection", False)
        if hasattr(self, '_realtime_var'):
            self._realtime_var.set(realtime_enabled)
        self._sync_home_rt_card(realtime_enabled)

        # FIX-SETTINGS-UI: 加载设置后清除脏标记与提示
        self._settings_dirty = False
        try:
            if hasattr(self, '_settings_hint_lbl') and self._settings_hint_lbl.winfo_exists():
                self._settings_hint_lbl.config(text="")
        except Exception:
            pass

    def _sync_home_rt_card(self, enabled=None):
        """同步首页实时防护卡片显示状态"""
        if enabled is None:
            enabled = self._realtime_var.get()
        try:
            if hasattr(self, '_home_rt_val') and self._home_rt_val.winfo_exists():
                if enabled:
                    self._home_rt_val.config(text="开启", fg=C["green"])
                else:
                    self._home_rt_val.config(text="关闭", fg=C["warn"])
        except Exception:
            pass

    # ══════════════════════════════════════════
    #  【FIX-SETTINGS-1/2/3】保存设置：返回状态，异常不再静默，修复原子写
    # ══════════════════════════════════════════
    def _save_settings(self) -> bool:
        """原子写入设置文件，返回是否成功"""
        try:
            new_data = {
                "virus_action": self._virus_action.get(),
                "autostart": self._autostart.get(),
                "realtime_protection": self._realtime_var.get(),
                "eula_accepted": self._settings_data.get("eula_accepted", False),
                "eula_accepted_at": self._settings_data.get("eula_accepted_at", None),
            }
            # FIX-SETTINGS-3: 确保目录存在（运行期间可能被外部删除）
            self._settings_file.parent.mkdir(parents=True, exist_ok=True)

            tmp = self._settings_file.with_suffix('.tmp')
            tmp.write_text(
                json.dumps(new_data, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )

            # FIX-SETTINGS-2: Windows 下如果 settings.json 被占用，replace() 会 PermissionError
            try:
                tmp.replace(self._settings_file)
            except PermissionError:
                if self._settings_file.exists():
                    self._settings_file.unlink()
                tmp.rename(self._settings_file)

            self._settings_data = new_data
            return True
        except Exception as e:
            self._log(f"设置保存失败: {e}", "danger")
            return False

    # ══════════════════════════════════════════
    #  EULA 强制确认与留痕
    # ══════════════════════════════════════════
    def _check_eula(self):
        if self._settings_data.get("eula_accepted", False):
            # FIX: EULA 已同意后再触发初始化，避免嵌套循环时后台提前运行
            self.after(300, self._init_check)
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
                "version": APP_VERSION
            })
            self._log(f"用户已同意 EULA ({ts})", "success")
            eula_win.destroy()
            # FIX: 同意后再触发初始化
            self.after(300, self._init_check)

        def _decline():
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            write_audit({
                "event": "eula_declined",
                "action": "拒绝",
                "timestamp": ts,
                "version": APP_VERSION
            })
            self._log(f"用户已拒绝 EULA ({ts})，程序即将退出", "danger")
            eula_win.destroy()
            # FIX-BUG-25: 只调用 destroy()，让 mainloop 正常退出
            # 不再调用 sys.exit(0) 避免在 wait_window 嵌套循环中抛异常
            self.destroy()

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
        # FIX: withdrawn 会导致任务栏按钮消失且无法恢复，改为 iconify
        self.iconify()

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
    #  UI 构建 (已删除重复定义，使用后定义版本)
    # ══════════════════════════════════════════

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

        tk.Label(parent, text="量盾安全", bg=C["panel"],
                 fg=C["white"], font=(FONT_FAMILY_BOLD, 16, "bold")).pack()
        tk.Label(parent, text="专业病毒防护", bg=C["panel"],
                 fg=C["dim"], font=(FONT_FAMILY, 10)).pack(pady=(3, 24))
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=24)

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

    def _sync_autostart_state(self):
        """检测外部自启状态，但不再自动覆盖 UI 设置（修复刷新消失问题）"""
        real = self._autostart_mgr.is_enabled()
        current = self._autostart.get()
        if real != current:
            self._log(
                f"检测到开机自启外部状态({'启用' if real else '禁用'})"
                f"与 UI({'启用' if current else '禁用'})不一致，"
                f"保留当前设置", "info"
            )

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

    def _progress_bar(self, parent, style="ld.Horizontal.TProgressbar"):
        """创建统一风格进度条"""
        pb = ttk.Progressbar(parent, style=style, mode="determinate", maximum=100)
        pb.pack(fill="x", pady=(9, 0))
        return pb

    def _append_log(self, text_widget, msg, tag=None):
        """向日志文本框追加内容，带行数限制和标签颜色"""
        text_widget.config(state="normal")
        # 配置标签颜色
        if tag:
            try:
                existing_fg = text_widget.tag_cget(tag, "foreground")
            except tk.TclError:
                existing_fg = ""
            if not existing_fg:
                tag_colors = {
                    "info": C["text"],
                    "success": C["green"],
                    "warn": C["warn"],
                    "warning": C["warn"],
                    "error": C["danger"],
                    "danger": C["danger"],
                    "dim": C["dim"],
                }
                if tag in tag_colors:
                    text_widget.tag_config(tag, foreground=tag_colors[tag])
        # 插入带标签的内容
        if tag:
            text_widget.insert("end", msg + "\n", tag)
        else:
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
                self._append_log(log_widget, f"[{ts}] {msg}", tag)

    # ═══════════════════════════════════════════════════════════════
    #  v6.0.0 新增：威胁详情弹窗
    # ═══════════════════════════════════════════════════════════════
    def _show_threat_detail(self, threat_info):
        """
        显示威胁详情弹窗
        :param threat_info: 威胁信息字典，包含以下键：
            - path: 文件完整路径
            - display_path: 显示用路径
            - virus: 威胁/病毒名称
            - time: 发现时间（可选）
        """
        file_path = threat_info.get("path", threat_info.get("display_path", "未知"))
        display_path = threat_info.get("display_path", file_path)
        virus_name = threat_info.get("virus", "未知威胁")
        found_time = threat_info.get("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # 创建弹窗
        detail_win = tk.Toplevel(self)
        detail_win.title("威胁详情")
        detail_win.geometry("520x480")
        detail_win.resizable(False, False)
        detail_win.transient(self)
        detail_win.grab_set()
        detail_win.configure(bg=C["bg"])
        detail_win.protocol("WM_DELETE_WINDOW", lambda: detail_win.destroy())

        # 标题栏
        title_frame = tk.Frame(detail_win, bg=C["danger_bg"], height=60)
        title_frame.pack(fill="x")
        title_frame.pack_propagate(False)

        tk.Label(title_frame, text="⚠  发现安全威胁",
                 bg=C["danger_bg"], fg=C["danger"],
                 font=(FONT_FAMILY_BOLD, 14, "bold")).pack(side="left", padx=20, pady=15)

        # 内容区域
        content = tk.Frame(detail_win, bg=C["bg"])
        content.pack(fill="both", expand=True, padx=24, pady=20)

        # 使用 Canvas 绘制圆角卡片风格的详情区域
        detail_canvas = tk.Canvas(content, bg=C["bg"], highlightthickness=0)
        detail_canvas.pack(fill="both", expand=True)

        # 信息卡片 - 文件路径
        card_y = 10
        _rounded_rect(detail_canvas, 10, card_y, 500, card_y + 80, 8,
                      fill=C["card"], outline=C["border"], width=1)
        tk.Label(content, text="文件路径", bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).place(x=24, y=card_y + 8)
        path_label = tk.Label(content, text=display_path, bg=C["card"], fg=C["text"],
                              font=(FONT_MONO, 10), anchor="w", wraplength=460,
                              justify="left")
        path_label.place(x=24, y=card_y + 28, width=464, height=44)

        # 信息卡片 - 威胁类型
        card_y = 100
        _rounded_rect(detail_canvas, 10, card_y, 500, card_y + 70, 8,
                      fill=C["card"], outline=C["border"], width=1)
        tk.Label(content, text="威胁类型", bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).place(x=24, y=card_y + 8)
        tk.Label(content, text=virus_name, bg=C["card"], fg=C["danger"],
                 font=(FONT_FAMILY_BOLD, 12, "bold"), anchor="w").place(
            x=24, y=card_y + 30, width=464)

        # 信息卡片 - 发现时间
        card_y = 180
        _rounded_rect(detail_canvas, 10, card_y, 500, card_y + 70, 8,
                      fill=C["card"], outline=C["border"], width=1)
        tk.Label(content, text="发现时间", bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).place(x=24, y=card_y + 8)
        tk.Label(content, text=found_time, bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 11), anchor="w").place(
            x=24, y=card_y + 30, width=464)

        # 建议操作区域
        card_y = 270
        _rounded_rect(detail_canvas, 10, card_y, 500, card_y + 60, 8,
                      fill=C["warn_bg"], outline=C["border"], width=1)
        tk.Label(content, text="建议操作", bg=C["warn_bg"], fg=C["warn"],
                 font=(FONT_FAMILY_BOLD, 10, "bold")).place(x=24, y=card_y + 8)
        tk.Label(content, text="建议立即隔离此文件以防止潜在的安全风险",
                 bg=C["warn_bg"], fg=C["text"],
                 font=(FONT_FAMILY, 9), anchor="w").place(
            x=24, y=card_y + 32, width=464)

        # 操作按钮区域
        btn_frame = tk.Frame(detail_win, bg=C["bg"])
        btn_frame.pack(fill="x", padx=24, pady=(0, 20))

        def _quarantine():
            """隔离威胁文件"""
            ok, msg = self.quar_mgr.quarantine_file(file_path, virus_name)
            if ok:
                self._toast.show("隔离成功", f"已隔离：{display_path}",
                                 icon_type="success")
                write_audit({
                    "event": "threat_quarantined",
                    "file": file_path,
                    "threat": virus_name,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "version": APP_VERSION
                })
            else:
                self._toast.show("隔离失败", msg, icon_type="error")
            detail_win.destroy()

        def _delete():
            """删除威胁文件"""
            if messagebox.askyesno("确认删除",
                    f"确定要永久删除此文件吗？\n\n{display_path}\n\n"
                    "此操作不可撤销！"):
                try:
                    p = Path(file_path)
                    if p.exists():
                        self.quar_mgr.secure_delete_with_retry(p)
                        self._toast.show("删除成功",
                                         f"已删除：{display_path}",
                                         icon_type="success")
                        write_audit({
                            "event": "threat_deleted",
                            "file": file_path,
                            "threat": virus_name,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "version": APP_VERSION
                        })
                    else:
                        self._toast.show("删除失败", "文件不存在",
                                         icon_type="error")
                except Exception as e:
                    self._toast.show("删除失败", str(e), icon_type="error")
                detail_win.destroy()

        def _ignore():
            """忽略此威胁"""
            self._toast.show("已忽略", f"已忽略威胁：{virus_name}",
                             icon_type="warning")
            write_audit({
                "event": "threat_ignored",
                "file": file_path,
                "threat": virus_name,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "version": APP_VERSION
            })
            detail_win.destroy()

        # 按钮排列：隔离（推荐）、删除、忽略
        self._btn(btn_frame, "隔离文件（推荐）", _quarantine,
                  color=C["danger"]).pack(side="left", padx=(0, 8))
        self._btn(btn_frame, "永久删除", _delete,
                  color=C["warn"]).pack(side="left", padx=(0, 8))
        self._btn(btn_frame, "忽略", _ignore,
                  color=C["dim"]).pack(side="left")

        # 居中于主窗口
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 520) // 2
        y = self.winfo_y() + (self.winfo_height() - 480) // 2
        detail_win.geometry(f"+{max(0, x)}+{max(0, y)}")

    # FIX-BUG-3: 新增多威胁列表弹窗，避免多个模态窗口堆叠
    def _show_threats_list(self, threats):
        """
        显示多威胁列表弹窗（单弹窗展示所有威胁）
        :param threats: 威胁信息列表
        """
        if not threats:
            return

        # 创建弹窗
        threats_win = tk.Toplevel(self)
        threats_win.title("发现安全威胁")
        threats_win.geometry("560x500")
        threats_win.resizable(True, True)
        threats_win.transient(self)
        threats_win.grab_set()
        threats_win.configure(bg=C["bg"])

        # 标题栏
        title_frame = tk.Frame(threats_win, bg=C["danger_bg"], height=60)
        title_frame.pack(fill="x")
        title_frame.pack_propagate(False)

        tk.Label(title_frame, text=f"⚠  发现 {len(threats)} 个安全威胁",
                 bg=C["danger_bg"], fg=C["danger"],
                 font=(FONT_FAMILY_BOLD, 14, "bold")).pack(side="left", padx=20, pady=15)

        # 内容区域（可滚动）
        content = tk.Frame(threats_win, bg=C["bg"])
        content.pack(fill="both", expand=True, padx=16, pady=12)

        # 创建 Canvas 和滚动条
        canvas = tk.Canvas(content, bg=C["bg"], highlightthickness=0)
        scrollbar = tk.Scrollbar(content, command=canvas.yview,
                                  bg=C["border"], troughcolor=C["bg"],
                                  relief="flat", bd=0)
        scroll_frame = tk.Frame(canvas, bg=C["bg"])

        scroll_frame.bind("<Configure>",
                          lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # 为每个威胁创建卡片
        for i, threat in enumerate(threats):
            file_path = threat.get("path", threat.get("display_path", "未知"))
            display_path = threat.get("display_path", file_path)
            virus_name = threat.get("virus", "未知威胁")

            card = tk.Frame(scroll_frame, bg=C["card"],
                            highlightthickness=1,
                            highlightbackground=C["border"])
            card.pack(fill="x", pady=(0, 8))

            tk.Label(card, text=f"威胁 {i+1}: {virus_name}",
                     bg=C["card"], fg=C["danger"],
                     font=(FONT_FAMILY_BOLD, 10, "bold")).pack(anchor="w", padx=12, pady=(8, 4))
            tk.Label(card, text=display_path,
                     bg=C["card"], fg=C["text"],
                     font=(FONT_MONO, 9), anchor="w", wraplength=480).pack(anchor="w", padx=12, pady=(0, 8))

        # 操作按钮区域
        btn_frame = tk.Frame(threats_win, bg=C["bg"])
        btn_frame.pack(fill="x", padx=16, pady=(0, 16))

        def _quarantine_all():
            """隔离所有威胁文件"""
            success = 0
            for threat in threats:
                file_path = threat.get("path", threat.get("display_path", ""))
                virus_name = threat.get("virus", "未知威胁")
                ok, _ = self.quar_mgr.quarantine_file(file_path, virus_name)
                if ok:
                    success += 1
            self._toast.show("隔离完成", f"成功隔离 {success}/{len(threats)} 个文件", icon_type="success")
            threats_win.destroy()

        self._btn(btn_frame, "全部隔离", _quarantine_all,
                  color=C["danger"]).pack(side="left", padx=(0, 8))
        self._btn(btn_frame, "关闭", threats_win.destroy,
                  color=C["dim"]).pack(side="right")

        # 居中于主窗口
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 560) // 2
        y = self.winfo_y() + (self.winfo_height() - 500) // 2
        threats_win.geometry(f"+{max(0, x)}+{max(0, y)}")

    # ═════════════ 首页 ═════════════
    # （_build_home 及之后的方法将在后续部分实现）
    # ═══════════════════════════════════════════════════════════════
    #  首页 - 安全概览（优化版）
    # ═══════════════════════════════════════════════════════════════
    def _build_home(self, parent):
        page = tk.Frame(parent, bg=C["bg"])
        page.pack(fill="both", expand=True)

        # ── 顶部盾牌状态指示器 ──
        shield_frame = tk.Frame(page, bg=C["bg"])
        shield_frame.pack(fill="x", padx=30, pady=(24, 16))

        self._home_shield_canvas = tk.Canvas(shield_frame, width=120, height=120,
                                              bg=C["bg"], highlightthickness=0)
        self._home_shield_canvas.pack()

        self._home_status_label = tk.Label(shield_frame, text="正在检测安全状态...",
                                            bg=C["bg"], fg=C["dim"],
                                            font=(FONT_FAMILY_BOLD, 13, "bold"))
        self._home_status_label.pack(pady=(8, 0))

        self._home_status_sub = tk.Label(shield_frame, text="",
                                          bg=C["bg"], fg=C["dim"],
                                          font=(FONT_FAMILY, 10))
        self._home_status_sub.pack(pady=(2, 0))

        # 初始绘制灰色盾牌
        self._draw_shield("gray")

        # ── 状态卡片区域 ──
        cards_frame = tk.Frame(page, bg=C["bg"])
        cards_frame.pack(fill="x", padx=30, pady=(8, 12))

        # 使用 Canvas 绘制圆角矩形背景的卡片
        self._home_card_canvas = tk.Canvas(cards_frame, height=100,
                                            bg=C["bg"], highlightthickness=0)
        self._home_card_canvas.pack(fill="x")

        # 引擎状态卡片
        self._home_engine_card = tk.Frame(cards_frame, bg=C["card"],
                                           highlightthickness=1,
                                           highlightbackground=C["border"])
        self._home_engine_card.place(x=0, y=0, width=220, height=100)

        tk.Label(self._home_engine_card, text="引擎状态",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(pady=(14, 4))
        self._home_engine_val = tk.Label(self._home_engine_card, text="检测中...",
                                          bg=C["card"], fg=C["text"],
                                          font=(FONT_MONO, 16, "bold"))
        self._home_engine_val.pack()

        # 病毒库状态卡片
        self._home_db_card = tk.Frame(cards_frame, bg=C["card"],
                                       highlightthickness=1,
                                       highlightbackground=C["border"])
        self._home_db_card.place(x=240, y=0, width=220, height=100)

        tk.Label(self._home_db_card, text="病毒库",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(pady=(14, 4))
        self._home_db_val = tk.Label(self._home_db_card, text="检测中...",
                                      bg=C["card"], fg=C["text"],
                                      font=(FONT_MONO, 16, "bold"))
        self._home_db_val.pack()

        # 隔离文件卡片
        self._home_quar_card = tk.Frame(cards_frame, bg=C["card"],
                                         highlightthickness=1,
                                         highlightbackground=C["border"])
        self._home_quar_card.place(x=480, y=0, width=220, height=100)

        tk.Label(self._home_quar_card, text="隔离文件",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(pady=(14, 4))
        self._home_quar_val = tk.Label(self._home_quar_card, text="0",
                                        bg=C["card"], fg=C["text"],
                                        font=(FONT_MONO, 16, "bold"))
        self._home_quar_val.pack()

        # 实时防护卡片
        self._home_rt_card = tk.Frame(cards_frame, bg=C["card"],
                                       highlightthickness=1,
                                       highlightbackground=C["border"])
        self._home_rt_card.place(x=720, y=0, width=220, height=100)

        tk.Label(self._home_rt_card, text="实时防护",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(pady=(14, 4))
        self._home_rt_val = tk.Label(self._home_rt_card, text="关闭",
                                      bg=C["card"], fg=C["warn"],
                                      font=(FONT_MONO, 16, "bold"))
        self._home_rt_val.pack()

        # ── 扫描统计仪表盘 ──
        dash_frame = tk.Frame(page, bg=C["bg"])
        dash_frame.pack(fill="x", padx=30, pady=(4, 12))

        tk.Label(dash_frame, text="扫描统计", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 12, "bold"), anchor="w").pack(fill="x", pady=(0, 8))

        self._home_dash_canvas = tk.Canvas(dash_frame, height=80,
                                            bg=C["bg"], highlightthickness=0)
        self._home_dash_canvas.pack(fill="x")

        # 仪表盘卡片 - 本周扫描次数
        self._dash_week_card = tk.Frame(dash_frame, bg=C["card"],
                                         highlightthickness=1,
                                         highlightbackground=C["border"])
        self._dash_week_card.place(x=0, y=0, width=310, height=80)

        tk.Label(self._dash_week_card, text="本周扫描次数",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(pady=(12, 2))
        self._dash_week_val = tk.Label(self._dash_week_card, text="0",
                                        bg=C["card"], fg=C["accent"],
                                        font=(FONT_MONO, 16, "bold"))
        self._dash_week_val.pack()

        # 仪表盘卡片 - 累计拦截威胁数
        self._dash_threats_card = tk.Frame(dash_frame, bg=C["card"],
                                            highlightthickness=1,
                                            highlightbackground=C["border"])
        self._dash_threats_card.place(x=330, y=0, width=310, height=80)

        tk.Label(self._dash_threats_card, text="累计拦截威胁",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(pady=(12, 2))
        self._dash_threats_val = tk.Label(self._dash_threats_card, text="0",
                                           bg=C["card"], fg=C["danger"],
                                           font=(FONT_MONO, 16, "bold"))
        self._dash_threats_val.pack()

        # 仪表盘卡片 - 病毒库签名总数
        self._dash_sigs_card = tk.Frame(dash_frame, bg=C["card"],
                                         highlightthickness=1,
                                         highlightbackground=C["border"])
        self._dash_sigs_card.place(x=660, y=0, width=310, height=80)

        tk.Label(self._dash_sigs_card, text="病毒库签名数",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(pady=(12, 2))
        self._dash_sigs_val = tk.Label(self._dash_sigs_card, text="--",
                                        bg=C["card"], fg=C["green"],
                                        font=(FONT_MONO, 16, "bold"))
        self._dash_sigs_val.pack()

        # ── 快速操作区 ──
        action_frame = tk.Frame(page, bg=C["bg"])
        action_frame.pack(fill="x", padx=30, pady=(8, 24))

        self._btn(action_frame, "快速扫描", lambda: self._start_scan("quick"),
                  color=C["accent"]).pack(side="left", padx=(0, 12))
        self._btn(action_frame, "全盘扫描", lambda: self._start_scan("full"),
                  color=C["accent2"]).pack(side="left", padx=(0, 12))
        self._btn(action_frame, "更新病毒库", self._do_update,
                  color=C["green"]).pack(side="left")

        # 保存引用以便后续更新
        self._home_widgets = {
            "shield_canvas": self._home_shield_canvas,
            "status_label": self._home_status_label,
            "status_sub": self._home_status_sub,
            "engine_val": self._home_engine_val,
            "db_val": self._home_db_val,
            "quar_val": self._home_quar_val,
            "rt_val": self._home_rt_val,
            "week_val": self._dash_week_val,
            "threats_val": self._dash_threats_val,
            "sigs_val": self._dash_sigs_val,
        }

        return page

    def _draw_shield(self, status="gray"):
        """
        在首页 Canvas 上绘制盾牌状态图标
        :param status: "green"(安全), "red"(威胁), "gray"(未扫描)
        """
        c = self._home_shield_canvas
        c.delete("all")
        cx, cy = 60, 60
        r = 48

        # 颜色映射
        color_map = {
            "green": C["green"],
            "red": C["danger"],
            "gray": C["dim"],
        }
        fill_color = color_map.get(status, C["dim"])
        light_color = _lighten(fill_color, 0.2)

        # 外圈光晕
        c.create_oval(cx - r - 4, cy - r - 4, cx + r + 4, cy + r + 4,
                      fill="", outline=light_color, width=2)

        # 主圆
        c.create_oval(cx - r, cy - r, cx + r, cy + r,
                      fill=_darken(fill_color, 0.6), outline=fill_color, width=3)

        # 盾牌形状（内部）
        shield_pts = [
            cx, cy - 28,       # 顶部中心
            cx + 22, cy - 18,  # 右上
            cx + 22, cy + 6,   # 右中
            cx, cy + 24,       # 底部
            cx - 22, cy + 6,   # 左中
            cx - 22, cy - 18,  # 左上
        ]
        c.create_polygon(shield_pts, fill=fill_color, outline="", smooth=False)

        # 盾牌内文字
        if status == "green":
            c.create_text(cx, cy - 2, text="✓", font=(FONT_FAMILY_BOLD, 22, "bold"),
                          fill=C["white"])
        elif status == "red":
            c.create_text(cx, cy - 2, text="!", font=(FONT_FAMILY_BOLD, 22, "bold"),
                          fill=C["white"])
        else:
            c.create_text(cx, cy - 2, text="?", font=(FONT_FAMILY_BOLD, 18, "bold"),
                          fill=C["white"])

    def _pulse_shield(self, step=0, total=10):
        """盾牌脉冲动画（威胁时使用）"""
        if not self._anim_active:
            return
        if step >= total:
            return
        try:
            if not self._home_shield_canvas.winfo_exists():
                return
        except Exception:
            return

        color = _pulse_color(C["danger"], step, total)
        c = self._home_shield_canvas
        cx, cy = 60, 60
        r = 48
        # 更新外圈颜色
        c.delete("pulse_ring")
        c.create_oval(cx - r - 4, cy - r - 4, cx + r + 4, cy + r + 4,
                      fill="", outline=color, width=3, tags="pulse_ring")
        self.after(80, lambda: self._pulse_shield(step + 1, total))

    def _update_home_status(self, engine_ok, db_ok, threats=0):
        """更新首页安全状态"""
        if engine_ok and db_ok and threats == 0:
            self._draw_shield("green")
            self._home_status_label.config(text="您的电脑很安全", fg=C["green"])
            self._home_status_sub.config(text="所有防护组件运行正常")
            self._home_engine_val.config(text="就绪", fg=C["green"])
            self._home_db_val.config(text="已安装", fg=C["green"])
        elif threats > 0:
            self._draw_shield("red")
            self._home_status_label.config(text=f"发现 {threats} 个威胁",
                                            fg=C["danger"])
            self._home_status_sub.config(text="建议立即处理威胁文件")
            self._home_engine_val.config(text="就绪", fg=C["green"])
            self._home_db_val.config(text="已安装", fg=C["green"])
            self._pulse_shield()
        else:
            self._draw_shield("gray")
            self._home_status_label.config(text="建议立即扫描", fg=C["warn"])
            self._home_status_sub.config(text="部分组件未就绪")
            if not engine_ok:
                self._home_engine_val.config(text="异常", fg=C["danger"])
            else:
                self._home_engine_val.config(text="就绪", fg=C["green"])
            if not db_ok:
                self._home_db_val.config(text="未安装", fg=C["warn"])
            else:
                self._home_db_val.config(text="已安装", fg=C["green"])

        # 更新隔离文件数
        try:
            quar_count = self.quar_mgr.count_items()
            self._home_quar_val.config(text=str(quar_count))
        except Exception:
            pass

        # 更新仪表盘统计
        self._update_dashboard_stats()

    def _update_dashboard_stats(self):
        """更新仪表盘统计数据"""
        try:
            stats = self._scan_history.get_stats()
            # get_stats 返回 total_scans, total_scanned, total_infected, total_errors
            # 没有 week_count，使用 total_scans 代替
            total_scans = stats.get("total_scans", 0)
            total_threats = stats.get("total_infected", 0)

            self._dash_week_val.config(text=str(total_scans))
            self._dash_threats_val.config(text=str(total_threats))
        except Exception:
            pass

        # 更新病毒库签名数
        try:
            db_info = self.backend.get_db_info()
            sig_count = 0
            for info in db_info:
                if info.get("ok"):
                    # 从日期字段提取签名数（YARA 规则）
                    date_str = info.get("date", "")
                    if "条签名" in date_str:
                        m = re.search(r'(\d+)', date_str)
                        if m:
                            sig_count += int(m.group(1))
            if sig_count > 0:
                self._dash_sigs_val.config(text=f"{sig_count:,}")
            else:
                self._dash_sigs_val.config(text="已加载")
        except Exception:
            self._dash_sigs_val.config(text="--")

    # ═══════════════════════════════════════════════════════════════
    #  扫描页面（优化版）
    # ═══════════════════════════════════════════════════════════════
    def _build_scan(self, parent):
        page = tk.Frame(parent, bg=C["bg"])
        page.pack(fill="both", expand=True)

        # ── 扫描模式选择 ──
        mode_frame = tk.Frame(page, bg=C["bg"])
        mode_frame.pack(fill="x", padx=30, pady=(24, 12))

        tk.Label(mode_frame, text="选择扫描模式", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 12, "bold"), anchor="w").pack(fill="x", pady=(0, 10))

        modes_row = tk.Frame(mode_frame, bg=C["bg"])
        modes_row.pack(fill="x")

        # 快速扫描卡片
        self._scan_mode_quick = tk.Frame(modes_row, bg=C["card"],
                                          highlightthickness=1,
                                          highlightbackground=C["border"],
                                          cursor="hand2")
        self._scan_mode_quick.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self._scan_mode_quick.pack_propagate(False)
        self._scan_mode_quick.configure(height=90)

        tk.Label(self._scan_mode_quick, text="快速扫描",
                 bg=C["card"], fg=C["accent"],
                 font=(FONT_FAMILY_BOLD, 12, "bold")).pack(pady=(16, 2))
        tk.Label(self._scan_mode_quick, text="扫描关键系统目录",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack()
        self._scan_mode_quick.bind("<Button-1>", lambda e: self._select_scan_mode("quick"))
        self._scan_mode_quick.bind("<Enter>", lambda e: self._scan_mode_quick.config(
            bg=C["card_hover"]) if self._current_scan_mode != "quick" else None)
        self._scan_mode_quick.bind("<Leave>", lambda e: self._scan_mode_quick.config(
            bg=C["card"]) if self._current_scan_mode != "quick" else None)

        # 全盘扫描卡片
        self._scan_mode_full = tk.Frame(modes_row, bg=C["card"],
                                         highlightthickness=1,
                                         highlightbackground=C["border"],
                                         cursor="hand2")
        self._scan_mode_full.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self._scan_mode_full.pack_propagate(False)
        self._scan_mode_full.configure(height=90)

        tk.Label(self._scan_mode_full, text="全盘扫描",
                 bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY_BOLD, 12, "bold")).pack(pady=(16, 2))
        tk.Label(self._scan_mode_full, text="扫描所有磁盘分区",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack()
        self._scan_mode_full.bind("<Button-1>", lambda e: self._select_scan_mode("full"))
        self._scan_mode_full.bind("<Enter>", lambda e: self._scan_mode_full.config(
            bg=C["card_hover"]) if self._current_scan_mode != "full" else None)
        self._scan_mode_full.bind("<Leave>", lambda e: self._scan_mode_full.config(
            bg=C["card"]) if self._current_scan_mode != "full" else None)

        # 自定义扫描卡片
        self._scan_mode_custom = tk.Frame(modes_row, bg=C["card"],
                                           highlightthickness=1,
                                           highlightbackground=C["border"],
                                           cursor="hand2")
        self._scan_mode_custom.pack(side="left", fill="both", expand=True)
        self._scan_mode_custom.pack_propagate(False)
        self._scan_mode_custom.configure(height=90)

        tk.Label(self._scan_mode_custom, text="自定义扫描",
                 bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY_BOLD, 12, "bold")).pack(pady=(16, 2))
        tk.Label(self._scan_mode_custom, text="选择文件或目录扫描",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack()
        self._scan_mode_custom.bind("<Button-1>", lambda e: self._select_scan_mode("custom"))
        self._scan_mode_custom.bind("<Enter>", lambda e: self._scan_mode_custom.config(
            bg=C["card_hover"]) if self._current_scan_mode != "custom" else None)
        self._scan_mode_custom.bind("<Leave>", lambda e: self._scan_mode_custom.config(
            bg=C["card"]) if self._current_scan_mode != "custom" else None)

        self._current_scan_mode = "quick"
        self._scan_mode_quick.config(highlightbackground=C["accent"], highlightthickness=2)

        # ── 扫描目标路径 ──
        target_frame = tk.Frame(page, bg=C["bg"])
        target_frame.pack(fill="x", padx=30, pady=(8, 8))

        tk.Label(target_frame, text="扫描目标", bg=C["bg"], fg=C["text"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(fill="x", pady=(0, 4))

        target_row = tk.Frame(target_frame, bg=C["bg"])
        target_row.pack(fill="x")

        self._scan_target_entry = tk.Entry(target_row, textvariable=self._scan_target,
                                            bg=C["card"], fg=C["text"],
                                            font=(FONT_MONO, 10),
                                            insertbackground=C["accent"],
                                            relief="flat", bd=0)
        self._scan_target_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))

        self._btn(target_row, "浏览", self._browse_target,
                  color=C["border"]).pack(side="left")

        # ── 白名单管理入口 ──
        excl_frame = tk.Frame(page, bg=C["bg"])
        excl_frame.pack(fill="x", padx=30, pady=(0, 8))

        excl_count = len(self._exclusion_mgr.list_all())
        self._btn(excl_frame,
                  f"扫描白名单 ({excl_count} 条)",
                  self._show_exclusion_manager,
                  color=C["border"]).pack(anchor="w")

        # ── 扫描进度区域 ──
        progress_frame = tk.Frame(page, bg=C["bg"])
        progress_frame.pack(fill="x", padx=30, pady=(8, 8))

        self._scan_file_label = tk.Label(progress_frame,
                                          textvariable=self._current_scan_file,
                                          bg=C["bg"], fg=C["dim"],
                                          font=(FONT_MONO, 9), anchor="w")
        self._scan_file_label.pack(fill="x", pady=(0, 4))

        self._scan_pb = self._progress_bar(progress_frame)

        # 进度百分比标签
        self._scan_pct_label = tk.Label(progress_frame, text="0%",
                                         bg=C["bg"], fg=C["dim"],
                                         font=(FONT_MONO, 9), anchor="e")
        self._scan_pct_label.pack(fill="x")

        # ── 操作按钮 ──
        btn_frame = tk.Frame(page, bg=C["bg"])
        btn_frame.pack(fill="x", padx=30, pady=(8, 12))

        self._scan_start_btn = self._btn(btn_frame, "开始扫描", self._start_scan,
                                          color=C["accent"])
        self._scan_start_btn.pack(side="left", padx=(0, 12))

        self._scan_stop_btn = self._btn(btn_frame, "停止扫描", self._stop_scan,
                                         color=C["danger"])
        self._scan_stop_btn.pack(side="left")
        self._scan_stop_btn.config(state="disabled")

        # ── 扫描结果日志 ──
        log_label_frame = tk.Frame(page, bg=C["bg"])
        log_label_frame.pack(fill="x", padx=30, pady=(8, 4))

        tk.Label(log_label_frame, text="扫描日志", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 11, "bold"), anchor="w").pack(fill="x")

        self._scan_out = self._log_text(page, height=8)
        self._scan_out.pack(fill="both", expand=True, padx=30, pady=(0, 24))

        return page

    def _select_scan_mode(self, mode):
        """选择扫描模式"""
        self._current_scan_mode = mode
        # 重置所有卡片样式
        for card, m in [(self._scan_mode_quick, "quick"),
                        (self._scan_mode_full, "full"),
                        (self._scan_mode_custom, "custom")]:
            if m == mode:
                card.config(highlightbackground=C["accent"], highlightthickness=2,
                           bg=C["card"])
            else:
                card.config(highlightbackground=C["border"], highlightthickness=1,
                           bg=C["card"])

        # 设置扫描目标
        if mode == "quick":
            # 快速扫描：关键系统目录
            if IS_WIN:
                targets = [os.environ.get("APPDATA", ""),
                           os.environ.get("PROGRAMFILES", "C:\\Program Files"),
                           os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")]
                # 使用第一个有效目标作为快速扫描目标
                valid_targets = [t for t in targets if t]
                if valid_targets:
                    self._scan_target.set(valid_targets[0])
                else:
                    self._scan_target.set("C:\\")
            else:
                # 使用 /home 作为快速扫描目标
                self._scan_target.set("/home")
        elif mode == "full":
            if IS_WIN:
                self._scan_target.set("C:\\")
            else:
                self._scan_target.set("/")
        elif mode == "custom":
            self._scan_target.set("")

    def _browse_target(self):
        """浏览选择扫描目标"""
        path = filedialog.askdirectory(title="选择扫描目录")
        if path:
            self._scan_target.set(path)

    def _start_scan(self, mode=None):
        """开始扫描"""
        if self._scanning:
            return

        # FIX-BUG-6: 如果传入了 mode，更新当前扫描模式
        if mode:
            self._current_scan_mode = mode
            self._select_scan_mode(mode)

        target = self._scan_target.get().strip()
        if not target:
            if mode == "quick":
                self._select_scan_mode("quick")
                target = self._scan_target.get().strip()
            elif mode == "full":
                self._select_scan_mode("full")
                target = self._scan_target.get().strip()
            else:
                self._toast.show("请选择扫描目标", "请先选择要扫描的文件或目录",
                                 icon_type="warning")
                return

        if not target:
            self._toast.show("请选择扫描目标", "请先选择要扫描的文件或目录",
                             icon_type="warning")
            return

        self._scanning = True
        self._scan_results = None
        self._scan_start_time = time.time()
        self._scan_has_real_total = False
        self._pseudo_start_time = 0

        # UI 状态更新
        self._scan_start_btn.config(state="disabled")
        self._scan_stop_btn.config(state="normal")
        self._scan_pb["value"] = 0
        self._scan_pct_label.config(text="0%")
        self._current_scan_file.set("正在准备扫描...")
        self._status_text.set("正在扫描...")

        # 清空日志
        try:
            self._scan_out.config(state="normal")
            self._scan_out.delete("1.0", "end")
            self._scan_out.config(state="disabled")
        except Exception:
            pass

        # 获取排除列表
        exclusions = self._exclusion_mgr.list_all()

        self._log(f"开始扫描: {target}", "info")
        if exclusions:
            self._log(f"已加载 {len(exclusions)} 条排除规则", "info")

        # 启动伪进度（阶段1）
        self._start_pseudo_progress()

        # 调用后端扫描
        self.backend.scan(target, self._on_scan_progress, self._on_scan_result,
                          log_file_cb=self._on_scan_log_file,
                          exclusions=exclusions)

    def _start_pseudo_progress(self):
        """启动伪进度动画（阶段1：0~5%）"""
        self._pseudo_start_time = time.time()
        self._pseudo_timer = self.after(50, self._tick_pseudo_progress)

    def _tick_pseudo_progress(self):
        """伪进度定时器"""
        if not self._scanning or self._scan_has_real_total:
            if self._pseudo_timer:
                self.after_cancel(self._pseudo_timer)
                self._pseudo_timer = None
            return
        try:
            elapsed = time.time() - self._pseudo_start_time
            # 5秒内从0%到5%
            pct = min(5, elapsed * 1.0)
            self._scan_pb["value"] = pct
            self._scan_pct_label.config(text=f"{pct:.0f}%")
            self._pseudo_timer = self.after(50, self._tick_pseudo_progress)
        except Exception:
            pass

    def _on_scan_progress(self, pct, current_file, scanned, total):
        """扫描进度回调 - 线程安全版本"""
        # FIX-BUG-1: 使用 after(0, ...) 确保 UI 更新在主线程执行
        self.after(0, lambda: self._do_update_scan_progress(pct, current_file, scanned, total))

    def _do_update_scan_progress(self, pct, current_file, scanned, total):
        """实际执行扫描进度 UI 更新（在主线程中）"""
        if not self._anim_active:
            return
        try:
            if pct == -1:
                # 尚无真实 total，继续伪进度
                return

            if total is not None and total > 0 and not self._scan_has_real_total:
                self._scan_has_real_total = True
                if self._pseudo_timer:
                    self.after_cancel(self._pseudo_timer)
                    self._pseudo_timer = None

            if current_file:
                self._current_scan_file.set(f"正在扫描: {current_file}")

            self._scan_pb["value"] = pct
            self._scan_pct_label.config(text=f"{pct}%")
        except Exception:
            pass

    def _on_scan_result(self, results, error):
        """扫描结果回调 - 线程安全版本"""
        # FIX-BUG-1: 使用 after(0, ...) 确保 UI 更新在主线程执行
        self.after(0, lambda: self._do_update_scan_result(results, error))

    def _do_update_scan_result(self, results, error):
        """实际执行扫描结果 UI 更新（在主线程中）"""
        self._scanning = False
        self._scan_results = results

        # 停止伪进度
        if self._pseudo_timer:
            self.after_cancel(self._pseudo_timer)
            self._pseudo_timer = None

        # UI 状态恢复
        self._scan_start_btn.config(state="normal")
        self._scan_stop_btn.config(state="disabled")

        if error:
            self._scan_pb["value"] = 0
            self._scan_pct_label.config(text="失败")
            self._current_scan_file.set(f"扫描失败: {error}")
            self._status_text.set("扫描失败")
            self._log(f"扫描失败: {error}", "danger")
            self._toast.show("扫描失败", error, icon_type="error")
            return

        # 计算扫描耗时
        duration = 0
        if self._scan_start_time:
            duration = time.time() - self._scan_start_time

        infected = len(results.get("infected", []))
        scanned = results.get("scanned", 0)
        errors = results.get("errors", 0)

        # 完成进度到100%
        self._scan_pb["value"] = 100
        self._scan_pct_label.config(text="100%")
        self._current_scan_file.set("扫描完成")

        if infected > 0:
            self._status_text.set(f"扫描完成 - 发现 {infected} 个威胁")
            self._log(f"扫描完成: 发现 {infected} 个威胁", "danger")
            self._toast.show("发现威胁",
                             f"扫描完成，发现 {infected} 个威胁文件",
                             icon_type="error")

            # FIX-BUG-3: 多威胁时改为单弹窗列出所有威胁
            self._show_threats_list(results["infected"])

            # 脉冲动画
            self._pulse_card(self._scan_pb.master, C["danger"])
        else:
            self._status_text.set("扫描完成 - 未发现威胁")
            self._log(f"扫描完成: 安全，已扫描 {scanned} 个文件", "success")
            self._toast.show("扫描完成",
                             f"已扫描 {scanned} 个文件，未发现威胁",
                             icon_type="success")

            # 绿色脉冲闪烁2次
            self._pulse_card(self._scan_pb.master, C["green"])

        # 记录扫描历史
        try:
            scan_type = self._current_scan_mode
            target = self._scan_target.get().strip()
            self._scan_history.add_record(
                scan_type=scan_type,
                target=target,
                scanned=scanned,
                infected=infected,
                errors=errors,
                duration=duration
            )
        except Exception as e:
            self._log(f"记录扫描历史失败: {e}", "warn")

        # 更新首页状态
        self._update_home_status(True, self.backend.check_database(),
                                  infected)

    def _on_scan_log_file(self, log_path):
        """扫描日志文件路径回调"""
        self._scan_log_path = log_path

    def _stop_scan(self):
        """停止扫描 - FIX-BUG-9: 在子线程中执行取消操作避免阻塞 UI"""
        if not self._scanning:
            return
        # FIX-BUG-9: 将取消操作移到子线程，避免阻塞主线程
        threading.Thread(target=self._do_cancel_scan, daemon=True).start()
        self._scanning = False
        self._status_text.set("扫描已停止")

        if self._pseudo_timer:
            self.after_cancel(self._pseudo_timer)
            self._pseudo_timer = None

        self._scan_start_btn.config(state="normal")
        self._scan_stop_btn.config(state="disabled")
        self._current_scan_file.set("扫描已停止")
        self._log("用户已停止扫描", "warn")

    def _do_cancel_scan(self):
        """实际执行取消扫描（在子线程中）"""
        self.backend.cancel_scan()

    def _pulse_card(self, parent, color):
        """
        扫描完成时让状态卡片脉冲闪烁2次
        :param parent: 父容器
        :param color: 脉冲颜色
        """
        total_steps = 20  # 2次完整脉冲，每次10步
        self._do_pulse_card(parent, color, 0, total_steps)

    def _do_pulse_card(self, parent, color, step, total_steps):
        """执行卡片脉冲动画"""
        if not self._anim_active or step >= total_steps:
            try:
                parent.config(highlightbackground=C["border"])
            except Exception:
                pass
            return
        try:
            if not parent.winfo_exists():
                return
        except Exception:
            return

        pulse = _pulse_color(color, step % 10, 10)
        parent.config(highlightbackground=pulse)
        self.after(80, lambda: self._do_pulse_card(parent, color, step + 1, total_steps))

    # ═══════════════════════════════════════════════════════════════
    #  更新页面（优化版）
    # ═══════════════════════════════════════════════════════════════
    def _build_update(self, parent):
        page = tk.Frame(parent, bg=C["bg"])
        page.pack(fill="both", expand=True)

        # 标题
        tk.Label(page, text="病毒库更新", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 14, "bold")).pack(anchor="w", padx=30, pady=(24, 4))
        tk.Label(page, text="保持病毒库最新以获得最佳防护效果",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 10)).pack(anchor="w", padx=30, pady=(0, 16))

        # 病毒库信息卡片
        info_frame = tk.Frame(page, bg=C["card"],
                               highlightthickness=1,
                               highlightbackground=C["border"])
        info_frame.pack(fill="x", padx=30, pady=(0, 16))

        tk.Label(info_frame, text="当前病毒库信息", bg=C["card"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 11, "bold")).pack(anchor="w", padx=16, pady=(14, 8))

        self._db_info_frame = tk.Frame(info_frame, bg=C["card"])
        self._db_info_frame.pack(fill="x", padx=16, pady=(0, 14))

        # 更新进度
        self._upd_pb = self._progress_bar(page, style="ld_up.Horizontal.TProgressbar")
        self._upd_pb.pack(fill="x", padx=30, pady=(0, 4))

        self._upd_pct_label = tk.Label(page, text="", bg=C["bg"], fg=C["dim"],
                                        font=(FONT_MONO, 9), anchor="e")
        self._upd_pct_label.pack(fill="x", padx=30)

        # 操作按钮
        btn_frame = tk.Frame(page, bg=C["bg"])
        btn_frame.pack(fill="x", padx=30, pady=(12, 12))

        self._upd_start_btn = self._btn(btn_frame, "检查并更新", self._do_update,
                                         color=C["green"])
        self._upd_start_btn.pack(side="left", padx=(0, 12))

        # 更新日志
        tk.Label(page, text="更新日志", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 11, "bold"), anchor="w").pack(
            fill="x", padx=30, pady=(8, 4))

        self._upd_out = self._log_text(page, height=10)
        self._upd_out.pack(fill="both", expand=True, padx=30, pady=(0, 24))

        return page

    def _do_update(self):
        """执行病毒库更新"""
        if self._updating or self._scanning:
            if self._scanning:
                self._toast.show("无法更新", "正在扫描中，请先停止扫描",
                                 icon_type="warning")
            return

        self._updating = True
        self._upd_start_btn.config(state="disabled")
        self._upd_pb["value"] = 0
        self._upd_pct_label.config(text="0%")
        self._status_text.set("正在更新病毒库...")

        # 清空日志
        try:
            self._upd_out.config(state="normal")
            self._upd_out.delete("1.0", "end")
            self._upd_out.config(state="disabled")
        except Exception:
            pass

        self.backend.update_database(self._on_update_progress, self._on_update_done)

    def _on_update_progress(self, pct):
        """更新进度回调"""
        try:
            self._upd_pb["value"] = pct
            self._upd_pct_label.config(text=f"{pct}%")
        except Exception:
            pass

    def _on_update_done(self, success, message):
        """更新完成回调"""
        self._updating = False
        self._upd_start_btn.config(state="normal")

        if success:
            self._upd_pb["value"] = 100
            self._upd_pct_label.config(text="100%")
            self._status_text.set("病毒库已是最新")
            self._toast.show("更新成功", message, icon_type="success")
        else:
            self._status_text.set("更新失败")
            self._toast.show("更新失败", message, icon_type="error")

        # 刷新病毒库信息
        self._refresh_db_info()
        # 更新首页状态
        self._update_home_status(True, self.backend.check_database(), 0)

    def _refresh_db_info(self):
        """刷新病毒库信息显示"""
        try:
            # 清空旧信息
            for w in self._db_info_frame.winfo_children():
                w.destroy()

            db_info = self.backend.get_db_info()
            for info in db_info:
                row = tk.Frame(self._db_info_frame, bg=C["card"])
                row.pack(fill="x", pady=2)

                name = info.get("name", "")
                size = info.get("size", "--")
                date = info.get("date", "--")
                ok = info.get("ok", False)

                status_color = C["green"] if ok else C["warn"]
                status_text = "OK" if ok else "未安装"

                tk.Label(row, text=status_text, bg=C["card"], fg=status_color,
                         font=(FONT_MONO, 9, "bold"), width=6, anchor="w").pack(side="left")
                tk.Label(row, text=name, bg=C["card"], fg=C["text"],
                         font=(FONT_MONO, 10), width=20, anchor="w").pack(side="left")
                tk.Label(row, text=size, bg=C["card"], fg=C["dim"],
                         font=(FONT_MONO, 9), width=10, anchor="w").pack(side="left")
                tk.Label(row, text=date, bg=C["card"], fg=C["dim"],
                         font=(FONT_MONO, 9), anchor="w").pack(side="left")
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    #  扫描日志页面（优化版）
    # ═══════════════════════════════════════════════════════════════
    def _build_log(self, parent):
        page = tk.Frame(parent, bg=C["bg"])
        page.pack(fill="both", expand=True)

        # 标题和操作按钮
        header = tk.Frame(page, bg=C["bg"])
        header.pack(fill="x", padx=30, pady=(24, 12))

        tk.Label(header, text="扫描历史记录", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 14, "bold")).pack(side="left")

        self._btn(header, "查看全部", self._show_scan_history,
                  color=C["border"]).pack(side="right")

        # 历史记录卡片列表
        self._log_cards_frame = tk.Frame(page, bg=C["bg"])
        self._log_cards_frame.pack(fill="both", expand=True, padx=30, pady=(0, 12))

        # 创建可滚动区域
        log_canvas = tk.Canvas(self._log_cards_frame, bg=C["bg"],
                                highlightthickness=0)
        log_scrollbar = tk.Scrollbar(self._log_cards_frame, command=log_canvas.yview,
                                      bg=C["border"], troughcolor=C["bg"],
                                      relief="flat", bd=0)
        self._log_scroll_frame = tk.Frame(log_canvas, bg=C["bg"])

        self._log_scroll_frame.bind(
            "<Configure>",
            lambda e: log_canvas.configure(scrollregion=log_canvas.bbox("all"))
        )

        log_canvas.create_window((0, 0), window=self._log_scroll_frame, anchor="nw")
        log_canvas.configure(yscrollcommand=log_scrollbar.set)

        log_scrollbar.pack(side="right", fill="y")
        log_canvas.pack(side="left", fill="both", expand=True)

        # 鼠标滚轮绑定 - 只在 canvas 有焦点时绑定
        def _on_mousewheel(event):
            log_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_mousewheel(event):
            log_canvas.bind("<MouseWheel>", _on_mousewheel)

        def _unbind_mousewheel(event):
            log_canvas.unbind("<MouseWheel>")

        log_canvas.bind("<Enter>", _bind_mousewheel)
        log_canvas.bind("<Leave>", _unbind_mousewheel)

        self._log_canvas_ref = log_canvas

        # 加载最近记录
        self._refresh_log_cards()

        return page

    def _refresh_log_cards(self):
        """刷新日志卡片列表"""
        try:
            for w in self._log_scroll_frame.winfo_children():
                w.destroy()

            records = self._scan_history.get_records(limit=20)
            if not records:
                # 空状态
                empty_frame = tk.Frame(self._log_scroll_frame, bg=C["bg"])
                empty_frame.pack(fill="x", pady=40)
                tk.Label(empty_frame, text="暂无扫描记录",
                         bg=C["bg"], fg=C["dim"],
                         font=(FONT_FAMILY, 12)).pack()
                return

            for record in records:
                self._create_log_card(record)
        except Exception as e:
            self._log(f"刷新日志卡片失败: {e}", "warn")

    def _create_log_card(self, record):
        """创建单条扫描记录卡片"""
        card = tk.Frame(self._log_scroll_frame, bg=C["card"],
                         highlightthickness=1,
                         highlightbackground=C["border"])
        card.pack(fill="x", pady=(0, 8))

        # 时间 - 数据库字段名是 timestamp
        scan_time = record.get("timestamp", "--")
        scan_type = record.get("scan_type", "--")
        target = record.get("target", "--")
        scanned = record.get("scanned", 0)
        infected = record.get("infected", 0)
        duration = record.get("duration", 0)

        # 扫描类型映射
        type_map = {"quick": "快速扫描", "full": "全盘扫描", "custom": "自定义扫描"}
        type_text = type_map.get(scan_type, scan_type)

        # 顶部行：时间和类型
        top_row = tk.Frame(card, bg=C["card"])
        top_row.pack(fill="x", padx=14, pady=(10, 4))

        tk.Label(top_row, text=scan_time, bg=C["card"], fg=C["dim"],
                 font=(FONT_MONO, 9)).pack(side="left")

        type_color = C["accent"] if scan_type == "quick" else (
            C["accent2"] if scan_type == "full" else C["warn"])
        tk.Label(top_row, text=f"  {type_text}", bg=C["card"], fg=type_color,
                 font=(FONT_FAMILY, 9, "bold")).pack(side="left")

        # 结果状态
        if infected > 0:
            result_text = f"发现 {infected} 个威胁"
            result_color = C["danger"]
        else:
            result_text = "安全"
            result_color = C["green"]
        tk.Label(top_row, text=result_text, bg=C["card"], fg=result_color,
                 font=(FONT_FAMILY_BOLD, 9, "bold")).pack(side="right")

        # 中间行：目标路径
        mid_row = tk.Frame(card, bg=C["card"])
        mid_row.pack(fill="x", padx=14, pady=(0, 4))

        display_target = _truncate_path(target, 80)
        tk.Label(mid_row, text=f"目标: {display_target}", bg=C["card"], fg=C["text"],
                 font=(FONT_MONO, 9), anchor="w").pack(side="left")

        # 底部行：统计信息
        bot_row = tk.Frame(card, bg=C["card"])
        bot_row.pack(fill="x", padx=14, pady=(0, 10))

        duration_str = f"{duration:.1f}s" if duration > 0 else "--"
        tk.Label(bot_row, text=f"已扫描: {scanned}  |  耗时: {duration_str}",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_MONO, 9)).pack(side="left")

    def _show_scan_history(self):
        """显示完整扫描历史弹窗"""
        history_win = tk.Toplevel(self)
        history_win.title("扫描历史记录")
        history_win.geometry("700x500")
        history_win.resizable(True, True)
        history_win.transient(self)
        history_win.configure(bg=C["bg"])
        history_win.protocol("WM_DELETE_WINDOW", lambda: history_win.destroy())

        # 标题栏
        title_bar = tk.Frame(history_win, bg=C["panel"], height=50)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        tk.Label(title_bar, text="全部扫描历史记录", bg=C["panel"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 13, "bold")).pack(side="left", padx=20, pady=12)

        self._btn(title_bar, "清空记录", lambda: self._clear_scan_history(history_win),
                  color=C["danger"]).pack(side="right", padx=20, pady=10)

        # 列表区域
        list_frame = tk.Frame(history_win, bg=C["bg"])
        list_frame.pack(fill="both", expand=True, padx=16, pady=16)

        # 表头
        header = tk.Frame(list_frame, bg=C["card"])
        header.pack(fill="x", pady=(0, 4))
        headers = [("时间", 16), ("类型", 10), ("目标", 30), ("已扫描", 8),
                   ("威胁", 6), ("耗时", 8)]
        for text, width in headers:
            tk.Label(header, text=text, bg=C["card"], fg=C["dim"],
                     font=(FONT_FAMILY_BOLD, 9, "bold"), width=width,
                     anchor="w").pack(side="left", padx=4, pady=6)

        # 可滚动列表
        canvas = tk.Canvas(list_frame, bg=C["bg"], highlightthickness=0)
        scrollbar = tk.Scrollbar(list_frame, command=canvas.yview,
                                  bg=C["border"], troughcolor=C["bg"],
                                  relief="flat", bd=0)
        scroll_frame = tk.Frame(canvas, bg=C["bg"])

        scroll_frame.bind("<Configure>",
                          lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # 加载记录
        try:
            records = self._scan_history.get_records(limit=100)
            type_map = {"quick": "快速扫描", "full": "全盘扫描", "custom": "自定义扫描"}

            for record in records:
                row = tk.Frame(scroll_frame, bg=C["card"],
                               highlightthickness=1,
                               highlightbackground=C["border"])
                row.pack(fill="x", pady=(0, 2))

                scan_time = record.get("timestamp", "--")
                scan_type = type_map.get(record.get("scan_type", ""), record.get("scan_type", ""))
                target = _truncate_path(record.get("target", "--"), 40)
                scanned = str(record.get("scanned", 0))
                infected = str(record.get("infected", 0))
                duration = f"{record.get('duration', 0):.1f}s"

                infected_color = C["danger"] if int(infected) > 0 else C["green"]

                for text, width in [(scan_time, 16), (scan_type, 10),
                                     (target, 30), (scanned, 8)]:
                    tk.Label(row, text=text, bg=C["card"], fg=C["text"],
                             font=(FONT_MONO, 9), width=width,
                             anchor="w").pack(side="left", padx=4, pady=4)

                tk.Label(row, text=infected, bg=C["card"], fg=infected_color,
                         font=(FONT_MONO, 9, "bold"), width=6,
                         anchor="w").pack(side="left", padx=4, pady=4)

                tk.Label(row, text=duration, bg=C["card"], fg=C["dim"],
                         font=(FONT_MONO, 9), width=8,
                         anchor="w").pack(side="left", padx=4, pady=4)

            if not records:
                tk.Label(scroll_frame, text="暂无扫描记录", bg=C["bg"], fg=C["dim"],
                         font=(FONT_FAMILY, 11)).pack(pady=40)
        except Exception as e:
            tk.Label(scroll_frame, text=f"加载失败: {e}", bg=C["bg"], fg=C["danger"],
                     font=(FONT_FAMILY, 10)).pack(pady=40)

        # 居中
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 700) // 2
        y = self.winfo_y() + (self.winfo_height() - 500) // 2
        history_win.geometry(f"+{max(0, x)}+{max(0, y)}")

    def _clear_scan_history(self, parent_win):
        """清空扫描历史"""
        if messagebox.askyesno("确认清空", "确定要清空所有扫描历史记录吗？\n此操作不可撤销。"):
            try:
                self._scan_history.clear_records()
                self._refresh_log_cards()
                parent_win.destroy()
                self._toast.show("已清空", "扫描历史记录已清空", icon_type="success")
            except Exception as e:
                self._toast.show("清空失败", str(e), icon_type="error")

    # ═══════════════════════════════════════════════════════════════
    #  隔离箱页面（优化版）
    # ═══════════════════════════════════════════════════════════════
    def _build_quarantine(self, parent):
        page = tk.Frame(parent, bg=C["bg"])
        page.pack(fill="both", expand=True)

        # 标题和操作按钮
        header = tk.Frame(page, bg=C["bg"])
        header.pack(fill="x", padx=30, pady=(24, 12))

        tk.Label(header, text="隔离箱", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 14, "bold")).pack(side="left")

        self._quar_count_label = tk.Label(header, text="", bg=C["bg"], fg=C["dim"],
                                           font=(FONT_FAMILY, 10))
        self._quar_count_label.pack(side="left", padx=(12, 0))

        # 操作按钮行
        btn_row = tk.Frame(header, bg=C["bg"])
        btn_row.pack(side="right")

        self._quar_restore_btn = self._btn(btn_row, "恢复选中", self._restore_selected,
                                            color=C["green"])
        self._quar_restore_btn.pack(side="left", padx=(0, 8))
        self._quar_restore_btn.config(state="disabled")

        self._quar_delete_btn = self._btn(btn_row, "删除选中", self._delete_selected,
                                           color=C["danger"])
        self._quar_delete_btn.pack(side="left", padx=(0, 8))
        self._quar_delete_btn.config(state="disabled")

        self._quar_select_all_btn = self._btn(btn_row, "全选", self._select_all_quar,
                                               color=C["border"])
        self._quar_select_all_btn.pack(side="left")

        # 搜索栏
        search_frame = tk.Frame(page, bg=C["bg"])
        search_frame.pack(fill="x", padx=30, pady=(0, 8))

        self._quar_search_var = tk.StringVar()
        self._quar_search_var.trace_add("write", lambda *a: self._on_quar_search())

        search_entry = tk.Entry(search_frame, textvariable=self._quar_search_var,
                                 bg=C["card"], fg=C["text"],
                                 font=(FONT_FAMILY, 10),
                                 insertbackground=C["accent"],
                                 relief="flat", bd=0)
        search_entry.pack(fill="x", ipady=8)
        search_entry.insert(0, "搜索隔离文件...")
        search_entry.bind("<FocusIn>", lambda e: (
            search_entry.delete(0, "end") if search_entry.get() == "搜索隔离文件..." else None
        ))
        search_entry.bind("<FocusOut>", lambda e: (
            search_entry.insert(0, "搜索隔离文件...") if not search_entry.get() else None
        ))

        # 隔离文件列表（使用 Canvas + Treeview 风格的自定义列表）
        self._quar_list_frame = tk.Frame(page, bg=C["bg"])
        self._quar_list_frame.pack(fill="both", expand=True, padx=30, pady=(0, 24))

        # 空状态占位
        self._quar_empty_frame = tk.Frame(self._quar_list_frame, bg=C["bg"])
        self._quar_empty_frame.pack(fill="both", expand=True)

        # 灰色盾牌图标
        empty_canvas = tk.Canvas(self._quar_empty_frame, width=80, height=80,
                                  bg=C["bg"], highlightthickness=0)
        empty_canvas.pack(pady=(40, 12))
        cx, cy = 40, 40
        shield_pts = [cx, cy - 24, cx + 18, cy - 16, cx + 18, cy + 4,
                      cx, cy + 20, cx - 18, cy + 4, cx - 18, cy - 16]
        empty_canvas.create_polygon(shield_pts, fill=C["border"], outline="", smooth=False)
        empty_canvas.create_text(cx, cy - 2, text="?", font=(FONT_FAMILY_BOLD, 14, "bold"),
                                  fill=C["dim"])

        tk.Label(self._quar_empty_frame, text="暂无隔离文件，您的电脑很安全",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 11)).pack()

        # 实际列表容器（初始隐藏）
        self._quar_items_frame = tk.Frame(self._quar_list_frame, bg=C["bg"])

        return page

    def _refresh_quarantine(self):
        """刷新隔离箱列表"""
        if self._quar_busy:
            return
        self._quar_busy = True

        try:
            items = self.quar_mgr.list_items()
            count = len(items)

            self._quar_count_label.config(text=f"({count} 个文件)")
            # FIX-BUG-5: 移除这行，保留用户的选择状态
            # self._quar_selected.clear()

            if count == 0:
                self._quar_empty_frame.pack(fill="both", expand=True)
                self._quar_items_frame.pack_forget()
                self._quar_restore_btn.config(state="disabled")
                self._quar_delete_btn.config(state="disabled")
            else:
                self._quar_empty_frame.pack_forget()
                self._quar_items_frame.pack(fill="both", expand=True)

                # 清空并重建列表
                for w in self._quar_items_frame.winfo_children():
                    w.destroy()

                # 创建可滚动区域
                canvas = tk.Canvas(self._quar_items_frame, bg=C["bg"],
                                    highlightthickness=0)
                scrollbar = tk.Scrollbar(self._quar_items_frame, command=canvas.yview,
                                          bg=C["border"], troughcolor=C["bg"],
                                          relief="flat", bd=0)
                scroll_frame = tk.Frame(canvas, bg=C["bg"])

                scroll_frame.bind("<Configure>",
                                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
                canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
                canvas.configure(yscrollcommand=scrollbar.set)
                scrollbar.pack(side="right", fill="y")
                canvas.pack(side="left", fill="both", expand=True)

                for item in items:
                    self._create_quar_item(scroll_frame, item)

                # 更新首页隔离数
                try:
                    self._home_quar_val.config(text=str(count))
                except Exception:
                    pass
        except Exception as e:
            self._log(f"刷新隔离箱失败: {e}", "danger")
        finally:
            self._quar_busy = False

    def _create_quar_item(self, parent, item):
        """创建单条隔离文件卡片"""
        qid = item.get("qid", "")
        original_name = item.get("orig", "未知文件")
        threat_name = item.get("threat", "未知威胁")
        quar_time = item.get("time", "--")
        file_size = item.get("size", "0 KB")

        card = tk.Frame(parent, bg=C["card"],
                         highlightthickness=1,
                         highlightbackground=C["border"])
        card.pack(fill="x", pady=(0, 6))

        # 选择框
        selected_var = tk.BooleanVar(value=False)

        def _toggle_select():
            if selected_var.get():
                self._quar_selected.add(qid)
            else:
                self._quar_selected.discard(qid)
            self._update_quar_btn_state()

        cb = tk.Checkbutton(card, variable=selected_var, command=_toggle_select,
                             bg=C["card"], fg=C["text"], selectcolor=C["accent"],
                             activebackground=C["card"], activeforeground=C["text"],
                             font=(FONT_FAMILY, 10))
        cb.pack(side="left", padx=(12, 8), pady=10)

        # 文件信息
        info_frame = tk.Frame(card, bg=C["card"])
        info_frame.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=10)

        # 从完整路径提取文件名
        display_name = Path(original_name).name if original_name and original_name != "—" else "未知文件"
        tk.Label(info_frame, text=display_name, bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY_BOLD, 10, "bold"), anchor="w").pack(fill="x")

        detail_text = f"威胁: {threat_name}  |  时间: {quar_time}"
        if file_size and file_size != "—":
            detail_text += f"  |  大小: {file_size}"
        tk.Label(info_frame, text=detail_text, bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 9), anchor="w").pack(fill="x")

        # 操作按钮
        def _show_detail():
            self._show_threat_detail({
                "path": item.get("orig", ""),
                "display_path": original_name,
                "virus": threat_name,
                "time": quar_time,
            })

        self._btn(card, "详情", _show_detail, color=C["border"]).pack(
            side="right", padx=(0, 4), pady=10)

        def _restore():
            ok, msg = self.quar_mgr.restore_item(qid)
            if ok:
                self._toast.show("恢复成功", f"已恢复: {original_name}", icon_type="success")
                self._refresh_quarantine()
            else:
                self._toast.show("恢复失败", msg, icon_type="error")

        self._btn(card, "恢复", _restore, color=C["green"]).pack(
            side="right", padx=(0, 4), pady=10)

    def _update_quar_btn_state(self):
        """更新隔离箱操作按钮状态"""
        has_selection = len(self._quar_selected) > 0
        self._quar_restore_btn.config(state="normal" if has_selection else "disabled")
        self._quar_delete_btn.config(state="normal" if has_selection else "disabled")

    def _select_all_quar(self):
        """全选/取消全选隔离文件"""
        if self._quar_selected:
            self._quar_selected.clear()
        else:
            try:
                items = self.quar_mgr.list_items()
                for item in items:
                    self._quar_selected.add(item.get("qid", ""))
            except Exception:
                pass
        self._refresh_quarantine()

    def _restore_selected(self):
        """恢复选中的隔离文件"""
        if not self._quar_selected:
            return
        if not messagebox.askyesno("确认恢复",
                f"确定要恢复选中的 {len(self._quar_selected)} 个文件吗？"):
            return

        success = 0
        for qid in list(self._quar_selected):
            ok, msg = self.quar_mgr.restore_item(qid)
            if ok:
                success += 1

        self._toast.show("恢复完成",
                         f"成功恢复 {success}/{len(self._quar_selected)} 个文件",
                         icon_type="success")
        self._refresh_quarantine()

    def _delete_selected(self):
        """删除选中的隔离文件"""
        if not self._quar_selected:
            return
        if not messagebox.askyesno("确认删除",
                f"确定要永久删除选中的 {len(self._quar_selected)} 个文件吗？\n"
                "此操作不可撤销！"):
            return

        qids = list(self._quar_selected)
        ok_count, fail_count, fail_list = self.quar_mgr.delete_items(qids)
        if ok_count > 0:
            self._toast.show("删除成功", f"已删除 {ok_count}/{len(qids)} 个文件", icon_type="success")
        else:
            fail_msg = fail_list[0] if fail_list else "删除失败"
            self._toast.show("删除失败", fail_msg, icon_type="error")
        self._refresh_quarantine()

    def _on_quar_search(self):
        """隔离箱搜索"""
        if self._quar_search_timer:
            self.after_cancel(self._quar_search_timer)
        self._quar_search_timer = self.after(300, self._do_quar_search)

    def _do_quar_search(self):
        """执行隔离箱搜索"""
        keyword = self._quar_search_var.get().strip()
        if keyword == "搜索隔离文件...":
            keyword = ""

        try:
            for w in self._quar_items_frame.winfo_children():
                w.destroy()

            items = self.quar_mgr.list_items()
            if keyword:
                items = [item for item in items
                         if keyword.lower() in item.get("orig", "").lower()
                         or keyword.lower() in item.get("threat", "").lower()]

            if items:
                canvas = tk.Canvas(self._quar_items_frame, bg=C["bg"],
                                    highlightthickness=0)
                scrollbar = tk.Scrollbar(self._quar_items_frame, command=canvas.yview,
                                          bg=C["border"], troughcolor=C["bg"],
                                          relief="flat", bd=0)
                scroll_frame = tk.Frame(canvas, bg=C["bg"])
                scroll_frame.bind("<Configure>",
                                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
                canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
                canvas.configure(yscrollcommand=scrollbar.set)
                scrollbar.pack(side="right", fill="y")
                canvas.pack(side="left", fill="both", expand=True)

                for item in items:
                    self._create_quar_item(scroll_frame, item)
            else:
                tk.Label(self._quar_items_frame, text="未找到匹配的文件",
                         bg=C["bg"], fg=C["dim"],
                         font=(FONT_FAMILY, 10)).pack(pady=20)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    #  设置页面（重写版）
    # ═══════════════════════════════════════════════════════════════
    def _build_settings(self, parent):
        page = tk.Frame(parent, bg=C["bg"])
        page.pack(fill="both", expand=True)

        # 标题
        tk.Label(page, text="系统设置", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 14, "bold")).pack(anchor="w", padx=30, pady=(24, 16))

        # 设置内容可滚动区域
        settings_canvas = tk.Canvas(page, bg=C["bg"], highlightthickness=0)
        settings_scrollbar = tk.Scrollbar(page, command=settings_canvas.yview,
                                           bg=C["border"], troughcolor=C["bg"],
                                           relief="flat", bd=0)
        self._settings_scroll_frame = tk.Frame(settings_canvas, bg=C["bg"])

        self._settings_scroll_frame.bind(
            "<Configure>",
            lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))
        )
        settings_canvas.create_window((0, 0), window=self._settings_scroll_frame, anchor="nw")
        settings_canvas.configure(yscrollcommand=settings_scrollbar.set)
        settings_scrollbar.pack(side="right", fill="y")
        settings_canvas.pack(side="left", fill="both", expand=True, padx=(30, 0))

        self._settings_canvas_ref = settings_canvas

        sf = self._settings_scroll_frame

        # ── 基本设置 ──
        self._settings_section(sf, "基本设置")

        # 威胁处理方式
        action_frame = tk.Frame(sf, bg=C["card"],
                                 highlightthickness=1,
                                 highlightbackground=C["border"])
        action_frame.pack(fill="x", pady=(0, 12), ipady=12)

        tk.Label(action_frame, text="发现威胁时的处理方式",
                 bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(fill="x", padx=16, pady=(8, 4))

        for text, val in [("自动隔离（推荐）", "quarantine"), ("仅告警", "alert")]:
            tk.Radiobutton(action_frame, text=text, variable=self._virus_action,
                           value=val, bg=C["card"], fg=C["text"],
                           selectcolor=C["accent"], activebackground=C["card"],
                           activeforeground=C["text"],
                           font=(FONT_FAMILY, 10),
                           command=self._mark_settings_dirty).pack(
                anchor="w", padx=32, pady=2)

        # 开机自启动
        autostart_frame = tk.Frame(sf, bg=C["card"],
                                    highlightthickness=1,
                                    highlightbackground=C["border"])
        autostart_frame.pack(fill="x", pady=(0, 12), ipady=8)

        tk.Label(autostart_frame, text="开机自启动",
                 bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(side="left", padx=16)

        tk.Checkbutton(autostart_frame, variable=self._autostart,
                       bg=C["card"], fg=C["text"], selectcolor=C["accent"],
                       activebackground=C["card"], activeforeground=C["text"],
                       font=(FONT_FAMILY, 10),
                       command=self._mark_settings_dirty).pack(side="right", padx=16)

        # ── 实时防护 ──
        self._settings_section(sf, "实时防护")

        rt_frame = tk.Frame(sf, bg=C["card"],
                             highlightthickness=1,
                             highlightbackground=C["border"])
        rt_frame.pack(fill="x", pady=(0, 12), ipady=8)

        # FIX-BUG-2: 不再重新创建 _realtime_var，使用 __init__ 中已创建的变量
        # self._realtime_var = tk.BooleanVar(value=False)
        tk.Label(rt_frame, text="实时文件监控防护",
                 bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(side="left", padx=16)

        tk.Checkbutton(rt_frame, variable=self._realtime_var,
                       bg=C["card"], fg=C["text"], selectcolor=C["accent"],
                       activebackground=C["card"], activeforeground=C["text"],
                       font=(FONT_FAMILY, 10),
                       command=self._toggle_realtime_protection).pack(
            side="right", padx=16)

        # 监控路径说明
        rt_desc = tk.Frame(sf, bg=C["bg"])
        rt_desc.pack(fill="x", pady=(0, 12))
        tk.Label(rt_desc, text="启用后将监控指定目录中的文件变化，自动扫描新增/修改的文件",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 9), anchor="w", wraplength=600,
                 justify="left").pack(fill="x")

        # ── 扫描白名单 ──
        self._settings_section(sf, "扫描白名单")

        excl_btn_frame = tk.Frame(sf, bg=C["bg"])
        excl_btn_frame.pack(fill="x", pady=(0, 8))

        excl_count = len(self._exclusion_mgr.list_all())
        tk.Label(excl_btn_frame, text=f"当前 {excl_count} 条排除规则",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack(side="left")

        self._btn(excl_btn_frame, "管理白名单", self._show_exclusion_manager,
                  color=C["accent"]).pack(side="right")

        # ── 定时扫描 ──
        self._settings_section(sf, "定时扫描")

        sched_btn_frame = tk.Frame(sf, bg=C["bg"])
        sched_btn_frame.pack(fill="x", pady=(0, 8))

        sched_count = len(self._schedule_mgr.get_schedules())
        tk.Label(sched_btn_frame, text=f"当前 {sched_count} 个定时任务",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack(side="left")

        self._btn(sched_btn_frame, "管理定时扫描", self._show_schedule_manager,
                  color=C["accent"]).pack(side="right")

        # ── 通知设置 ──
        self._settings_section(sf, "通知设置")

        notif_frame = tk.Frame(sf, bg=C["card"],
                                highlightthickness=1,
                                highlightbackground=C["border"])
        notif_frame.pack(fill="x", pady=(0, 12), ipady=8)

        self._notif_var = tk.BooleanVar(value=True)
        tk.Label(notif_frame, text="启用桌面通知",
                 bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(side="left", padx=16)

        tk.Checkbutton(notif_frame, variable=self._notif_var,
                       bg=C["card"], fg=C["text"], selectcolor=C["accent"],
                       activebackground=C["card"], activeforeground=C["text"],
                       font=(FONT_FAMILY, 10)).pack(side="right", padx=16)

        # ── 主题设置 ──
        self._settings_section(sf, "外观设置")

        theme_frame = tk.Frame(sf, bg=C["card"],
                                highlightthickness=1,
                                highlightbackground=C["border"])
        theme_frame.pack(fill="x", pady=(0, 12), ipady=8)

        self._theme_var = tk.StringVar(value="dark")
        tk.Label(theme_frame, text="界面主题",
                 bg=C["card"], fg=C["text"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(side="left", padx=16)

        for text, val in [("暗色", "dark"), ("亮色", "light")]:
            tk.Radiobutton(theme_frame, text=text, variable=self._theme_var,
                           value=val, bg=C["card"], fg=C["text"],
                           selectcolor=C["accent"], activebackground=C["card"],
                           activeforeground=C["text"],
                           font=(FONT_FAMILY, 10)).pack(side="left", padx=8)

        tk.Label(sf, text="* 主题切换功能即将推出，当前仅支持暗色主题",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 9), anchor="w").pack(fill="x", pady=(0, 12))

        # ── 保存按钮 ──
        save_frame = tk.Frame(sf, bg=C["bg"])
        save_frame.pack(fill="x", pady=(8, 24))

        self._btn(save_frame, "保存设置", self._save_and_apply_settings,
                  color=C["accent"]).pack(side="left", padx=(0, 12))

        # 未保存提示
        self._settings_hint_lbl = tk.Label(save_frame, text="",
                                            bg=C["bg"], fg=C["warn"],
                                            font=(FONT_FAMILY, 9))
        self._settings_hint_lbl.pack(side="left", padx=8)

        return page

    def _settings_section(self, parent, title):
        """创建设置分区标题"""
        tk.Label(parent, text=title, bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 11, "bold"), anchor="w").pack(
            fill="x", pady=(12, 6))

    def _mark_settings_dirty(self):
        """标记设置已修改"""
        self._settings_dirty = True
        try:
            if hasattr(self, '_settings_hint_lbl') and self._settings_hint_lbl.winfo_exists():
                self._settings_hint_lbl.config(text="* 有未保存的更改")
        except Exception:
            pass

    def _save_and_apply_settings(self):
        """保存并应用设置 - FIX-BUG-19: 先尝试 enable/disable，成功后再写 json"""
        # FIX-BUG-19: 先应用自启动设置，成功后再保存到 json
        autostart_ok = True
        autostart_msg = ""
        if self._autostart.get():
            autostart_ok, autostart_msg = self._autostart_mgr.enable()
            if not autostart_ok:
                self._log(f"启用自启动失败: {autostart_msg}", "warn")
                self._toast.show("自启动设置失败", autostart_msg, icon_type="error")
                return
        else:
            autostart_ok, autostart_msg = self._autostart_mgr.disable()
            if not autostart_ok:
                self._log(f"禁用自启动失败: {autostart_msg}", "warn")
                self._toast.show("自启动设置失败", autostart_msg, icon_type="error")
                return

        # 自启动设置成功后再保存基本设置
        if self._save_settings():
            self._settings_dirty = False
            try:
                if hasattr(self, '_settings_hint_lbl') and self._settings_hint_lbl.winfo_exists():
                    self._settings_hint_lbl.config(text="设置已保存", fg=C["green"])
                    self.after(2000, lambda: self._settings_hint_lbl.config(text=""))
            except Exception:
                pass

            self._toast.show("设置已保存", "系统设置已成功保存并应用",
                             icon_type="success")
        else:
            self._toast.show("保存失败", "设置保存失败，请重试", icon_type="error")

    # ═══════════════════════════════════════════════════════════════
    #  关于页面（优化版）
    # ═══════════════════════════════════════════════════════════════
    def _build_about(self, parent):
        page = tk.Frame(parent, bg=C["bg"])
        page.pack(fill="both", expand=True)

        # 居中内容
        center = tk.Frame(page, bg=C["bg"])
        center.pack(expand=True)

        # Logo
        logo_canvas = tk.Canvas(center, width=100, height=100,
                                 bg=C["bg"], highlightthickness=0)
        logo_canvas.pack(pady=(0, 12))

        # 绘制盾牌 Logo
        cx, cy = 50, 50
        shield_pts = [cx, cy - 30, cx + 24, cy - 20, cx + 24, cy + 8,
                      cx, cy + 30, cx - 24, cy + 8, cx - 24, cy - 20]
        logo_canvas.create_polygon(shield_pts, fill=C["accent2"], outline="", smooth=False)
        logo_canvas.create_text(cx, cy, text="LD",
                                 font=("Consolas", 18, "bold"), fill=C["white"])

        tk.Label(center, text="量盾安全", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 20, "bold")).pack()
        tk.Label(center, text=APP_VERSION, bg=C["bg"], fg=C["accent"],
                 font=(FONT_FAMILY, 12)).pack(pady=(4, 16))

        # 信息卡片
        info_card = tk.Frame(center, bg=C["card"],
                              highlightthickness=1,
                              highlightbackground=C["border"])
        info_card.pack(fill="x", padx=60, pady=(0, 16))

        info_items = [
            ("引擎", "ClamAV (开源反病毒引擎)"),
            ("引擎版本", "ClamAV 1.x"),
            ("病毒库格式", "CVD / NDB / YARA"),
            ("构建日期", "2026"),
            ("运行平台", f"{platform.system()} {platform.release()}"),
            ("Python 版本", platform.python_version()),
            ("架构", platform.architecture()[0]),
        ]

        for label, value in info_items:
            row = tk.Frame(info_card, bg=C["card"])
            row.pack(fill="x", padx=16, pady=4)

            tk.Label(row, text=label, bg=C["card"], fg=C["dim"],
                     font=(FONT_FAMILY, 10), width=12, anchor="w").pack(side="left")
            tk.Label(row, text=value, bg=C["card"], fg=C["text"],
                     font=(FONT_FAMILY, 10), anchor="w").pack(side="left")

        # 引擎详细信息
        engine_card = tk.Frame(center, bg=C["card"],
                                highlightthickness=1,
                                highlightbackground=C["border"])
        engine_card.pack(fill="x", padx=60, pady=(0, 16))

        tk.Label(engine_card, text="引擎详细信息", bg=C["card"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 11, "bold"), anchor="w").pack(
            fill="x", padx=16, pady=(12, 8))

        self._about_engine_info = tk.Frame(engine_card, bg=C["card"])
        self._about_engine_info.pack(fill="x", padx=16, pady=(0, 12))

        # 检查引擎状态
        engine_ok, engine_msg = self.backend.check_engine()
        db_ok = self.backend.check_database()

        status_color = C["green"] if engine_ok else C["danger"]
        tk.Label(self._about_engine_info, text=f"引擎状态: ",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(side="left")
        tk.Label(self._about_engine_info, text=engine_msg,
                 bg=C["card"], fg=status_color,
                 font=(FONT_FAMILY_BOLD, 10), anchor="w").pack(side="left")

        db_status_row = tk.Frame(engine_card, bg=C["card"])
        db_status_row.pack(fill="x", padx=16, pady=(0, 12))

        db_color = C["green"] if db_ok else C["warn"]
        tk.Label(db_status_row, text="病毒库状态: ",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(side="left")
        tk.Label(db_status_row, text="已安装" if db_ok else "未安装",
                 bg=C["card"], fg=db_color,
                 font=(FONT_FAMILY_BOLD, 10), anchor="w").pack(side="left")

        # ClamAV 路径
        path_row = tk.Frame(engine_card, bg=C["card"])
        path_row.pack(fill="x", padx=16, pady=(0, 12))

        tk.Label(path_row, text="引擎路径: ",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(side="left")
        tk.Label(path_row, text=str(CLAMAV_DIR),
                 bg=C["card"], fg=C["text"],
                 font=(FONT_MONO, 9), anchor="w").pack(side="left")

        # 数据目录
        data_row = tk.Frame(engine_card, bg=C["card"])
        data_row.pack(fill="x", padx=16, pady=(0, 12))

        tk.Label(data_row, text="数据目录: ",
                 bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), anchor="w").pack(side="left")
        tk.Label(data_row, text=str(USER_DATA_DIR),
                 bg=C["card"], fg=C["text"],
                 font=(FONT_MONO, 9), anchor="w").pack(side="left")

        # 版权信息
        tk.Label(center, text="量盾安全 - 专业病毒防护软件",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack(pady=(8, 0))
        tk.Label(center, text="基于 ClamAV 开源引擎",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack()

        return page

    # ═══════════════════════════════════════════════════════════════
    #  导航栏重写（Unicode 图标 + VS Code 风格竖条指示器）
    # ═══════════════════════════════════════════════════════════════
    def _nav_buttons(self, parent):
        """重写导航按钮，使用 Unicode 图标 + 左侧 accent 竖条"""
        btns = [
            ("\U0001f6e1  首页概览", 0),
            ("\U0001f50d  病毒扫描", 1),
            ("\U0001f504  更新病毒库", 2),
            ("\U0001f4cb  扫描日志", 3),
            ("\U0001f4e6  隔离箱", 4),
            ("\u2699  系统设置", 5),
            ("\u2139  关于软件", 6),
        ]
        self._nav_btns = []
        self._nav_indicators = []  # 竖条指示器 Canvas

        for label, idx in btns:
            nav_item = tk.Frame(parent, bg=C["panel"])
            nav_item.pack(fill="x", pady=1)

            # 左侧竖条指示器（使用 Canvas 绘制 3px 宽的 accent 色竖条）
            indicator = tk.Canvas(nav_item, width=3, height=42,
                                   bg=C["panel"], highlightthickness=0)
            indicator.pack(side="left")

            b = tk.Button(
                nav_item, text=label, anchor="w",
                bg=C["panel"], fg=C["text"],
                font=(FONT_FAMILY, 11),
                relief="flat", bd=0, padx=24, pady=12,
                activebackground=C["card"], activeforeground=C["accent"],
                cursor="hand2",
                command=lambda i=idx: self._switch_tab(i)
            )
            b.pack(side="left", fill="x", expand=True)
            b.bind("<Enter>", lambda e, btn=b: self._on_nav_hover(btn, True))
            b.bind("<Leave>", lambda e, btn=b: self._on_nav_hover(btn, False))
            self._nav_btns.append(b)
            self._nav_indicators.append(indicator)

        # 底部版本信息
        tk.Label(parent, text=f"{APP_VERSION}  |  引擎: ClamAV",
                 bg=C["panel"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack(side="bottom", pady=18)

    def _update_nav_indicators(self, active_idx):
        """更新导航栏竖条指示器"""
        for i, indicator in enumerate(self._nav_indicators):
            indicator.delete("all")
            if i == active_idx:
                # 绘制 3px accent 色竖条
                indicator.create_rectangle(0, 0, 3, 42, fill=C["accent"], outline="")
                indicator.config(bg=C["panel"])
            else:
                indicator.config(bg=C["panel"])

    # ═══════════════════════════════════════════════════════════════
    #  页面切换 fade-in 效果
    # ═══════════════════════════════════════════════════════════════
    def _switch_tab(self, idx):
        """切换页面标签页（带 fade-in 效果）"""
        # FIX-SETTINGS-UI: 离开设置页时检查未保存更改
        if self._settings_dirty and idx != 5:
            if not messagebox.askyesno("未保存的更改",
                    "您在「系统设置」中有未保存的更改。\n"
                    "如果离开此页面，更改将丢失。\n\n"
                    "确定要放弃更改并离开吗？"):
                return
            self._load_settings()
            self._settings_dirty = False
            try:
                if hasattr(self, '_settings_hint_lbl') and self._settings_hint_lbl.winfo_exists():
                    self._settings_hint_lbl.config(text="")
            except Exception:
                pass

        self._nb.show(idx)

        # 更新导航按钮样式
        for i, b in enumerate(self._nav_btns):
            if i == idx:
                b.config(bg=C["card"], fg=C["accent"])
            else:
                b.config(bg=C["panel"], fg=C["text"])

        # 更新竖条指示器
        self._update_nav_indicators(idx)

        # fade-in 效果
        self._fade_in_page(idx)

        # 切换到隔离箱时刷新
        if idx == 4:
            self._refresh_quarantine()
        # 切换到设置页时同步自启状态
        if idx == 5:
            self._sync_autostart_state()

    def _fade_in_page(self, idx, step=0, total_steps=6):
        """页面切换 fade-in 效果"""
        if step >= total_steps:
            return
        try:
            frame = self._nb._frames[idx]
            if not frame.winfo_exists():
                return
            # 通过逐步改变背景色模拟淡入
            t = step / total_steps
            fade_color = _interpolate_color(C["bg"], C["bg"], t)  # 背景色不变
            # 实际上用透明度模拟：逐步从稍亮到正常
            # tkinter 不支持透明度，改用子控件可见性模拟
            # 这里简单使用 after 延迟显示，产生"渐入"感觉
            if step == 0:
                frame.pack_forget()
                self._nb.show(idx)
        except Exception:
            pass
        self.after(30, lambda: self._fade_in_page(idx, step + 1, total_steps))

    # ═══════════════════════════════════════════════════════════════
    #  按钮 hover scale 微缩放
    # ═══════════════════════════════════════════════════════════════
    def _btn(self, parent, text, cmd, color=None):
        """创建统一风格按钮（带 hover 微缩放效果）"""
        c = color or C["accent"]
        bg_normal   = c
        bg_hover    = _lighten(c, 0.15)
        fg_normal   = C["bg"] if c in (C["accent"], C["accent2"], C["green"],
                                        C["warn"], C["danger"]) else C["text"]
        fg_hover    = C["white"] if fg_normal == C["bg"] else C["white"]

        b = tk.Button(parent, text=text, command=cmd,
                      bg=bg_normal, fg=fg_normal,
                      activebackground=bg_hover, activeforeground=fg_hover,
                      font=(FONT_FAMILY, 10, "bold"),
                      relief="flat", bd=0, padx=24, pady=10,
                      cursor="hand2")

        def _on_enter(e):
            # hover 时字号从 10 切换到 11 模拟缩放
            try:
                b.config(bg=bg_hover, fg=fg_hover, font=(FONT_FAMILY, 11, "bold"))
            except Exception:
                pass

        def _on_leave(e):
            try:
                b.config(bg=bg_normal, fg=fg_normal, font=(FONT_FAMILY, 10, "bold"))
            except Exception:
                pass

        b.bind("<Enter>", _on_enter)
        b.bind("<Leave>", _on_leave)
        return b

    # ═══════════════════════════════════════════════════════════════
    #  窗口外边框和 Windows 阴影
    # ═══════════════════════════════════════════════════════════════
    def _build_ui(self):
        """构建主界面（带外边框）"""
        # === 最外层边框 Frame ===
        self._outer_border = tk.Frame(self, bg="#1a1a2e",
                                       highlightthickness=1,
                                       highlightbackground="#1a1a2e")
        self._outer_border.pack(fill="both", expand=True)

        # === 自定义标题栏 ===
        self._title_bar = tk.Frame(self._outer_border, bg=C["panel"], height=36, bd=0,
                                    highlightthickness=0)
        self._title_bar.pack(side="top", fill="x")
        self._title_bar.pack_propagate(False)

        # 左侧：标题
        title_left = tk.Frame(self._title_bar, bg=C["panel"])
        title_left.pack(side="left", fill="y")
        tk.Label(title_left, text="量盾安全", bg=C["panel"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 11, "bold")).pack(side="left", padx=(18, 6))

        # 右侧：窗口控制按钮
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
        self._content = tk.Frame(self._outer_border, bg=C["bg"])
        self._content.pack(side="top", fill="both", expand=True)

        nav = tk.Frame(self._content, bg=C["panel"], width=220)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)

        self._draw_logo(nav)
        self._nav_buttons(nav)

        self._main = tk.Frame(self._content, bg=C["bg"])
        self._main.pack(side="left", fill="both", expand=True)

        # 顶栏
        topbar = tk.Frame(self._main, bg=C["panel"], height=78)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        tk.Label(topbar, textvariable=self._status_text,
                 bg=C["panel"], fg=C["accent"],
                 font=(FONT_FAMILY, 11)).pack(side="left", padx=30, pady=21)
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

        self._nb.add_tab("首页",   self._page_home)
        self._nb.add_tab("扫描",   self._page_scan)
        self._nb.add_tab("更新",   self._page_update)
        self._nb.add_tab("日志",   self._page_log)
        self._nb.add_tab("隔离箱", self._page_quarantine)
        self._nb.add_tab("设置",   self._page_settings)
        self._nb.add_tab("关于",   self._page_about)

        self._switch_tab(0)

        # 启用 Windows 阴影
        self._enable_window_shadow()

    def _enable_window_shadow(self):
        """启用 Windows 窗口阴影效果（仅 Windows 平台）"""
        if not IS_WIN:
            return
        try:
            # 使用 DwmExtendFrameIntoClientArea 实现窗口阴影
            class MARGINS(ctypes.Structure):
                _fields_ = [
                    ("cxLeftWidth", ctypes.c_int),
                    ("cxRightWidth", ctypes.c_int),
                    ("cyTopHeight", ctypes.c_int),
                    ("cyBottomHeight", ctypes.c_int),
                ]

            # FIX-BUG-26: 使用 winfo_id() 获取正确的窗口句柄
            # 不再使用 GetForegroundWindow() 或 frame()
            hwnd = self.winfo_id()

            if hwnd:
                margins = MARGINS(-1, -1, -1, -1)
                ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(
                    ctypes.c_void_p(hwnd), ctypes.byref(margins))
        except Exception:
            # 非关键功能，失败时静默忽略
            pass

    # ═══════════════════════════════════════════════════════════════
    #  时钟更新
    # ═══════════════════════════════════════════════════════════════
    def _update_clock(self):
        """更新顶栏时钟"""
        try:
            if hasattr(self, '_time_lbl') and self._time_lbl.winfo_exists():
                self._time_lbl.config(
                    text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
                self.after(1000, self._update_clock)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    #  初始化检查
    # ═══════════════════════════════════════════════════════════════
    def _init_check(self):
        """应用启动后的初始化检查"""
        self._log("正在初始化...", "info")

        # 检查引擎
        engine_ok, engine_msg = self.backend.check_engine()
        if engine_ok:
            self._log(f"引擎: {engine_msg}", "success")
        else:
            self._log(f"引擎: {engine_msg}", "danger")
            self._toast.show("引擎异常", engine_msg, icon_type="error")

        # 检查病毒库
        db_ok = self.backend.check_database()
        if db_ok:
            self._log("病毒库: 已安装", "success")
        else:
            self._log("病毒库: 未安装，建议更新", "warn")

        # 更新首页状态
        self._update_home_status(engine_ok, db_ok, 0)

        # 刷新病毒库信息
        self._refresh_db_info()

        # 检查定时扫描
        try:
            self._schedule_mgr.check_and_run(self._run_scheduled_scan)
        except Exception as e:
            self._log(f"定时扫描检查失败: {e}", "warn")

        # FIX-BUG-4: 启动定时扫描轮询（每60秒检查一次）
        self._schedule_timer = None
        self._start_schedule_polling()

        self._status_text.set("就绪")
        self._log("初始化完成", "success")

    def _start_schedule_polling(self):
        """启动定时扫描轮询"""
        try:
            self._schedule_mgr.check_and_run(self._run_scheduled_scan)
        except Exception as e:
            self._log(f"定时扫描检查失败: {e}", "warn")
        # 每60秒检查一次
        self._schedule_timer = self.after(60000, self._start_schedule_polling)

    def _stop_schedule_polling(self):
        """停止定时扫描轮询"""
        if self._schedule_timer:
            self.after_cancel(self._schedule_timer)
            self._schedule_timer = None

    def _run_scheduled_scan(self, schedule):
        """执行定时扫描任务"""
        name = schedule.get("name", "定时扫描")
        target = schedule.get("target", "")
        scan_type = schedule.get("scan_type", "quick")

        self._log(f"执行定时任务: {name}", "info")
        self._scan_target.set(target)
        self._current_scan_mode = scan_type
        self._switch_tab(1)  # 切换到扫描页
        self.after(500, lambda: self._start_scan())

    # ═══════════════════════════════════════════════════════════════
    #  白名单管理弹窗
    # ═══════════════════════════════════════════════════════════════
    def _show_exclusion_manager(self):
        """显示扫描白名单管理弹窗"""
        excl_win = tk.Toplevel(self)
        excl_win.title("扫描白名单管理")
        excl_win.geometry("550x450")
        excl_win.resizable(True, True)
        excl_win.transient(self)
        excl_win.grab_set()
        excl_win.configure(bg=C["bg"])
        excl_win.protocol("WM_DELETE_WINDOW", lambda: excl_win.destroy())

        # 标题
        tk.Label(excl_win, text="扫描白名单管理", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 13, "bold")).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(excl_win, text="白名单中的路径将在扫描时被跳过",
                 bg=C["bg"], fg=C["dim"],
                 font=(FONT_FAMILY, 9)).pack(anchor="w", padx=20, pady=(0, 12))

        # 添加新规则
        add_frame = tk.Frame(excl_win, bg=C["bg"])
        add_frame.pack(fill="x", padx=20, pady=(0, 8))

        self._excl_new_path = tk.StringVar()
        new_entry = tk.Entry(add_frame, textvariable=self._excl_new_path,
                              bg=C["card"], fg=C["text"],
                              font=(FONT_MONO, 10),
                              insertbackground=C["accent"],
                              relief="flat", bd=0)
        new_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        new_entry.insert(0, "输入要排除的路径...")

        def _on_focus_in(e):
            if new_entry.get() == "输入要排除的路径...":
                new_entry.delete(0, "end")
        def _on_focus_out(e):
            if not new_entry.get():
                new_entry.insert(0, "输入要排除的路径...")
        new_entry.bind("<FocusIn>", _on_focus_in)
        new_entry.bind("<FocusOut>", _on_focus_out)

        def _add_exclusion():
            path = self._excl_new_path.get().strip()
            if path and path != "输入要排除的路径...":
                ok, msg = self._exclusion_mgr.add(path)
                if ok:
                    self._toast.show("已添加", f"已添加排除规则: {path}",
                                     icon_type="success")
                    self._excl_new_path.set("")
                    _refresh_excl_list()
                else:
                    self._toast.show("添加失败", msg, icon_type="error")

        self._btn(add_frame, "添加", _add_exclusion, color=C["accent"]).pack(side="left")

        # 规则列表
        list_frame = tk.Frame(excl_win, bg=C["bg"])
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        excl_canvas = tk.Canvas(list_frame, bg=C["bg"], highlightthickness=0)
        excl_scrollbar = tk.Scrollbar(list_frame, command=excl_canvas.yview,
                                       bg=C["border"], troughcolor=C["bg"],
                                       relief="flat", bd=0)
        excl_scroll_frame = tk.Frame(excl_canvas, bg=C["bg"])
        excl_scroll_frame.bind("<Configure>",
                                lambda e: excl_canvas.configure(
                                    scrollregion=excl_canvas.bbox("all")))
        excl_canvas.create_window((0, 0), window=excl_scroll_frame, anchor="nw")
        excl_canvas.configure(yscrollcommand=excl_scrollbar.set)
        excl_scrollbar.pack(side="right", fill="y")
        excl_canvas.pack(side="left", fill="both", expand=True)

        def _refresh_excl_list():
            for w in excl_scroll_frame.winfo_children():
                w.destroy()

            exclusions = self._exclusion_mgr.list_all()
            if not exclusions:
                tk.Label(excl_scroll_frame, text="暂无排除规则",
                         bg=C["bg"], fg=C["dim"],
                         font=(FONT_FAMILY, 10)).pack(pady=20)
                return

            for path in exclusions:
                row = tk.Frame(excl_scroll_frame, bg=C["card"],
                               highlightthickness=1,
                               highlightbackground=C["border"])
                row.pack(fill="x", pady=(0, 4))

                tk.Label(row, text=path, bg=C["card"], fg=C["text"],
                         font=(FONT_MONO, 9), anchor="w").pack(
                    side="left", fill="x", expand=True, padx=12, pady=8)

                def _remove(p=path):
                    ok, msg = self._exclusion_mgr.remove(p)
                    if ok:
                        self._toast.show("已移除", f"已移除: {p}", icon_type="success")
                        _refresh_excl_list()
                    else:
                        self._toast.show("移除失败", msg, icon_type="error")

                self._btn(row, "移除", _remove, color=C["danger"]).pack(
                    side="right", padx=8, pady=6)

        _refresh_excl_list()

        # 居中
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 550) // 2
        y = self.winfo_y() + (self.winfo_height() - 450) // 2
        excl_win.geometry(f"+{max(0, x)}+{max(0, y)}")

    # ═══════════════════════════════════════════════════════════════
    #  定时扫描管理弹窗
    # ═══════════════════════════════════════════════════════════════
    def _show_schedule_manager(self):
        """显示定时扫描管理弹窗"""
        sched_win = tk.Toplevel(self)
        sched_win.title("定时扫描管理")
        sched_win.geometry("600x500")
        sched_win.resizable(True, True)
        sched_win.transient(self)
        sched_win.grab_set()
        sched_win.configure(bg=C["bg"])
        sched_win.protocol("WM_DELETE_WINDOW", lambda: sched_win.destroy())

        # 标题
        tk.Label(sched_win, text="定时扫描管理", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 13, "bold")).pack(anchor="w", padx=20, pady=(16, 12))

        # 添加新任务区域
        add_card = tk.Frame(sched_win, bg=C["card"],
                             highlightthickness=1,
                             highlightbackground=C["border"])
        add_card.pack(fill="x", padx=20, pady=(0, 12))

        tk.Label(add_card, text="新建定时任务", bg=C["card"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 11, "bold")).pack(anchor="w", padx=14, pady=(12, 8))

        # 任务名称
        name_row = tk.Frame(add_card, bg=C["card"])
        name_row.pack(fill="x", padx=14, pady=(0, 6))

        tk.Label(name_row, text="任务名称:", bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), width=10, anchor="w").pack(side="left")
        sched_name_var = tk.StringVar(value="每日安全扫描")
        tk.Entry(name_row, textvariable=sched_name_var,
                 bg=C["bg"], fg=C["text"],
                 font=(FONT_FAMILY, 10),
                 insertbackground=C["accent"],
                 relief="flat", bd=0).pack(side="left", fill="x", expand=True, ipady=4)

        # 扫描目标
        target_row = tk.Frame(add_card, bg=C["card"])
        target_row.pack(fill="x", padx=14, pady=(0, 6))

        tk.Label(target_row, text="扫描目标:", bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), width=10, anchor="w").pack(side="left")
        sched_target_var = tk.StringVar(value="C:\\" if IS_WIN else "/")
        tk.Entry(target_row, textvariable=sched_target_var,
                 bg=C["bg"], fg=C["text"],
                 font=(FONT_MONO, 10),
                 insertbackground=C["accent"],
                 relief="flat", bd=0).pack(side="left", fill="x", expand=True, ipady=4)

        # 扫描类型和间隔
        type_row = tk.Frame(add_card, bg=C["card"])
        type_row.pack(fill="x", padx=14, pady=(0, 6))

        tk.Label(type_row, text="扫描类型:", bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), width=10, anchor="w").pack(side="left")
        sched_type_var = tk.StringVar(value="quick")
        for text, val in [("快速", "quick"), ("全盘", "full"), ("自定义", "custom")]:
            tk.Radiobutton(type_row, text=text, variable=sched_type_var,
                           value=val, bg=C["card"], fg=C["text"],
                           selectcolor=C["accent"], activebackground=C["card"],
                           activeforeground=C["text"],
                           font=(FONT_FAMILY, 10)).pack(side="left", padx=(0, 12))

        interval_row = tk.Frame(add_card, bg=C["card"])
        interval_row.pack(fill="x", padx=14, pady=(0, 12))

        tk.Label(interval_row, text="执行间隔:", bg=C["card"], fg=C["dim"],
                 font=(FONT_FAMILY, 10), width=10, anchor="w").pack(side="left")
        sched_interval_var = tk.StringVar(value="daily")
        for text, val in [("每天", "daily"), ("每周", "weekly"), ("每月", "monthly")]:
            tk.Radiobutton(interval_row, text=text, variable=sched_interval_var,
                           value=val, bg=C["card"], fg=C["text"],
                           selectcolor=C["accent"], activebackground=C["card"],
                           activeforeground=C["text"],
                           font=(FONT_FAMILY, 10)).pack(side="left", padx=(0, 12))

        def _add_schedule():
            name = sched_name_var.get().strip()
            target = sched_target_var.get().strip()
            scan_type = sched_type_var.get()
            interval = sched_interval_var.get()
            if not name or not target:
                self._toast.show("请填写完整", "请输入任务名称和扫描目标",
                                 icon_type="warning")
                return
            task_id = self._schedule_mgr.add_schedule(name, target, scan_type, interval)
            if task_id:
                self._toast.show("已添加", f"定时任务 '{name}' 已创建", icon_type="success")
                _refresh_sched_list()
            else:
                self._toast.show("添加失败", "无法创建定时任务", icon_type="error")

        self._btn(add_card, "创建任务", _add_schedule, color=C["accent"]).pack(
            anchor="e", padx=14, pady=(0, 14))

        # 已有任务列表
        list_frame = tk.Frame(sched_win, bg=C["bg"])
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        sched_canvas = tk.Canvas(list_frame, bg=C["bg"], highlightthickness=0)
        sched_scrollbar = tk.Scrollbar(list_frame, command=sched_canvas.yview,
                                        bg=C["border"], troughcolor=C["bg"],
                                        relief="flat", bd=0)
        sched_scroll_frame = tk.Frame(sched_canvas, bg=C["bg"])
        sched_scroll_frame.bind("<Configure>",
                                 lambda e: sched_canvas.configure(
                                     scrollregion=sched_canvas.bbox("all")))
        sched_canvas.create_window((0, 0), window=sched_scroll_frame, anchor="nw")
        sched_canvas.configure(yscrollcommand=sched_scrollbar.set)
        sched_scrollbar.pack(side="right", fill="y")
        sched_canvas.pack(side="left", fill="both", expand=True)

        def _refresh_sched_list():
            for w in sched_scroll_frame.winfo_children():
                w.destroy()

            schedules = self._schedule_mgr.get_schedules()
            if not schedules:
                tk.Label(sched_scroll_frame, text="暂无定时任务",
                         bg=C["bg"], fg=C["dim"],
                         font=(FONT_FAMILY, 10)).pack(pady=20)
                return

            interval_map = {"daily": "每天", "weekly": "每周", "monthly": "每月"}
            type_map = {"quick": "快速扫描", "full": "全盘扫描", "custom": "自定义扫描"}

            for sched in schedules:
                sid = sched.get("id", "")
                name = sched.get("name", "--")
                target = _truncate_path(sched.get("target", "--"), 30)
                scan_type = type_map.get(sched.get("scan_type", ""), sched.get("scan_type", ""))
                interval = interval_map.get(sched.get("interval_type", ""), sched.get("interval_type", ""))
                enabled = sched.get("enabled", True)

                row = tk.Frame(sched_scroll_frame, bg=C["card"],
                               highlightthickness=1,
                               highlightbackground=C["border"])
                row.pack(fill="x", pady=(0, 4))

                info = tk.Frame(row, bg=C["card"])
                info.pack(side="left", fill="x", expand=True, padx=12, pady=8)

                status_color = C["green"] if enabled else C["dim"]
                status_text = "启用" if enabled else "禁用"
                tk.Label(info, text=f"{name}  [{status_text}]",
                         bg=C["card"], fg=status_color,
                         font=(FONT_FAMILY_BOLD, 10, "bold"), anchor="w").pack(fill="x")
                tk.Label(info, text=f"{scan_type} | {interval} | {target}",
                         bg=C["card"], fg=C["dim"],
                         font=(FONT_FAMILY, 9), anchor="w").pack(fill="x")

                btn_col = tk.Frame(row, bg=C["card"])
                btn_col.pack(side="right", padx=8, pady=6)

                def _toggle(s=sid):
                    ok, msg, new_state = self._schedule_mgr.toggle_schedule(s)
                    if ok:
                        _refresh_sched_list()
                    else:
                        self._toast.show("操作失败", msg, icon_type="error")

                def _remove(s=sid):
                    if messagebox.askyesno("确认删除", "确定要删除此定时任务吗？"):
                        ok, msg = self._schedule_mgr.remove_schedule(s)
                        if ok:
                            self._toast.show("已删除", "定时任务已删除", icon_type="success")
                            _refresh_sched_list()
                        else:
                            self._toast.show("删除失败", msg, icon_type="error")

                self._btn(btn_col, "切换", _toggle, color=C["border"]).pack(
                    side="left", padx=(0, 4))
                self._btn(btn_col, "删除", _remove, color=C["danger"]).pack(
                    side="left")

        _refresh_sched_list()

        # 居中
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 600) // 2
        y = self.winfo_y() + (self.winfo_height() - 500) // 2
        sched_win.geometry(f"+{max(0, x)}+{max(0, y)}")

    # ═══════════════════════════════════════════════════════════════
    #  实时防护切换
    # ═══════════════════════════════════════════════════════════════
    def _toggle_realtime_protection(self):
        """切换实时文件监控防护"""
        if self._realtime_var.get():
            # 启用实时防护
            try:
                # 默认监控用户目录
                monitor_paths = [str(Path.home())]
                if IS_WIN:
                    desktop = Path.home() / "Desktop"
                    downloads = Path.home() / "Downloads"
                    monitor_paths.extend([str(desktop), str(downloads)])

                self._file_monitor.start(monitor_paths, self._on_realtime_threat)
                self._toast.show("实时防护已启用",
                                 f"正在监控 {len(monitor_paths)} 个目录",
                                 icon_type="success")
                self._log(f"实时防护已启用，监控 {len(monitor_paths)} 个目录", "success")

                # 更新首页状态
                self._sync_home_rt_card(True)
                # 保存设置
                self._save_settings()
            except Exception as e:
                self._realtime_var.set(False)
                self._sync_home_rt_card(False)
                self._toast.show("启用失败", str(e), icon_type="error")
                self._log(f"启用实时防护失败: {e}", "danger")
        else:
            # 禁用实时防护
            try:
                self._file_monitor.stop()
                self._toast.show("实时防护已关闭", "文件监控已停止",
                                 icon_type="warning")
                self._log("实时防护已关闭", "warn")

                self._sync_home_rt_card(False)
                # 保存设置
                self._save_settings()
            except Exception as e:
                self._toast.show("关闭失败", str(e), icon_type="error")

    def _on_realtime_threat(self, file_path, threat_name):
        """实时防护发现威胁回调"""
        self._log(f"实时防护发现威胁: {file_path} [{threat_name}]", "danger")
        self._toast.show("发现威胁",
                         f"实时防护检测到: {threat_name}\n{file_path}",
                         icon_type="error")

        # 显示威胁详情
        self.after(100, lambda: self._show_threat_detail({
            "path": file_path,
            "display_path": _truncate_path(file_path, 60),
            "virus": threat_name,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }))

    # ═══════════════════════════════════════════════════════════════
    #  Splash Screen 启动画面
    # ═══════════════════════════════════════════════════════════════
    def _show_splash(self):
        """显示启动画面"""
        splash = tk.Toplevel(self)
        splash.title("量盾安全")
        splash.geometry("400x300")
        splash.resizable(False, False)
        splash.overrideredirect(True)
        splash.configure(bg=C["bg"])

        # 居中显示
        splash.update_idletasks()
        x = (splash.winfo_screenwidth() - 400) // 2
        y = (splash.winfo_screenheight() - 300) // 2
        splash.geometry(f"+{x}+{y}")

        # Logo
        logo_canvas = tk.Canvas(splash, width=80, height=80,
                                 bg=C["bg"], highlightthickness=0)
        logo_canvas.pack(pady=(40, 12))

        cx, cy = 40, 40
        shield_pts = [cx, cy - 24, cx + 18, cy - 16, cx + 18, cy + 4,
                      cx, cy + 20, cx - 18, cy + 4, cx - 18, cy - 16]
        logo_canvas.create_polygon(shield_pts, fill=C["accent2"], outline="", smooth=False)
        logo_canvas.create_text(cx, cy, text="LD",
                                 font=("Consolas", 16, "bold"), fill=C["white"])

        tk.Label(splash, text="量盾安全", bg=C["bg"], fg=C["white"],
                 font=(FONT_FAMILY_BOLD, 18, "bold")).pack()

        # 加载文字
        self._splash_status = tk.Label(splash, text="正在加载...",
                                        bg=C["bg"], fg=C["dim"],
                                        font=(FONT_FAMILY, 10))
        self._splash_status.pack(pady=(8, 16))

        # 进度条
        splash_pb = ttk.Progressbar(splash, style="ld.Horizontal.TProgressbar",
                                     mode="determinate", maximum=100)
        splash_pb.pack(fill="x", padx=60)

        # 模拟加载进度
        def _update_splash(step):
            if step > 100:
                splash.destroy()
                return
            try:
                if splash.winfo_exists():
                    splash_pb["value"] = step
                    messages = {
                        10: "正在初始化引擎...",
                        30: "正在加载病毒库...",
                        50: "正在检查防护状态...",
                        70: "正在加载配置...",
                        90: "正在准备界面...",
                    }
                    msg = messages.get(step, "正在加载...")
                    if step in messages:
                        self._splash_status.config(text=msg)
                    splash.after(20, lambda: _update_splash(step + 2))
            except Exception:
                pass

        def _safe_destroy(win):
            try:
                if win.winfo_exists():
                    win.destroy()
            except Exception:
                pass

        _update_splash(0)

        # 2秒后强制关闭（防止卡住）
        splash.after(2000, lambda: _safe_destroy(splash))

        return splash

    # ═══════════════════════════════════════════════════════════════
    #  入口
    # ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # 创建主窗口（先创建但不显示）
    root = LiangDunApp()
    root.withdraw()

    # 显示启动画面
    splash = root._show_splash()

    # 启动画面结束后显示主窗口
    def _show_main():
        try:
            root.deiconify()
            root.lift()
            root.focus_force()
        except Exception:
            pass

    root.after(2200, _show_main)

    root.mainloop()
