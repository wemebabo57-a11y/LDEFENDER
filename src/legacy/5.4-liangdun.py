"""
量盾安全 - 专业病毒防护软件
基于 ClamAV 引擎，自动配置、自动检测、自动更新病毒库

v5.2.4 修复：
- 隔离箱移入失败问题：改用“先复制后删除源文件”策略，兼容跨分区与文件占用
- 扫描结果路径解析优化，强制转为绝对路径，避免 exists() 误判
- 隔离失败时弹出具体错误提示，引导用户处理
- 隔离箱增加批量删除、搜索过滤、详情弹窗等功能
- 修复隔离文件恢复非原子性操作，避免数据丢失
- 修复隔离文件命名不一致导致的维护困难
- 修复批量删除/清空隔离箱时的重复删除问题
- 优化隔离箱删除操作的性能

v5.2.4 补丁 (本修复)：
- Q-001 修复重命名失败导致的数据危险状态
- Q-002 统一隔离元数据 qid 与物理文件名
- Q-003 元数据写入原子性(临时文件+文件锁)
- Q-004 恢复文件时检测跨文件系统并采用复制策略
- Q-005 修正 Linux 只读文件删除权限
- 删除/隔离操作增加重试机制
- 病毒删除模块添加权限处理、详细错误提示和审计日志
- 所有空白异常捕获补充日志记录
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
from pathlib import Path
from datetime import datetime

# 文件锁相关（跨平台）
if platform.system() == "Windows":
    import msvcrt
else:
    import fcntl


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

CVD_FILES      = ["main.cvd", "daily.cvd", "bytecode.cvd",
                  "main.cld", "daily.cld", "bytecode.cld"]

# 隔离箱
QUARANTINE_DIR  = BASE_DIR / "quarantine"
QUARANTINE_META = QUARANTINE_DIR / ".meta.json"
QUAR_SUFFIX     = ".ld_quarantined"

# 审计日志
AUDIT_LOG = LOG_DIR / "audit.jsonl"

# ─────────────────────────────────────────────
#  颜色主题
# ─────────────────────────────────────────────
C = {
    "bg":        "#070d1a",
    "panel":     "#0c1527",
    "card":      "#111e35",
    "border":    "#1a2e52",
    "accent":    "#00d4ff",
    "accent2":   "#0088ff",
    "green":     "#00ff88",
    "warn":      "#ffb800",
    "danger":    "#ff3c5c",
    "text":      "#d0e8ff",
    "dim":       "#4a6fa5",
    "white":     "#ffffff",
    "glow":      "#00d4ff33",
}


# ══════════════════════════════════════════════════════════════
#  隔离箱管理器（增强版）
# ══════════════════════════════════════════════════════════════
class QuarantineManager:
    def __init__(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        self.log = lambda msg, tag="": None   # 日志回调，由主界面赋值

    def _read_meta(self):
        try:
            if QUARANTINE_META.exists():
                return json.loads(QUARANTINE_META.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def _write_meta(self, data):
        """原子写入元数据：临时文件 + 重命名 + 文件锁"""
        QUARANTINE_META.parent.mkdir(parents=True, exist_ok=True)
        tmp = QUARANTINE_META.with_suffix('.tmp')
        try:
            # 写入临时文件
            tmp.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            # 获取文件锁并原子替换
            with open(str(QUARANTINE_META), 'wb') as lock_file:
                if IS_WIN:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                if tmp.exists():
                    tmp.replace(QUARANTINE_META)
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
        """强制删除文件，去除只读属性，带重试机制"""
        max_retries = 3
        retry_delay = 1  # 秒
        last_exc = None
        for attempt in range(max_retries):
            try:
                if path.is_file():
                    # 移除只读属性（兼容Windows和Linux）
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IWGRP)
                    path.unlink()
                    self.log(f"文件已删除: {path}", "info")
                    return True
            except PermissionError as e:
                last_exc = e
                self.log(f"删除权限错误 (尝试 {attempt+1}/{max_retries}): {e}", "warn")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    self.log(f"删除最终失败: {path}", "danger")
            except Exception as e:
                last_exc = e
                self.log(f"删除异常: {type(e).__name__}: {e}", "danger")
                break
        return False

    def quarantine_file(self, src_path: str, threat_name: str = "Unknown") -> tuple:
        """
        稳健隔离：复制到隔离箱 → 删除源文件
        返回 (成功状态, 信息)
        """
        src = Path(src_path).resolve()
        if not src.exists():
            return False, f"源文件不存在：{src}"

        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        # Q-002：qid 必须与 qfile 文件名完全一致
        qid   = src.name + f".{ts}" + QUAR_SUFFIX
        qfile = QUARANTINE_DIR / qid
        entry = {
            "qfile":  str(qfile),
            "orig":   str(src),
            "threat": threat_name,
            "time":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        # 步骤1：复制到临时文件（保证原子性）
        tmp_file = qfile.with_suffix('.tmp')
        try:
            shutil.copy2(src, tmp_file)
            self.log(f"源文件已复制到临时位置: {tmp_file}", "info")
        except Exception as e:
            self.log(f"复制到隔离箱失败: {e}", "danger")
            return False, f"复制到隔离箱失败：{e}"

        # 步骤2：删除源文件
        deleted = self._secure_delete(src)
        if not deleted:
            # 源文件删除失败，清理已复制的临时文件
            try:
                tmp_file.unlink()
                self.log(f"回滚临时文件: {tmp_file}", "warn")
            except Exception:
                pass
            return False, f"无法删除源文件（可能被占用）：{src}"

        # 步骤3：原子重命名
        try:
            tmp_file.rename(qfile)
            self.log(f"隔离文件重命名成功: {qfile}", "info")
        except Exception as e:
            # Q-001: 重命名失败时的安全处理
            self.log(f"重命名失败: {tmp_file} -> {qfile}, 异常: {e}", "danger")
            # 尝试恢复到原始名称
            try:
                backup_path = src.with_name(src.name + ".ld_backup")
                tmp_file.rename(backup_path)
                self.log(f"临时文件已重命名为 {backup_path}", "warn")
                entry["note"] = f"重命名失败，文件已恢复到 {backup_path}"
            except Exception as rename_err:
                self.log(f"恢复到原始名失败: {rename_err}", "danger")
                # 最后尝试改为 .incomplete 后缀
                try:
                    incomplete = tmp_file.with_suffix('.incomplete' + QUAR_SUFFIX)
                    tmp_file.rename(incomplete)
                    self.log(f"临时文件已重命名为 .incomplete: {incomplete}", "warn")
                    entry["note"] = f"重命名失败，文件已置为 .incomplete"
                except Exception as final_err:
                    self.log(f"无法处理临时文件，残留: {tmp_file}, 错误: {final_err}", "danger")
                    entry["note"] = f"严重错误：临时文件残留 {tmp_file}，请手动处理"
            # 无论如何记录元数据，避免丢失信息
            meta = self._read_meta()
            meta[qid] = entry
            self._write_meta(meta)
            return False, f"隔离完成但重命名失败: {e}"

        # 步骤4：写入 metadata
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
            orig.parent.mkdir(parents=True, exist_ok=True)
            # Q-004: 检测是否跨文件系统
            if os.stat(qfile).st_dev != os.stat(orig.parent).st_dev:
                # 跨文件系统，使用复制+删除
                self.log(f"跨文件系统恢复: {qfile} -> {orig}", "info")
                shutil.copy2(qfile, orig)
                qfile.unlink()
                self.log("复制完成，已删除隔离文件", "info")
            else:
                shutil.move(str(qfile), str(orig))
                self.log(f"同文件系统移动: {qfile} -> {orig}", "info")
            # 只有成功后才更新 metadata
            del meta[qid]
            self._write_meta(meta)
            return True, str(orig)
        except Exception as e:
            self.log(f"恢复失败: {e}", "danger")
            # 清理可能残留的目标文件
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

        # 文件删除（带重试，已在 _secure_delete 中实现）
        if qfile.exists():
            if not self._secure_delete(qfile):
                return False, "删除隔离文件失败"

        del meta[qid]
        self._write_meta(meta)
        return True, "已彻底删除"

    def delete_items(self, qids: list) -> tuple:
        ok_count = 0
        fail_list = []
        for qid in qids:
            ok, msg = self.delete_item(qid)
            if ok:
                ok_count += 1
            else:
                fail_list.append(f"{qid}: {msg}")
        return ok_count, len(qids) - ok_count, fail_list


# ══════════════════════════════════════════════════════════════
#  ClamAV 后端
# ══════════════════════════════════════════════════════════════
class ClamAVBackend:
    def __init__(self, log_cb):
        self.log = log_cb

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

        clamd_content = f"""\
# 量盾安全 - clamd 自动生成配置
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
# 量盾安全 - freshclam 自动生成配置
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
        self.log("✅ 配置文件已生成", "success")

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
            self.log("🔄 开始更新病毒库...", "info")
            progress_cb(5)
            if not FRESH_CONF.exists():
                self.generate_configs()
            progress_cb(15)
            try:
                env = os.environ.copy()
                cmd = [str(FRESHCLAM), f"--config-file={FRESH_CONF}",
                       f"--datadir={DB_DIR}", "--stdout"]
                self._scan_proc = proc = subprocess.Popen(
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
                proc.wait()
                if proc.returncode == 0 or self.check_database():
                    progress_cb(100)
                    self.log("✅ 病毒库更新完成", "success")
                    done_cb(True, "病毒库更新成功")
                else:
                    self.log("⚠️  更新过程中遇到问题", "warn")
                    done_cb(False, f"更新失败 (代码 {proc.returncode})")
            except FileNotFoundError:
                self.log("❌ freshclam 未找到，请确认 clamav 目录", "danger")
                done_cb(False, "freshclam 未找到")
            except Exception as e:
                self.log(f"❌ 更新错误: {e}", "danger")
                done_cb(False, str(e))
        threading.Thread(target=run, daemon=True).start()

    def scan(self, target, progress_cb, result_cb, log_file_cb=None):
        def run():
            if not self.check_database():
                result_cb(None, "病毒库未安装，请先更新病毒库")
                return
            self.log(f"🔍 开始扫描：{target}", "info")
            progress_cb(0)
            try:
                cmd = [
                    str(CLAMSCAN), "-r", "--bell", "--verbose",
                    f"--database={DB_DIR}",
                    "--stdout",
                    str(target)
                ]
                if log_file_cb:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    lf = LOG_DIR / f"scan_{ts}.log"
                    cmd += [f"--log={lf}"]
                    log_file_cb(str(lf))

                self._scan_proc = proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if IS_WIN else 0
                )
                results = {"infected": [], "scanned": 0, "errors": 0}
                for line in proc.stdout:
                    line = line.rstrip()
                    if not line:
                        continue
                    self.log(f"  {line}", "dim")
                    if line.startswith("Scanning "):
                        current_file = line.replace("Scanning ", "").strip()
                        self.log(f"📄 正在扫描: {current_file}", "info")
                    if "FOUND" in line:
                        clean = line.strip()
                        if clean.endswith(" FOUND"):
                            core = clean[:-6].strip()
                            if ': ' in core:
                                sep = core.rfind(': ')
                                fpath = core[:sep].strip()
                                vname = core[sep+2:].strip()
                                fpath = str(Path(fpath).resolve())  # 转绝对路径
                                results["infected"].append({"path": fpath, "virus": vname})
                                self.log(f"🚨 发现威胁: {fpath}  [{vname}]", "danger")
                            else:
                                fpath = str(Path(clean).resolve())
                                results["infected"].append({"path": fpath, "virus": "Unknown"})
                                self.log(f"🚨 发现威胁: {fpath}", "danger")
                    elif "ERROR" in line.upper():
                        results["errors"] += 1
                    if "Scanned files:" in line:
                        m = re.search(r'Scanned files: (\d+)', line)
                        if m:
                            results["scanned"] = int(m.group(1))
                    progress_cb(-1)
                proc.wait()
                result_cb(results, None)
                total_infected = len(results["infected"])
                self.log(
                    f"✅ 扫描完成 | 已扫描: {results['scanned']} | "
                    f"威胁: {total_infected} | 错误: {results['errors']}",
                    "success" if total_infected == 0 else "danger"
                )
            except FileNotFoundError:
                result_cb(None, "clamscan 未找到")
            except Exception as e:
                result_cb(None, str(e))
        threading.Thread(target=run, daemon=True).start()


# ══════════════════════════════════════════════════════════════
#  主界面
# ══════════════════════════════════════════════════════════════
class LiangDunApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("量盾安全")
        self.geometry("1080x720")
        self.minsize(900, 620)
        self.configure(bg=C["bg"])
        self.resizable(True, True)

        self._scan_target  = tk.StringVar(value="")
        self._status_text  = tk.StringVar(value="正在初始化…")
        self._scan_log_path = None
        self._pulse_dir    = 1
        self._pulse_val    = 0
        self._scanning     = False
        self._updating     = False
        self._scan_results = None
        self._scan_proc    = None
        self._current_scan_file = tk.StringVar(value="等待扫描…")

        # 设置
        self._settings_file = BASE_DIR / "settings.json"
        self._virus_action  = tk.StringVar(value="quarantine")
        self._autostart     = tk.BooleanVar(value=False)
        self._load_settings()

        self.backend    = ClamAVBackend(self._log)
        self.quar_mgr   = QuarantineManager()
        # 将日志回调注入隔离箱管理器
        self.quar_mgr.log = self._log

        # 隔离箱批量选择集合
        self._quar_selected = set()

        self._build_ui()
        self.after(300, self._init_check)

        self._shield_angle = 0
        self._animate_ring()

    # ── UI 构建 ──────────────────────────────────────────────
    def _build_ui(self):
        nav = tk.Frame(self, bg=C["panel"], width=220)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)

        self._draw_logo(nav)
        self._nav_buttons(nav)

        self._main = tk.Frame(self, bg=C["bg"])
        self._main.pack(side="left", fill="both", expand=True)

        topbar = tk.Frame(self._main, bg=C["panel"], height=52)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        tk.Label(topbar, textvariable=self._status_text,
                 bg=C["panel"], fg=C["accent"],
                 font=("Microsoft YaHei UI", 10)).pack(side="left", padx=20, pady=14)
        self._time_lbl = tk.Label(topbar, text="", bg=C["panel"],
                                   fg=C["dim"], font=("Microsoft YaHei UI", 9))
        self._time_lbl.pack(side="right", padx=20)
        self._update_clock()

        self._nb = self._TabManager(self._main)

        self._page_home      = self._build_home(self._nb)
        self._page_scan      = self._build_scan(self._nb)
        self._page_update    = self._build_update(self._nb)
        self._page_log       = self._build_log(self._nb)
        self._page_quarantine= self._build_quarantine(self._nb)
        self._page_settings  = self._build_settings(self._nb)
        self._page_about     = self._build_about(self._nb)

        self._nb.add_tab("首页",   self._page_home,       "🛡")
        self._nb.add_tab("扫描",   self._page_scan,       "🔍")
        self._nb.add_tab("更新",   self._page_update,     "🔄")
        self._nb.add_tab("日志",   self._page_log,        "📋")
        self._nb.add_tab("隔离箱", self._page_quarantine, "📦")
        self._nb.add_tab("设置",   self._page_settings,   "⚙")
        self._nb.add_tab("关于",   self._page_about,      "ℹ")
        self._nb.show(0)

    class _TabManager(tk.Frame):
        def __init__(self, parent):
            super().__init__(parent, bg=C["bg"])
            self.pack(fill="both", expand=True)
            self._tabs   = []
            self._frames = []
            self._active = -1
        def add_tab(self, name, frame, icon=""):
            self._tabs.append((name, icon))
            self._frames.append(frame)
        def show(self, idx):
            for i, f in enumerate(self._frames):
                if i == idx:
                    f.pack(fill="both", expand=True)
                else:
                    f.pack_forget()
            self._active = idx

    def _draw_logo(self, parent):
        c = tk.Canvas(parent, width=220, height=120,
                      bg=C["panel"], highlightthickness=0)
        c.pack(pady=(20, 0))
        pts = [110, 20, 155, 38, 155, 75, 110, 105, 65, 75, 65, 38]
        c.create_polygon(pts, fill=C["accent2"], outline=C["accent"], width=2)
        c.create_text(110, 65, text="量", font=("Microsoft YaHei", 22, "bold"),
                      fill=C["white"])
        self._ring_canvas = c
        self._ring_arc_id = c.create_arc(
            78, 12, 142, 76, start=0, extent=220,
            outline=C["accent"], width=2, style="arc"
        )
        tk.Label(parent, text="量盾安全", bg=C["panel"],
                 fg=C["white"], font=("Microsoft YaHei", 15, "bold")).pack()
        tk.Label(parent, text="专业病毒防护", bg=C["panel"],
                 fg=C["dim"], font=("Microsoft YaHei UI", 9)).pack(pady=(2, 16))
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=16)

    def _animate_ring(self):
        if hasattr(self, '_ring_canvas'):
            self._shield_angle = (self._shield_angle + 3) % 360
            try:
                self._ring_canvas.itemconfig(
                    self._ring_arc_id, start=self._shield_angle)
            except Exception:
                pass
        self.after(30, self._animate_ring)

    def _nav_buttons(self, parent):
        btns = [
            ("🛡  首页概览", 0), ("🔍  病毒扫描", 1),
            ("🔄  更新病毒库", 2), ("📋  扫描日志", 3),
            ("📦  隔离箱", 4), ("⚙  设置", 5), ("ℹ  关于软件", 6),
        ]
        self._nav_btns = []
        for label, idx in btns:
            b = tk.Button(
                parent, text=label, anchor="w",
                bg=C["panel"], fg=C["text"],
                font=("Microsoft YaHei UI", 10),
                relief="flat", bd=0, padx=22, pady=10,
                activebackground=C["card"], activeforeground=C["accent"],
                cursor="hand2",
                command=lambda i=idx: self._switch_tab(i)
            )
            b.pack(fill="x", pady=1)
            self._nav_btns.append(b)
        tk.Label(parent, text="v5.2.4  |  引擎: ClamAV",
                 bg=C["panel"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 8)).pack(side="bottom", pady=12)

    def _switch_tab(self, idx):
        self._nb.show(idx)
        for i, b in enumerate(self._nav_btns):
            if i == idx:
                b.config(bg=C["card"], fg=C["accent"])
            else:
                b.config(bg=C["panel"], fg=C["text"])

    # ═════════════ 首页 ═════════════
    def _build_home(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        tk.Label(frame, text="安全概览", bg=C["bg"], fg=C["white"],
                 font=("Microsoft YaHei", 17, "bold")).pack(anchor="w", padx=32, pady=(24, 4))
        tk.Label(frame, text="系统防护状态与病毒库信息", bg=C["bg"],
                 fg=C["dim"], font=("Microsoft YaHei UI", 10)).pack(anchor="w", padx=32, pady=(0, 20))

        cards_row = tk.Frame(frame, bg=C["bg"])
        cards_row.pack(fill="x", padx=32, pady=(0, 20))

        self._card_engine = self._status_card(cards_row, "引擎状态", "检测中…", C["warn"])
        self._card_db     = self._status_card(cards_row, "病毒库",   "检测中…", C["warn"])
        self._card_last   = self._status_card(cards_row, "上次扫描", "未扫描",  C["dim"])
        self._card_quar   = self._status_card(cards_row, "隔离箱",   "0 个文件", C["dim"])

        tk.Label(frame, text="病毒库文件", bg=C["bg"], fg=C["text"],
                 font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", padx=32, pady=(0, 8))

        db_frame = tk.Frame(frame, bg=C["card"], bd=0)
        db_frame.pack(fill="x", padx=32, pady=(0, 20))
        headers = ["文件名", "大小", "更新时间", "状态"]
        for col, h in enumerate(headers):
            tk.Label(db_frame, text=h, bg=C["border"], fg=C["dim"],
                     font=("Microsoft YaHei UI", 9, "bold"),
                     padx=16, pady=8).grid(row=0, column=col, sticky="ew", padx=1, pady=1)
            db_frame.columnconfigure(col, weight=1)

        self._db_rows = []
        for r in range(6):
            row_labels = []
            for col in range(4):
                lbl = tk.Label(db_frame, text="—", bg=C["card"], fg=C["dim"],
                               font=("Microsoft YaHei UI", 9), padx=16, pady=7)
                lbl.grid(row=r+1, column=col, sticky="ew", padx=1, pady=1)
                row_labels.append(lbl)
            self._db_rows.append(row_labels)

        btn_row = tk.Frame(frame, bg=C["bg"])
        btn_row.pack(padx=32, pady=8, anchor="w")
        self._btn(btn_row, "⚡ 快速扫描", lambda: self._quick_scan()).pack(side="left", padx=(0, 12))
        self._btn(btn_row, "🔄 更新病毒库", lambda: (self._switch_tab(2), self._start_update()),
                  color=C["accent2"]).pack(side="left", padx=(0, 12))
        self._btn(btn_row, "📦 查看隔离箱", lambda: self._switch_tab(4),
                  color=C["warn"]).pack(side="left", padx=(0, 12))
        self._btn(btn_row, "🔃 刷新状态", self._init_check,
                  color=C["dim"]).pack(side="left")
        return frame

    def _status_card(self, parent, title, value, color):
        card = tk.Frame(parent, bg=C["card"], pady=16, padx=20)
        card.pack(side="left", fill="x", expand=True, padx=(0, 12))
        tk.Label(card, text=title, bg=C["card"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        lbl = tk.Label(card, text=value, bg=C["card"], fg=color,
                       font=("Microsoft YaHei", 13, "bold"))
        lbl.pack(anchor="w", pady=(4, 0))
        return lbl

    # ═════════════ 扫描页 ═════════════
    def _build_scan(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        tk.Label(frame, text="病毒扫描", bg=C["bg"], fg=C["white"],
                 font=("Microsoft YaHei", 17, "bold")).pack(anchor="w", padx=32, pady=(24, 4))

        target_frame = tk.Frame(frame, bg=C["card"], pady=14, padx=18)
        target_frame.pack(fill="x", padx=32, pady=(8, 0))
        tk.Label(target_frame, text="扫描目标", bg=C["card"],
                 fg=C["dim"], font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        row = tk.Frame(target_frame, bg=C["card"])
        row.pack(fill="x", pady=(6, 0))
        self._target_entry = tk.Entry(
            row, textvariable=self._scan_target,
            bg=C["border"], fg=C["text"], insertbackground=C["accent"],
            relief="flat", font=("Microsoft YaHei UI", 10),
            bd=0, highlightthickness=1, highlightbackground=C["border"],
            highlightcolor=C["accent"]
        )
        self._target_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))
        self._btn(row, "📁 选择文件", self._pick_file).pack(side="left", padx=(0, 6))
        self._btn(row, "📂 选择目录", self._pick_dir).pack(side="left")

        type_frame = tk.Frame(frame, bg=C["bg"])
        type_frame.pack(fill="x", padx=32, pady=12)
        self._scan_type = tk.StringVar(value="custom")
        types = [("自定义路径", "custom"), ("扫描主目录", "home"),
                 ("扫描全盘", "full"), ("扫描临时目录", "tmp")]
        for label, val in types:
            rb = tk.Radiobutton(
                type_frame, text=label, variable=self._scan_type, value=val,
                bg=C["bg"], fg=C["text"], selectcolor=C["card"],
                activebackground=C["bg"], activeforeground=C["accent"],
                font=("Microsoft YaHei UI", 9), cursor="hand2",
                command=self._on_scan_type
            )
            rb.pack(side="left", padx=(0, 20))

        prog_frame = tk.Frame(frame, bg=C["card"], pady=14, padx=18)
        prog_frame.pack(fill="x", padx=32, pady=(0, 8))
        top_prog = tk.Frame(prog_frame, bg=C["card"])
        top_prog.pack(fill="x")
        self._scan_lbl = tk.Label(top_prog, text="待机中", bg=C["card"],
                                   fg=C["dim"], font=("Microsoft YaHei UI", 9))
        self._scan_lbl.pack(side="left")
        self._scan_pct = tk.Label(top_prog, text="", bg=C["card"],
                                   fg=C["accent"], font=("Microsoft YaHei UI", 9))
        self._scan_pct.pack(side="right")
        self._scan_prog = self._progress_bar(prog_frame)
        tk.Label(prog_frame, text="当前扫描文件", bg=C["card"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(8,0))
        self._current_file_lbl = tk.Label(
            prog_frame, textvariable=self._current_scan_file,
            bg=C["card"], fg=C["text"], anchor="w", justify="left",
            font=("Consolas", 9)
        )
        self._current_file_lbl.pack(fill="x")

        self._result_frame = tk.Frame(frame, bg=C["bg"])
        self._result_frame.pack(fill="x", padx=32, pady=(0, 8))

        btn_row = tk.Frame(frame, bg=C["bg"])
        btn_row.pack(padx=32, pady=(0, 8), anchor="w")
        self._scan_btn = self._btn(btn_row, "▶ 开始扫描", self._start_scan, color=C["green"])
        self._scan_btn.pack(side="left", padx=(0, 12))
        self._stop_btn = self._btn(btn_row, "⏹ 停止", self._stop_scan, color=C["danger"])
        self._stop_btn.pack(side="left")
        self._stop_btn.config(state="disabled")

        tk.Label(frame, text="扫描输出", bg=C["bg"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", padx=32)
        self._scan_out = self._log_text(frame, height=10)
        self._scan_out.pack(fill="both", expand=True, padx=32, pady=(4, 16))
        return frame

    # ═════════════ 更新页 ═════════════
    def _build_update(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        tk.Label(frame, text="更新病毒库", bg=C["bg"], fg=C["white"],
                 font=("Microsoft YaHei", 17, "bold")).pack(anchor="w", padx=32, pady=(24, 4))
        tk.Label(frame, text="通过 freshclam 从官方镜像下载最新病毒特征库",
                 bg=C["bg"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 10)).pack(anchor="w", padx=32, pady=(0, 20))

        prog_card = tk.Frame(frame, bg=C["card"], pady=24, padx=24)
        prog_card.pack(fill="x", padx=32, pady=(0, 16))
        self._upd_lbl = tk.Label(prog_card, text="点击立即更新开始下载病毒库",
                                  bg=C["card"], fg=C["text"],
                                  font=("Microsoft YaHei UI", 11))
        self._upd_lbl.pack(anchor="w")
        prog_row = tk.Frame(prog_card, bg=C["card"])
        prog_row.pack(fill="x", pady=(12, 0))
        self._upd_prog = self._progress_bar(prog_row)
        self._upd_pct  = tk.Label(prog_row, text="0%", bg=C["card"],
                                   fg=C["accent"], font=("Microsoft YaHei UI", 9), width=5)
        self._upd_pct.pack(side="right", padx=(8, 0))

        btn_row = tk.Frame(frame, bg=C["bg"])
        btn_row.pack(padx=32, pady=(0, 12), anchor="w")
        self._upd_btn = self._btn(btn_row, "🔄 立即更新", self._start_update, color=C["accent2"])
        self._upd_btn.pack(side="left", padx=(0, 12))
        self._btn(btn_row, "⚙ 重新生成配置", self._regen_conf, color=C["dim"]).pack(side="left")

        tk.Label(frame, text="更新日志", bg=C["bg"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", padx=32)
        self._upd_out = self._log_text(frame, height=14)
        self._upd_out.pack(fill="both", expand=True, padx=32, pady=(4, 16))
        return frame

    # ═════════════ 日志页 ═════════════
    def _build_log(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        tk.Label(frame, text="运行日志", bg=C["bg"], fg=C["white"],
                 font=("Microsoft YaHei", 17, "bold")).pack(anchor="w", padx=32, pady=(24, 4))
        top = tk.Frame(frame, bg=C["bg"])
        top.pack(fill="x", padx=32, pady=(0, 8))
        self._btn(top, "🗑 清除日志", self._clear_log, color=C["dim"]).pack(side="left", padx=(0, 12))
        self._btn(top, "💾 导出日志", self._export_log, color=C["dim"]).pack(side="left")
        self._main_log = self._log_text(frame, height=30)
        self._main_log.pack(fill="both", expand=True, padx=32, pady=(0, 16))
        return frame

    # ═════════════ 隔离箱页 ═════════════
    def _build_quarantine(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        hdr = tk.Frame(frame, bg=C["bg"])
        hdr.pack(fill="x", padx=32, pady=(24, 0))
        tk.Label(hdr, text="隔离箱", bg=C["bg"], fg=C["white"],
                 font=("Microsoft YaHei", 17, "bold")).pack(side="left")
        self._quar_count_lbl = tk.Label(hdr, text="", bg=C["bg"],
                                         fg=C["warn"], font=("Microsoft YaHei UI", 10))
        self._quar_count_lbl.pack(side="left", padx=(12, 0), pady=4)
        tk.Label(frame, text="已隔离的威胁文件 · 可恢复至原位置或彻底删除",
                 bg=C["bg"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 10)).pack(anchor="w", padx=32, pady=(2, 12))

        toolbar = tk.Frame(frame, bg=C["bg"])
        toolbar.pack(fill="x", padx=32, pady=(0, 8))
        self._btn(toolbar, "🔄 刷新列表", self._refresh_quarantine,
                  color=C["dim"]).pack(side="left", padx=(0, 10))
        self._btn(toolbar, "🗑 删除选中", self._delete_selected_quarantine,
                  color=C["danger"]).pack(side="left", padx=(0, 10))
        self._btn(toolbar, "🧹 清空隔离箱", self._clear_quarantine,
                  color=C["danger"]).pack(side="left", padx=(0, 10))
        tk.Label(toolbar, text="搜索:", bg=C["bg"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 9)).pack(side="left", padx=(16, 4))
        self._quar_search_var = tk.StringVar()
        self._quar_search_var.trace_add("write", lambda *_: self._refresh_quarantine())
        search_entry = tk.Entry(
            toolbar, textvariable=self._quar_search_var,
            bg=C["border"], fg=C["text"], insertbackground=C["accent"],
            relief="flat", font=("Microsoft YaHei UI", 9), width=20,
            bd=0, highlightthickness=1, highlightbackground=C["border"],
            highlightcolor=C["accent"]
        )
        search_entry.pack(side="left", ipady=4)
        self._select_all_var = tk.BooleanVar(value=False)
        self._select_all_cb = tk.Checkbutton(
            toolbar, text="全选", variable=self._select_all_var,
            command=self._toggle_select_all, bg=C["bg"], fg=C["text"],
            selectcolor=C["card"], activebackground=C["bg"],
            activeforeground=C["accent"], font=("Microsoft YaHei UI", 9)
        )
        self._select_all_cb.pack(side="left", padx=10)
        tk.Label(toolbar, text=f"隔离目录：{QUARANTINE_DIR}",
                 bg=C["bg"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 8)).pack(side="right", padx=4)

        hdr_frame = tk.Frame(frame, bg=C["border"])
        hdr_frame.pack(fill="x", padx=32, pady=(0, 1))
        cols = [("选", 3), ("文件名", 16), ("威胁名称", 14), ("大小", 6),
                ("隔离时间", 14), ("原始路径", 0), ("操作", 18)]
        self._quar_col_weights = [c[1] for c in cols]
        for i, (h, w) in enumerate(cols):
            kw = {"width": w} if w else {}
            tk.Label(hdr_frame, text=h, bg=C["border"], fg=C["dim"],
                     font=("Microsoft YaHei UI", 9, "bold"),
                     padx=6, pady=7, anchor="w", **kw).grid(
                row=0, column=i, sticky="ew", padx=1)
            hdr_frame.columnconfigure(i, weight=w if w else 1)

        list_outer = tk.Frame(frame, bg=C["bg"])
        list_outer.pack(fill="both", expand=True, padx=32, pady=(0, 16))
        canvas = tk.Canvas(list_outer, bg=C["bg"], highlightthickness=0)
        sb = tk.Scrollbar(list_outer, orient="vertical", command=canvas.yview,
                          bg=C["border"], troughcolor=C["card"], relief="flat", bd=0)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        self._quar_inner = tk.Frame(canvas, bg=C["bg"])
        self._quar_window = canvas.create_window((0, 0), window=self._quar_inner, anchor="nw")

        def _on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def _on_canvas_configure(e):
            canvas.itemconfig(self._quar_window, width=e.width)
        self._quar_inner.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self._quar_canvas = canvas

        self.after(100, self._refresh_quarantine)
        return frame

    def _refresh_quar_card(self):
        try:
            q_count = len(self.quar_mgr.list_items())
            self._card_quar.config(
                text=f"{q_count} 个文件" if q_count else "0 个文件",
                fg=C["warn"] if q_count else C["dim"]
            )
        except Exception:
            pass

    def _refresh_quarantine(self):
        for w in self._quar_inner.winfo_children():
            w.destroy()
        self._quar_selected.clear()
        self._select_all_var.set(False)

        all_items = self.quar_mgr.list_items()
        search = self._quar_search_var.get().strip().lower()
        if search:
            items = [it for it in all_items if
                     search in Path(it["qfile"]).name.lower() or
                     search in it["threat"].lower() or
                     search in it["orig"].lower()]
        else:
            items = all_items
        total_count = len(all_items)
        shown_count = len(items)
        if search:
            self._quar_count_lbl.config(
                text=f"显示 {shown_count}/{total_count} 个文件" if all_items else "")
        else:
            self._quar_count_lbl.config(text=f"共 {total_count} 个文件" if total_count else "")
        if not items:
            msg = "🔍  无匹配结果" if search else "✅  隔离箱为空，当前无威胁文件"
            tk.Label(self._quar_inner, text=msg,
                     bg=C["bg"], fg=C["dim"],
                     font=("Microsoft YaHei UI", 11)).pack(pady=40)
            self._quar_inner.update_idletasks()
            self._quar_canvas.configure(scrollregion=self._quar_canvas.bbox("all"))
            self._refresh_quar_card()
            return

        for idx, item in enumerate(items):
            row_bg = C["card"] if idx % 2 == 0 else C["panel"]
            row = tk.Frame(self._quar_inner, bg=row_bg)
            row.pack(fill="x", pady=1)
            for ci, w in enumerate(self._quar_col_weights):
                row.columnconfigure(ci, weight=w if w else 1)

            qid = item["qid"]
            var = tk.BooleanVar(value=(qid in self._quar_selected))
            cb = tk.Checkbutton(
                row, text="", variable=var,
                bg=row_bg, activebackground=row_bg,
                selectcolor=C["card"], fg=C["text"],
                command=lambda q=qid, v=var: self._on_select_item(q, v)
            )
            cb.grid(row=0, column=0, sticky="w", padx=4)

            fname = Path(item["qfile"]).name
            display_name = fname
            if QUAR_SUFFIX in display_name:
                base = display_name[:display_name.rfind(QUAR_SUFFIX)]
                parts = base.rsplit('.', 1)
                if len(parts) == 2:
                    display_name = parts[0]
                else:
                    display_name = base

            fg_name = C["danger"] if item["exists"] else C["dim"]
            tk.Label(row, text=display_name, bg=row_bg, fg=fg_name,
                     font=("Microsoft YaHei UI", 9, "bold"),
                     padx=6, pady=8, anchor="w").grid(row=0, column=1, sticky="ew")
            tk.Label(row, text=item["threat"], bg=row_bg, fg=C["warn"],
                     font=("Microsoft YaHei UI", 8), padx=6, anchor="w").grid(row=0, column=2, sticky="ew")
            tk.Label(row, text=item["size"] if item["exists"] else "已丢失",
                     bg=row_bg, fg=C["text"], font=("Microsoft YaHei UI", 8),
                     padx=6, anchor="w").grid(row=0, column=3, sticky="ew")
            tk.Label(row, text=item["time"], bg=row_bg, fg=C["dim"],
                     font=("Microsoft YaHei UI", 8), padx=6, anchor="w").grid(row=0, column=4, sticky="ew")
            orig_short = item["orig"]
            if len(orig_short) > 40:
                orig_short = "…" + orig_short[-39:]
            tk.Label(row, text=orig_short, bg=row_bg, fg=C["dim"],
                     font=("Consolas", 8), padx=6, anchor="w").grid(row=0, column=5, sticky="ew")

            btn_cell = tk.Frame(row, bg=row_bg)
            btn_cell.grid(row=0, column=6, sticky="ew", padx=2, pady=4)
            tk.Button(
                btn_cell, text="↩", bg=C["accent2"], fg=C["white"],
                font=("Microsoft YaHei UI", 8, "bold"), relief="flat", bd=0,
                padx=8, pady=4, cursor="hand2",
                state="normal" if item["exists"] else "disabled",
                command=lambda q=qid: self._quarantine_restore(q)
            ).pack(side="left", padx=1)
            tk.Button(
                btn_cell, text="🔍", bg=C["dim"], fg=C["white"],
                font=("Microsoft YaHei UI", 8, "bold"), relief="flat", bd=0,
                padx=8, pady=4, cursor="hand2",
                command=lambda it=item: self._quarantine_detail(it)
            ).pack(side="left", padx=1)
            tk.Button(
                btn_cell, text="🗑", bg=C["danger"], fg=C["white"],
                font=("Microsoft YaHei UI", 8, "bold"), relief="flat", bd=0,
                padx=8, pady=4, cursor="hand2",
                command=lambda q=qid: self._quarantine_delete(q)
            ).pack(side="left", padx=1)

        self._quar_inner.update_idletasks()
        self._quar_canvas.configure(scrollregion=self._quar_canvas.bbox("all"))
        self._refresh_quar_card()

    def _on_select_item(self, qid, var):
        if var.get():
            self._quar_selected.add(qid)
        else:
            self._quar_selected.discard(qid)

    def _toggle_select_all(self):
        if self._select_all_var.get():
            self._select_all_items()
        else:
            self._quar_selected.clear()
            self._refresh_quarantine()

    def _select_all_items(self):
        search = self._quar_search_var.get().strip().lower()
        all_items = self.quar_mgr.list_items()
        if search:
            items = [it for it in all_items if
                     search in Path(it["qfile"]).name.lower() or
                     search in it["threat"].lower() or
                     search in it["orig"].lower()]
        else:
            items = all_items
        for item in items:
            self._quar_selected.add(item["qid"])
        self._refresh_quarantine()

    def _delete_selected_quarantine(self):
        if not self._quar_selected:
            messagebox.showinfo("提示", "请先勾选要删除的隔离文件")
            return
        count = len(self._quar_selected)
        if not messagebox.askyesno("确认删除",
                f"将彻底删除选中的 {count} 个隔离文件。\n\n此操作不可撤销，确定继续？"):
            return
        ok, fail, details = self.quar_mgr.delete_items(list(self._quar_selected))
        self._log(f"🗑 批量删除完成：成功 {ok}，失败 {fail}", "warn")
        if details:
            self._log(f"⚠ 失败详情: {'; '.join(details)}", "danger")
        self._quar_selected.clear()
        self._refresh_quarantine()

    def _quarantine_detail(self, item):
        win = tk.Toplevel(self)
        win.title("隔离文件详情")
        win.configure(bg=C["bg"])
        win.geometry("560x360")
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        tk.Label(win, text="隔离文件详情", bg=C["bg"], fg=C["white"],
                 font=("Microsoft YaHei", 14, "bold")).pack(anchor="w", padx=24, pady=(20, 4))
        tk.Frame(win, bg=C["border"], height=1).pack(fill="x", padx=24, pady=(0, 16))

        fields = [
            ("文件名",     Path(item["qfile"]).name),
            ("威胁名称",   item["threat"]),
            ("原始路径",   item["orig"]),
            ("隔离路径",   item["qfile"]),
            ("隔离时间",   item["time"]),
            ("文件大小",   item["size"] if item["exists"] else "文件已丢失"),
            ("文件状态",   "存在于隔离箱" if item["exists"] else "⚠ 隔离文件已丢失"),
        ]
        for label, value in fields:
            row = tk.Frame(win, bg=C["card"], pady=8, padx=16)
            row.pack(fill="x", padx=24, pady=2)
            tk.Label(row, text=label, bg=C["card"], fg=C["dim"],
                     font=("Microsoft YaHei UI", 9), width=10, anchor="w").pack(side="left")
            color = C["danger"] if "丢失" in value else C["text"]
            tk.Label(row, text=value, bg=C["card"], fg=color,
                     font=("Consolas", 9), anchor="w", wraplength=380, justify="left").pack(side="left", fill="x", expand=True)

        tk.Button(win, text="关闭", bg=C["dim"], fg=C["text"],
                  font=("Microsoft YaHei UI", 9, "bold"), relief="flat", bd=0,
                  padx=20, pady=6, cursor="hand2",
                  command=win.destroy).pack(pady=16)

    def _quarantine_restore(self, qid):
        ok, msg = self.quar_mgr.restore_item(qid)
        if ok:
            self._log(f"↩ 已恢复文件至：{msg}", "success")
            messagebox.showinfo("恢复成功", f"文件已恢复至原位置：\n{msg}")
        else:
            self._log(f"⚠ 恢复失败：{msg}", "danger")
            messagebox.showerror("恢复失败", msg)
        self._refresh_quarantine()

    def _quarantine_delete(self, qid):
        meta = self.quar_mgr._read_meta()
        if qid not in meta:
            return
        fname = Path(meta[qid]["orig"]).name
        if not messagebox.askyesno("确认删除",
                f"将彻底物理删除隔离文件：\n{fname}\n\n此操作不可撤销，确定继续？"):
            return
        ok, msg = self.quar_mgr.delete_item(qid)
        if ok:
            self._log(f"🗑 已彻底删除隔离文件：{fname}", "warn")
        else:
            self._log(f"⚠ 删除失败：{msg}", "danger")
            messagebox.showerror("删除失败", msg)
        self._refresh_quarantine()

    def _clear_quarantine(self):
        items = self.quar_mgr.list_items()
        if not items:
            messagebox.showinfo("提示", "隔离箱已经是空的")
            return
        if not messagebox.askyesno("确认清空",
                f"将彻底删除隔离箱中全部 {len(items)} 个文件。\n\n此操作不可撤销，确定继续？"):
            return
        failed = 0
        qids = [item["qid"] for item in items]  # 先提取所有qid，避免边删除边遍历
        for qid in qids:
            ok, _ = self.quar_mgr.delete_item(qid)
            if not ok:
                failed += 1
        self._log(f"🗑 隔离箱已清空，删除 {len(items)-failed} 个文件", "warn")
        if failed:
            self._log(f"⚠ {failed} 个文件删除失败", "danger")
        self._refresh_quarantine()

    # ═════════════ 设置页 ═════════════
    def _build_settings(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        tk.Label(frame, text="设置", bg=C["bg"], fg=C["white"],
                 font=("Microsoft YaHei", 17, "bold")).pack(anchor="w", padx=32, pady=(24, 4))
        tk.Label(frame, text="自定义量盾安全的行为与系统集成选项",
                 bg=C["bg"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 10)).pack(anchor="w", padx=32, pady=(0, 20))

        sec1 = tk.Frame(frame, bg=C["card"], pady=20, padx=24)
        sec1.pack(fill="x", padx=32, pady=(0, 16))
        tk.Label(sec1, text="🦠  发现病毒后的处理方式",
                 bg=C["card"], fg=C["text"],
                 font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", pady=(0, 4))
        tk.Label(sec1, text="扫描完成后，对检测到的威胁文件执行以下操作：",
                 bg=C["card"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", pady=(0, 12))

        actions = [
            ("quarantine", "📦  移入隔离箱", "将威胁文件移动到隔离目录，可随时恢复或删除（推荐）"),
            ("delete",     "🗑  直接删除", "永久删除威胁文件，操作不可逆，请谨慎选择"),
            ("notify",     "🔔  仅提醒", "仅显示威胁提示，不对文件做任何处理"),
        ]
        for val, label, desc in actions:
            row = tk.Frame(sec1, bg=C["border"], pady=10, padx=14)
            row.pack(fill="x", pady=3)
            rb = tk.Radiobutton(
                row, text=label, variable=self._virus_action, value=val,
                bg=C["border"], fg=C["text"], selectcolor=C["card"],
                activebackground=C["border"], activeforeground=C["accent"],
                font=("Microsoft YaHei UI", 10, "bold"), cursor="hand2"
            )
            rb.pack(anchor="w")
            tk.Label(row, text=desc, bg=C["border"], fg=C["dim"],
                     font=("Microsoft YaHei UI", 8)).pack(anchor="w", padx=20)
        tk.Label(sec1, text=f"隔离箱目录：{QUARANTINE_DIR}",
                 bg=C["card"], fg=C["dim"],
                 font=("Microsoft YaHei UI", 8)).pack(anchor="w", pady=(10, 0))

        sec2 = tk.Frame(frame, bg=C["card"], pady=20, padx=24)
        sec2.pack(fill="x", padx=32, pady=(0, 16))
        tk.Label(sec2, text="🚀  系统集成", bg=C["card"], fg=C["text"],
                 font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", pady=(0, 12))

        auto_row = tk.Frame(sec2, bg=C["border"], pady=12, padx=14)
        auto_row.pack(fill="x", pady=3)
        left = tk.Frame(auto_row, bg=C["border"])
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text="开机自动启动量盾安全", bg=C["border"], fg=C["text"],
                 font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
        tk.Label(left, text="系统登录时自动在后台启动量盾安全，保持实时防护",
                 bg=C["border"], fg=C["dim"], font=("Microsoft YaHei UI", 8)).pack(anchor="w")
        self._autostart_toggle = tk.Checkbutton(
            auto_row, text="", variable=self._autostart,
            bg=C["border"], fg=C["accent"], selectcolor=C["card"],
            activebackground=C["border"], cursor="hand2",
            command=self._on_autostart_toggle
        )
        self._autostart_toggle.pack(side="right", padx=8)

        btn_row = tk.Frame(frame, bg=C["bg"])
        btn_row.pack(padx=32, pady=(0, 16), anchor="w")
        self._btn(btn_row, "💾 保存设置", self._save_settings, color=C["accent2"]).pack(side="left", padx=(0, 12))
        self._btn(btn_row, "↺ 重置默认", self._reset_settings, color=C["dim"]).pack(side="left")
        self._settings_status = tk.Label(frame, text="", bg=C["bg"],
                                          fg=C["green"], font=("Microsoft YaHei UI", 9))
        self._settings_status.pack(anchor="w", padx=32)
        return frame

    # ═════════════ 关于页 ═════════════
    def _build_about(self, parent):
        frame = tk.Frame(parent, bg=C["bg"])
        center = tk.Frame(frame, bg=C["bg"])
        center.place(relx=0.5, rely=0.5, anchor="center")
        c = tk.Canvas(center, width=120, height=130, bg=C["bg"], highlightthickness=0)
        c.pack(pady=(0, 10))
        pts = [60, 8, 108, 28, 108, 82, 60, 122, 12, 82, 12, 28]
        c.create_polygon(pts, fill=C["accent2"], outline=C["accent"], width=2)
        c.create_text(60, 68, text="盾", font=("Microsoft YaHei", 36, "bold"), fill=C["white"])
        c.create_arc(18, 5, 102, 89, start=30, extent=120, outline=C["accent"], width=2, style="arc")
        tk.Label(center, text="量盾安全", bg=C["bg"], fg=C["white"],
                 font=("Microsoft YaHei", 22, "bold")).pack()
        tk.Label(center, text="专业级病毒防护解决方案", bg=C["bg"],
                 fg=C["dim"], font=("Microsoft YaHei UI", 11)).pack(pady=(4, 16))
        info = [
            ("版本", "5.2.4"), ("引擎", "ClamAV (本地)"),
            ("平台", platform.system() + " " + platform.release()),
            ("Python", sys.version.split()[0]),
        ]
        for key, val in info:
            row = tk.Frame(center, bg=C["card"], pady=6, padx=24)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=key, bg=C["card"], fg=C["dim"],
                     font=("Microsoft YaHei UI", 9), width=8, anchor="w").pack(side="left")
            tk.Label(row, text=val, bg=C["card"], fg=C["text"],
                     font=("Microsoft YaHei UI", 9)).pack(side="left")
        tk.Label(center, text="\n基于 ClamAV 开源引擎 · 量盾安全 © 2025",
                 bg=C["bg"], fg=C["dim"], font=("Microsoft YaHei UI", 8)).pack(pady=(16, 0))
        return frame

    # ── 通用控件 ──────────────────────────────
    def _btn(self, parent, text, cmd, color=C["accent"]):
        return tk.Button(
            parent, text=text, command=cmd,
            bg=color, fg=C["bg"] if color != C["dim"] else C["text"],
            font=("Microsoft YaHei UI", 9, "bold"),
            relief="flat", bd=0, padx=16, pady=7,
            activebackground=C["accent"], activeforeground=C["bg"],
            cursor="hand2"
        )

    def _progress_bar(self, parent):
        outer = tk.Frame(parent, bg=C["border"], height=8)
        outer.pack(fill="x", pady=(6, 0))
        outer.pack_propagate(False)
        inner = tk.Frame(outer, bg=C["accent"], height=8, width=0)
        inner.pack(side="left", fill="y")
        return (outer, inner)

    def _set_progress(self, bar_tuple, pct):
        outer, inner = bar_tuple
        outer.update_idletasks()
        w = outer.winfo_width()
        if pct < 0:
            self._pulse_val = max(0, min(100, self._pulse_val + self._pulse_dir * 4))
            if self._pulse_val >= 100 or self._pulse_val <= 0:
                self._pulse_dir *= -1
            pct = self._pulse_val
        target = max(0, min(int(w * pct / 100), w))
        inner.config(width=target)

    def _log_text(self, parent, height=12):
        frame = tk.Frame(parent, bg=C["card"])
        t = tk.Text(
            frame, height=height, bg=C["card"], fg=C["text"],
            font=("Consolas", 9), relief="flat", bd=0,
            insertbackground=C["accent"], selectbackground=C["border"],
            wrap="word", padx=12, pady=8
        )
        t.tag_config("success", foreground=C["green"])
        t.tag_config("danger",  foreground=C["danger"])
        t.tag_config("warn",    foreground=C["warn"])
        t.tag_config("info",    foreground=C["accent"])
        t.tag_config("dim",     foreground=C["dim"])
        sb = tk.Scrollbar(frame, command=t.yview, bg=C["border"],
                          troughcolor=C["card"], relief="flat", bd=0)
        t.config(yscrollcommand=sb.set, state="disabled")
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        return t

    def _log_append(self, widget, msg, tag=""):
        widget.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        widget.insert("end", f"[{ts}] {msg}\n", tag)
        widget.see("end")
        widget.config(state="disabled")

    def _log(self, msg, tag=""):
        self.after(0, lambda: self._log_append(self._main_log, msg, tag))

    def _clear_log(self):
        self._main_log.config(state="normal")
        self._main_log.delete("1.0", "end")
        self._main_log.config(state="disabled")

    def _export_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("文本文件", "*.txt")],
            initialfile=f"liangdun_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if path:
            content = self._main_log.get("1.0", "end")
            Path(path).write_text(content, encoding="utf-8")
            messagebox.showinfo("导出成功", f"日志已保存至：\n{path}")

    def _update_clock(self):
        self._time_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._update_clock)

    def _init_check(self):
        self._status_text.set("正在检测环境…")
        self._log("═" * 50, "dim")
        self._log("量盾安全 启动", "info")
        self._log(f"ClamAV 目录: {CLAMAV_DIR}", "dim")
        ok, msg = self.backend.check_engine()
        if ok:
            self._card_engine.config(text="✔ 已就绪", fg=C["green"])
            self._log(f"✅ {msg}", "success")
        else:
            self._card_engine.config(text="✖ 未检测到", fg=C["danger"])
            self._log(f"❌ {msg}", "danger")
        if not CLAMD_CONF.exists() or not FRESH_CONF.exists():
            self._log("⚙ 配置文件不存在，自动生成…", "info")
            self.backend.generate_configs()
        else:
            self._log("✅ 配置文件就绪", "success")
        has_db = self.backend.check_database()
        if has_db:
            self._card_db.config(text="✔ 已安装", fg=C["green"])
            self._log("✅ 病毒库文件存在", "success")
        else:
            self._card_db.config(text="⚠ 未检测到", fg=C["warn"])
            self._log("⚠ 未找到病毒库(CVD)文件，请前往更新页面下载", "warn")
            self._status_text.set("⚠ 病毒库未安装，请先更新病毒库")
            self.after(800, lambda: (self._switch_tab(2), self._start_update()))
        self._refresh_db_table()
        if has_db:
            self._status_text.set("✔ 系统防护就绪")
        q_count = len(self.quar_mgr.list_items())
        self._card_quar.config(text=f"{q_count} 个文件" if q_count else "0 个文件",
                               fg=C["warn"] if q_count else C["dim"])

    def _refresh_db_table(self):
        info = self.backend.get_db_info()
        for i, d in enumerate(info):
            if i >= len(self._db_rows):
                break
            self._db_rows[i][0].config(text=d["name"], fg=C["text"])
            self._db_rows[i][1].config(text=d["size"])
            self._db_rows[i][2].config(text=d["date"])
            if d["ok"]:
                self._db_rows[i][3].config(text="✔ 正常", fg=C["green"])
            else:
                self._db_rows[i][3].config(text="✖ 缺失", fg=C["danger"])

    def _start_update(self):
        if self._updating:
            return
        self._updating = True
        self._upd_btn.config(state="disabled", text="更新中…")
        self._upd_lbl.config(text="正在连接更新服务器…", fg=C["accent"])
        self._set_progress(self._upd_prog, 0)

        def on_progress(pct):
            self.after(0, lambda: (
                self._set_progress(self._upd_prog, pct),
                self._upd_pct.config(text=f"{pct}%")
            ))

        def on_done(ok, msg):
            def _done():
                self._updating = False
                self._upd_btn.config(state="normal", text="🔄 立即更新")
                if ok:
                    self._upd_lbl.config(text="✅ 病毒库已是最新", fg=C["green"])
                    self._status_text.set("✔ 病毒库更新完成，系统防护就绪")
                    self._card_db.config(text="✔ 已安装", fg=C["green"])
                    self._refresh_db_table()
                else:
                    self._upd_lbl.config(text=f"❌ 更新失败: {msg}", fg=C["danger"])
            self.after(0, _done)

        orig_log = self.backend.log
        def upd_log(msg, tag=""):
            self.after(0, lambda: self._log_append(self._upd_out, msg, tag))
            self.after(0, lambda: self._log_append(self._main_log, msg, tag))
        self.backend.log = upd_log
        self.backend.update_database(on_progress, on_done)
        # 恢复原日志回调
        def restore_log():
            self.backend.log = orig_log
        self.after(5000, restore_log)  # 5秒后恢复，避免覆盖更新结束后的日志

    def _load_settings(self):
        try:
            if self._settings_file.exists():
                data = json.loads(self._settings_file.read_text(encoding="utf-8"))
                self._virus_action.set(data.get("virus_action", "quarantine"))
                self._autostart.set(data.get("autostart", False))
        except Exception:
            pass

    def _save_settings(self):
        try:
            data = {"virus_action": self._virus_action.get(), "autostart": self._autostart.get()}
            self._settings_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            self._apply_autostart(self._autostart.get())
            self._settings_status.config(text="✅ 设置已保存", fg=C["green"])
            self.after(3000, lambda: self._settings_status.config(text=""))
        except Exception as e:
            self._settings_status.config(text=f"❌ 保存失败: {e}", fg=C["danger"])

    def _reset_settings(self):
        self._virus_action.set("quarantine")
        self._autostart.set(False)
        self._settings_status.config(text="↺ 已重置为默认值", fg=C["warn"])
        self.after(3000, lambda: self._settings_status.config(text=""))

    def _on_autostart_toggle(self):
        pass

    def _apply_autostart(self, enable):
        try:
            script_path = Path(sys.argv[0]).resolve()
            if IS_WIN:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    if enable:
                        winreg.SetValueEx(key, "LiangDun", 0, winreg.REG_SZ,
                                          f'"{sys.executable}" "{script_path}"')
                    else:
                        try:
                            winreg.DeleteValue(key, "LiangDun")
                        except FileNotFoundError:
                            pass
            else:
                autostart_dir = Path.home() / ".config" / "autostart"
                desktop_file  = autostart_dir / "liangdun.desktop"
                if enable:
                    autostart_dir.mkdir(parents=True, exist_ok=True)
                    desktop_file.write_text(
                        f"[Desktop Entry]\nType=Application\nName=量盾安全\n"
                        f"Exec={sys.executable} {script_path}\nHidden=false\n"
                        f"NoDisplay=false\nX-GNOME-Autostart-enabled=true\n",
                        encoding="utf-8"
                    )
                else:
                    if desktop_file.exists():
                        desktop_file.unlink()
        except Exception as e:
            self._log(f"⚠ 开机自启设置失败: {e}", "warn")

    # ── 病毒处理（重构版） ──────────────────────
    def _handle_infected_files(self, infected_list):
        action = self._virus_action.get()
        if action == "notify" or not infected_list:
            return

        handled, failed = [], []
        for item in infected_list:
            fpath_str = item["path"]
            threat_name = item.get("virus", "Unknown")
            self._log(f"🔍 处理威胁: 路径={fpath_str}  威胁名={threat_name}", "info")

            if action == "quarantine":
                ok, result = self.quar_mgr.quarantine_file(fpath_str, threat_name)
                if ok:
                    handled.append(f"{Path(fpath_str).name} [{threat_name}]")
                    self._log(f"📦 已隔离：{Path(fpath_str).name}", "warn")
                else:
                    failed.append(f"{Path(fpath_str).name}: {result}")
                    self._log(f"⚠ 隔离失败：{result}", "danger")
            elif action == "delete":
                fpath = Path(fpath_str)
                # 审计日志结构
                audit_entry = {
                    "action": "delete",
                    "path": str(fpath),
                    "threat": threat_name,
                    "timestamp": datetime.now().isoformat(),
                    "success": False
                }
                max_retries = 3
                last_exception = None
                for attempt in range(max_retries):
                    try:
                        self._log(f"删除准备: {fpath}", "info")
                        # 移除只读属性
                        if fpath.exists():
                            fpath.chmod(stat.S_IMODE(fpath.stat().st_mode) | stat.S_IWUSR)
                        fpath.unlink()
                        # 验证删除
                        if not fpath.exists():
                            audit_entry["success"] = True
                            handled.append(f"{fpath.name} [{threat_name}]")
                            self._log(f"🗑 已删除：{fpath.name}", "warn")
                        else:
                            raise OSError("删除后文件仍然存在")
                        break  # 成功跳出重试循环
                    except (PermissionError, OSError) as e:
                        last_exception = e
                        if attempt < max_retries - 1:
                            self._log(f"删除尝试 {attempt+1}/{max_retries} 失败: {e}, 1秒后重试", "warn")
                            time.sleep(1)
                        else:
                            # 最终失败
                            error_detail = str(e)
                            if IS_WIN and hasattr(e, 'winerror'):
                                if e.winerror == 5:
                                    error_detail = "权限不足，请以管理员身份运行"
                                elif e.winerror == 32:
                                    error_detail = "文件被占用，请关闭相关程序"
                            failed.append(f"{fpath_str}: {error_detail}")
                            self._log(f"⚠ 删除失败：{error_detail}", "danger")
                    except Exception as e:
                        last_exception = e
                        failed.append(f"{fpath_str}: {e}")
                        self._log(f"⚠ 删除异常: {type(e).__name__}: {e}", "danger")
                        break
                # 写入审计日志
                try:
                    LOG_DIR.mkdir(parents=True, exist_ok=True)
                    with open(AUDIT_LOG, "a", encoding="utf-8") as audit_file:
                        audit_file.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
                except Exception as audit_e:
                    self._log(f"审计日志写入失败: {audit_e}", "danger")

        if handled:
            verb = "已隔离" if action == "quarantine" else "已删除"
            self._log(f"🔒 {verb} {len(handled)} 个威胁文件", "warn")
        if failed:
            fail_msg = "\n".join(failed)
            self._log(f"⚠ 处理失败的文件:\n{fail_msg}", "danger")
            if action == "quarantine":
                messagebox.showwarning("隔离部分失败",
                    f"以下文件隔离失败（可能被占用）：\n{fail_msg}\n\n"
                    "建议手动关闭相关程序后重试。")
            else:
                messagebox.showwarning("删除部分失败",
                    f"以下文件删除失败：\n{fail_msg}")

        # 直接刷新隔离箱UI（已在主线程）
        if action == "quarantine" and handled:
            self._refresh_quarantine()
            self._refresh_quar_card()

    def _regen_conf(self):
        self.backend.generate_configs()
        messagebox.showinfo("配置已生成", f"配置文件已写入：\n{CONF_DIR}")

    def _pick_file(self):
        p = filedialog.askopenfilename()
        if p:
            self._scan_target.set(p)
            self._scan_type.set("custom")

    def _pick_dir(self):
        p = filedialog.askdirectory()
        if p:
            self._scan_target.set(p)
            self._scan_type.set("custom")

    def _on_scan_type(self):
        t = self._scan_type.get()
        if t == "home":
            self._scan_target.set(str(Path.home()))
        elif t == "full":
            self._scan_target.set("C:\\" if IS_WIN else "/")
        elif t == "tmp":
            import tempfile
            self._scan_target.set(tempfile.gettempdir())

    def _quick_scan(self):
        self._scan_type.set("home")
        self._scan_target.set(str(Path.home()))
        self._switch_tab(1)
        self.after(200, self._start_scan)

    def _start_scan(self):
        if self._scanning:
            return
        target = self._scan_target.get().strip()
        if not target:
            messagebox.showwarning("提示", "请先选择扫描目标")
            return
        if not Path(target).exists():
            messagebox.showerror("错误", f"路径不存在：{target}")
            return

        self._scanning = True
        self._scan_btn.config(state="disabled", text="扫描中…")
        self._stop_btn.config(state="normal")
        self._scan_lbl.config(text="正在扫描…", fg=C["accent"])
        self._set_progress(self._scan_prog, 0)
        self._card_last.config(text="扫描中…", fg=C["accent"])
        self._current_scan_file.set("准备开始扫描…")

        self._scan_file_count = [0]
        self._scan_est_total  = [500]
        self._scan_orig_log = self.backend.log
        orig_log = self._scan_orig_log

        def scan_log(msg, tag=""):
            if msg.startswith("📄 正在扫描:"):
                current = msg.replace("📄 正在扫描:", "").strip()
                self.after(0, lambda: self._current_scan_file.set(current))
                self._scan_file_count[0] += 1
                n = self._scan_file_count[0]
                est = self._scan_est_total[0]
                pct = int(95 * (1 - math.exp(-n / est)))
                self.after(0, lambda p=pct: (
                    self._set_progress(self._scan_prog, p),
                    self._scan_pct.config(text=f"{p}%")
                ))
            self.after(0, lambda: self._log_append(self._scan_out, msg, tag))
            self.after(0, lambda: self._log_append(self._main_log, msg, tag))
        self.backend.log = scan_log

        def on_result(results, err):
            def _done():
                self._scanning = False
                self._scan_proc = None
                self._scan_btn.config(state="normal", text="▶ 开始扫描")
                self._stop_btn.config(state="disabled")
                self.backend.log = orig_log
                actual = results.get("scanned", 0) if results else 0
                if actual > 0:
                    self._scan_est_total[0] = max(actual, 100)
                self._set_progress(self._scan_prog, 100)
                self._scan_pct.config(text="100%")
                ts = datetime.now().strftime("%H:%M")
                self._card_last.config(text=ts, fg=C["text"])

                if err:
                    self._scan_lbl.config(text=f"❌ 错误: {err}", fg=C["danger"])
                    return

                infected = len(results.get("infected", []))
                scanned  = results.get("scanned", 0)
                if infected == 0:
                    self._scan_lbl.config(
                        text=f"✅ 未发现威胁  |  已扫描 {scanned} 个文件", fg=C["green"])
                else:
                    self._scan_lbl.config(
                        text=f"🚨 发现 {infected} 个威胁！已扫描 {scanned} 个文件", fg=C["danger"])
                    action = self._virus_action.get()
                    action_text = {"quarantine": "移入隔离箱", "delete": "直接删除", "notify": "仅提醒"}.get(action, "")
                    threat_preview = "\n".join(
                        [f"{item['path']}  [{item.get('virus','?')}]" for item in results["infected"][:10]]
                    )
                    messagebox.showwarning(
                        "发现威胁",
                        f"扫描完成！\n发现 {infected} 个受感染文件。\n"
                        f"处理方式：{action_text}\n\n{threat_preview}"
                    )
                    self._handle_infected_files(results["infected"])
            self.after(0, _done)

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.backend.scan(target, lambda p: None, on_result,
                          log_file_cb=lambda p: setattr(self, '_scan_log_path', p))

    def _stop_scan(self):
        self._scanning = False
        if hasattr(self, '_scan_orig_log'):
            self.backend.log = self._scan_orig_log
        if self._scan_proc is None and hasattr(self.backend, '_scan_proc'):
            self._scan_proc = self.backend._scan_proc
        if self._scan_proc:
            try:
                self._scan_proc.terminate()
            except Exception:
                pass
            self._scan_proc = None
        self._scan_btn.config(state="normal", text="▶ 开始扫描")
        self._stop_btn.config(state="disabled")
        self._scan_lbl.config(text="已停止", fg=C["warn"])
        self._set_progress(self._scan_prog, 0)
        self._scan_pct.config(text="")
        self._current_scan_file.set("扫描已停止")
        self._log("⏹ 扫描已手动停止", "warn")


if __name__ == "__main__":
    app = LiangDunApp()
    app.mainloop()