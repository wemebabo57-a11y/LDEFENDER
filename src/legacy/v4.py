"""
量盾 - 系统安全工具 · 最终完整版（优化查杀性能）
功能：
1. 系统监控（CPU/内存/磁盘）
2. 进程管理（刷新、结束进程）
3. 病毒扫描（本地+在线）
4. 文件清理（临时文件、浏览器缓存、回收站）
5. 启动项管理（用户+系统，设置/取消自启）
6. 实时防护（进程监控+在线查毒+白名单，带记忆）
7. 网络监控（连接列表+搜索+结束进程）
8. 快速查杀（扫描高危目录，批量更新界面）
9. 全盘查杀（全盘扫描+进度+导出结果，批量更新）
10. 删除记忆（重置所有设置）
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import psutil
import os
import winreg
import threading
import queue
import hashlib
import sys
from datetime import datetime
import pystray
from PIL import Image, ImageDraw
import requests
import ctypes
import json
import time

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

class LiangDun(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("量盾 - 系统安全工具")
        self.geometry("1100x750")
        self.minsize(1100, 750)
        self.msg_queue = queue.Queue()
        self.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        self.create_tray()
        self.load_settings()          # 加载保存的设置
        self.create_widgets()
        self.process_ui_queue()
        self.refresh_system_info()

        # 实时防护相关变量
        self.protection_running = False
        self.protection_thread = None
        self.checked_pids = set()

        # 网络监控相关
        self.network_refresh_flag = True
        self.selected_pid = None

        # 全盘扫描相关
        self.full_scan_cancel = False
        self.full_scan_results = []

        # 如果上次防护是开启的，则自动启动
        if self.settings.get("protection_enabled", False):
            self.toggle_protection()

    def create_tray(self):
        icon = Image.new('RGB', (64, 64), '#1E3A8A')
        draw = ImageDraw.Draw(icon)
        draw.polygon([32,10,58,32,58,54,32,60,6,54,6,32], fill='white')
        self.tray = pystray.Icon(
            "量盾", icon, "量盾 - 后台运行",
            menu=pystray.Menu(
                pystray.MenuItem("显示窗口", lambda: self.after(0, self.show_window)),
                pystray.MenuItem("退出", lambda: self.after(0, self.quit_app))
            )
        )
        threading.Thread(target=self.tray.run, daemon=True).start()

    def hide_to_tray(self):
        self.withdraw()

    def show_window(self):
        self.deiconify()
        self.focus_force()

    def quit_app(self):
        self.save_settings()
        self.tray.stop()
        self.destroy()
        sys.exit()

    def ui_call(self, func):
        self.msg_queue.put(func)

    def process_ui_queue(self):
        while not self.msg_queue.empty():
            self.msg_queue.get()()
        self.after(100, self.process_ui_queue)

    # ==================== 设置记忆功能 ====================
    def load_settings(self):
        config_path = os.path.join(os.path.dirname(sys.argv[0]), "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.settings = json.load(f)
            except:
                self.settings = {}
        else:
            self.settings = {}
        if "whitelist" not in self.settings:
            self.settings["whitelist"] = []
        if "clean_options" not in self.settings:
            self.settings["clean_options"] = {"tmp": False, "cache": False, "rec": False}
        if "protection_enabled" not in self.settings:
            self.settings["protection_enabled"] = False
        self.whitelist = set(self.settings["whitelist"])

    def save_settings(self):
        self.settings["whitelist"] = list(self.whitelist)
        if hasattr(self, 'tmp_var'):
            self.settings["clean_options"] = {
                "tmp": self.tmp_var.get(),
                "cache": self.cache_var.get(),
                "rec": self.rec_var.get()
            }
        self.settings["protection_enabled"] = self.protection_running
        config_path = os.path.join(os.path.dirname(sys.argv[0]), "config.json")
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2, ensure_ascii=False)
        except:
            pass

    # ==================== 界面 ====================
    def create_widgets(self):
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(title_frame, text="🛡️ 量盾 - 系统安全工具",
            font=("Microsoft YaHei", 28, "bold"), text_color="#1E90FF").pack(pady=5)
        self.notebook = ctk.CTkTabview(self, width=1060, height=520)
        self.notebook.pack(pady=15, padx=15, fill="both", expand=True)

        self.create_monitor_tab()
        self.create_process_tab()
        self.create_scan_tab()
        self.create_clean_tab()
        self.create_startup_tab()
        self.create_realtime_tab()
        self.create_network_tab()
        self.create_quick_scan_tab()
        self.create_full_scan_tab()
        self.create_about_tab()

        status = ctk.CTkFrame(self, fg_color="#E0E0E0", corner_radius=5)
        status.pack(fill="x", padx=20, pady=10)
        self.status_label = ctk.CTkLabel(status, text="准备就绪", font=("Microsoft YaHei", 11))
        self.status_label.pack(side="left", padx=10, pady=5)

    def create_monitor_tab(self):
        p = self.notebook.add("系统监控")
        f1 = ctk.CTkFrame(p, fg_color="white", corner_radius=10)
        f1.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(f1, text="CPU 监控", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        self.cpu_bar = ctk.CTkProgressBar(f1, width=1000, height=20)
        self.cpu_bar.pack(pady=5, padx=20)
        self.cpu_label = ctk.CTkLabel(f1, text="CPU 使用率: 0%", font=("Microsoft YaHei", 13))
        self.cpu_label.pack(pady=5)
        self.cpu_text = ctk.CTkTextbox(f1, width=1000, height=80, font=("Consolas", 11))
        self.cpu_text.pack(pady=5, padx=20)

        f2 = ctk.CTkFrame(p, fg_color="white", corner_radius=10)
        f2.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(f2, text="内存监控", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        self.mem_bar = ctk.CTkProgressBar(f2, width=1000, height=20)
        self.mem_bar.pack(pady=5, padx=20)
        self.mem_label = ctk.CTkLabel(f2, text="内存使用率: 0%", font=("Microsoft YaHei", 13))
        self.mem_label.pack(pady=5)
        self.mem_text = ctk.CTkTextbox(f2, width=1000, height=80, font=("Consolas", 11))
        self.mem_text.pack(pady=5, padx=20)

        f3 = ctk.CTkFrame(p, fg_color="white", corner_radius=10)
        f3.pack(fill="both", expand=True, padx=15, pady=10)
        ctk.CTkLabel(f3, text="磁盘信息", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        self.disk_text = ctk.CTkTextbox(f3, width=1000, height=140, font=("Consolas", 11))
        self.disk_text.pack(pady=5, padx=20)

    def create_process_tab(self):
        p = self.notebook.add("进程管理")
        f = ctk.CTkFrame(p, fg_color="white", corner_radius=10)
        f.pack(fill="both", expand=True, padx=15, pady=10)
        ctk.CTkLabel(f, text="进程管理", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        self.process_text = ctk.CTkTextbox(f, width=1050, height=380, font=("Consolas", 11))
        self.process_text.pack(pady=5, padx=10)
        self.pid_entry = ctk.CTkEntry(f, placeholder_text="输入PID结束进程", width=150)
        self.pid_entry.pack(side="left", padx=10)
        ctk.CTkButton(f, text="刷新", width=120, command=self.refresh_process).pack(side="left", padx=5)
        ctk.CTkButton(f, text="结束进程", width=120, fg_color="#E53935", command=self.kill_pid).pack(side="left", padx=5)

    def create_scan_tab(self):
        p = self.notebook.add("病毒扫描")
        f = ctk.CTkFrame(p, fg_color="white", corner_radius=10)
        f.pack(fill="both", expand=True, padx=15, pady=10)
        ctk.CTkLabel(f, text="病毒扫描（本地+在线）", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        self.scan_path = ctk.CTkEntry(f, width=700, placeholder_text="选择文件/目录")
        self.scan_path.pack(pady=5, padx=10)
        ctk.CTkButton(f, text="浏览", width=120, command=self.choose_scan).pack(side="left", padx=5)
        self.scan_btn = ctk.CTkButton(f, text="开始扫描", width=120, fg_color="#E53935", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=5)
        self.online_btn = ctk.CTkButton(f, text="在线查毒", width=120, fg_color="#165DFF", command=self.online_scan)
        self.online_btn.pack(side="left", padx=5)
        self.scan_text = ctk.CTkTextbox(f, width=1050, height=320, font=("Consolas", 11))
        self.scan_text.pack(pady=10, padx=10)

    def create_clean_tab(self):
        p = self.notebook.add("文件清理")
        f = ctk.CTkFrame(p, fg_color="white", corner_radius=10)
        f.pack(fill="both", expand=True, padx=15, pady=10)
        ctk.CTkLabel(f, text="文件清理", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        self.tmp_var = ctk.BooleanVar(value=self.settings["clean_options"].get("tmp", False))
        self.cache_var = ctk.BooleanVar(value=self.settings["clean_options"].get("cache", False))
        self.rec_var = ctk.BooleanVar(value=self.settings["clean_options"].get("rec", False))
        ctk.CTkCheckBox(f, text="系统临时文件", variable=self.tmp_var).pack(anchor="w", padx=20, pady=4)
        ctk.CTkCheckBox(f, text="浏览器缓存", variable=self.cache_var).pack(anchor="w", padx=20, pady=4)
        ctk.CTkCheckBox(f, text="清空回收站", variable=self.rec_var).pack(anchor="w", padx=20, pady=4)
        ctk.CTkButton(f, text="开始清理", width=160, fg_color="#4CAF50", command=self.start_clean).pack(pady=10)
        self.clean_text = ctk.CTkTextbox(f, width=1050, height=250, font=("Consolas", 11))
        self.clean_text.pack(pady=5, padx=10)

    def create_startup_tab(self):
        p = self.notebook.add("启动项")
        f = ctk.CTkFrame(p, fg_color="white", corner_radius=10)
        f.pack(fill="both", expand=True, padx=15, pady=10)
        ctk.CTkLabel(f, text="开机启动项（用户+系统）", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        self.startup_text = ctk.CTkTextbox(f, width=1050, height=430, font=("Consolas", 11))
        self.startup_text.pack(pady=5, padx=10)
        ctk.CTkButton(f, text="刷新", width=120, command=self.load_startup).pack(side="left", padx=5)
        ctk.CTkButton(f, text="设置自启", width=120, command=self.set_self_startup).pack(side="right", padx=5)
        ctk.CTkButton(f, text="取消自启", width=120, command=self.del_self_startup).pack(side="right", padx=5)

    # ==================== 实时防护界面 ====================
    def create_realtime_tab(self):
        tab = self.notebook.add("实时防护")
        main_frame = ctk.CTkFrame(tab, fg_color="white", corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=15, pady=10)

        ctk.CTkLabel(main_frame, text="实时进程监控", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        control_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        control_frame.pack(pady=10, padx=10, fill="x")
        self.protection_btn = ctk.CTkButton(control_frame, text="启动防护", width=120, command=self.toggle_protection)
        self.protection_btn.pack(side="left", padx=5)
        ctk.CTkButton(control_frame, text="清空白名单", width=120, command=self.clear_whitelist).pack(side="left", padx=5)

        whitelist_frame = ctk.CTkFrame(main_frame, fg_color="#f0f0f0", corner_radius=8)
        whitelist_frame.pack(pady=5, padx=10, fill="x")
        ctk.CTkLabel(whitelist_frame, text="白名单管理", font=("Microsoft YaHei", 12, "bold")).pack(anchor="w", padx=10, pady=2)
        self.whitelist_entry = ctk.CTkEntry(whitelist_frame, placeholder_text="进程路径（如 C:\\Windows\\notepad.exe）", width=500)
        self.whitelist_entry.pack(side="left", padx=10, pady=5)
        ctk.CTkButton(whitelist_frame, text="添加", width=80, command=self.add_whitelist).pack(side="left", padx=2)
        ctk.CTkButton(whitelist_frame, text="删除", width=80, command=self.del_whitelist).pack(side="left", padx=2)

        log_frame = ctk.CTkFrame(main_frame, fg_color="white", corner_radius=8)
        log_frame.pack(pady=10, padx=10, fill="both", expand=True)
        ctk.CTkLabel(log_frame, text="防护日志", font=("Microsoft YaHei", 12, "bold")).pack(anchor="w", padx=10, pady=2)
        self.protection_log = ctk.CTkTextbox(log_frame, width=1050, height=260, font=("Consolas", 11))
        self.protection_log.pack(pady=5, padx=10, fill="both", expand=True)

    # ==================== 网络监控界面 ====================
    def create_network_tab(self):
        tab = self.notebook.add("网络监控")
        main_frame = ctk.CTkFrame(tab, fg_color="white", corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=15, pady=10)

        ctk.CTkLabel(main_frame, text="网络连接列表", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        search_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        search_frame.pack(pady=5, padx=10, fill="x")
        ctk.CTkLabel(search_frame, text="搜索:", font=("Microsoft YaHei", 12)).pack(side="left", padx=5)
        self.network_search = ctk.CTkEntry(search_frame, width=200, placeholder_text="进程名/PID/地址")
        self.network_search.pack(side="left", padx=5)
        self.network_search.bind('<KeyRelease>', lambda e: self.refresh_network())
        ctk.CTkButton(search_frame, text="刷新", width=80, command=self.refresh_network).pack(side="left", padx=5)
        ctk.CTkButton(search_frame, text="结束选中进程", width=120, fg_color="#E53935", command=self.kill_selected_network_process).pack(side="right", padx=5)

        self.network_text = ctk.CTkTextbox(main_frame, width=1050, height=380, font=("Consolas", 11))
        self.network_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.network_text.bind('<Button-1>', self.on_network_click)

        self.start_network_refresh()

    # ==================== 快速查杀界面 ====================
    def create_quick_scan_tab(self):
        tab = self.notebook.add("快速查杀")
        main_frame = ctk.CTkFrame(tab, fg_color="white", corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        ctk.CTkLabel(main_frame, text="快速扫描高危区域", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        
        self.quick_scan_btn = ctk.CTkButton(main_frame, text="开始快速查杀", width=150, fg_color="#E53935", command=self.start_quick_scan)
        self.quick_scan_btn.pack(pady=10)
        
        self.quick_scan_text = ctk.CTkTextbox(main_frame, width=1050, height=400, font=("Consolas", 11))
        self.quick_scan_text.pack(pady=10, padx=10, fill="both", expand=True)

    # ==================== 全盘查杀界面 ====================
    def create_full_scan_tab(self):
        tab = self.notebook.add("全盘查杀")
        main_frame = ctk.CTkFrame(tab, fg_color="white", corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        ctk.CTkLabel(main_frame, text="全盘深度扫描", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)
        
        self.full_scan_progress = ctk.CTkProgressBar(main_frame, width=1000, height=20)
        self.full_scan_progress.pack(pady=10, padx=20)
        self.full_scan_progress.set(0)
        
        self.full_scan_status = ctk.CTkLabel(main_frame, text="就绪", font=("Microsoft YaHei", 12))
        self.full_scan_status.pack(pady=5)
        
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(pady=10)
        self.full_scan_btn = ctk.CTkButton(btn_frame, text="开始全盘查杀", width=120, fg_color="#E53935", command=self.start_full_scan)
        self.full_scan_btn.pack(side="left", padx=5)
        self.cancel_full_scan_btn = ctk.CTkButton(btn_frame, text="取消", width=80, state="disabled", command=self.cancel_full_scan)
        self.cancel_full_scan_btn.pack(side="left", padx=5)
        self.export_full_scan_btn = ctk.CTkButton(btn_frame, text="导出结果", width=80, state="disabled", command=self.export_full_scan)
        self.export_full_scan_btn.pack(side="left", padx=5)
        
        self.full_scan_text = ctk.CTkTextbox(main_frame, width=1050, height=350, font=("Consolas", 11))
        self.full_scan_text.pack(pady=10, padx=10, fill="both", expand=True)

    # ==================== 关于界面 ====================
    def create_about_tab(self):
        tab = self.notebook.add("关于")
        main_frame = ctk.CTkFrame(tab, fg_color="white", corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        ctk.CTkLabel(main_frame, text="量盾 - 系统安全工具", font=("Microsoft YaHei", 24, "bold")).pack(pady=20)
        ctk.CTkLabel(main_frame, text="版本 2.0", font=("Microsoft YaHei", 14)).pack()
        ctk.CTkLabel(main_frame, text="© 2025 LiangDun Team", font=("Microsoft YaHei", 12)).pack(pady=5)
        
        ctk.CTkButton(main_frame, text="删除所有记忆（重置设置）", width=200, fg_color="#E53935", command=self.clear_all_memory).pack(pady=30)

    # ==================== 原有功能 ====================
    def refresh_system_info(self):
        try:
            cpu = psutil.cpu_percent(0.1)
            cores = psutil.cpu_count(logical=True)
            self.cpu_bar.set(cpu/100)
            self.cpu_label.configure(text=f"CPU 使用率: {cpu:.1f}%")
            self.cpu_text.delete("1.0", "end")
            self.cpu_text.insert("end", f"CPU 核心: {cores}\n")
            mem = psutil.virtual_memory()
            self.mem_bar.set(mem.percent/100)
            self.mem_label.configure(text=f"内存: {mem.percent:.1f}%")
            self.mem_text.delete("1.0", "end")
            self.mem_text.insert("end", f"总内存: {mem.total/1024**3:.1f}G\n")
            self.disk_text.delete("1.0", "end")
            for part in psutil.disk_partitions():
                try:
                    u = psutil.disk_usage(part.mountpoint)
                    s = f"{part.device} {u.total/1024**3:.1f}G 使用率 {u.percent}%\n"
                    self.disk_text.insert("end", s)
                except:
                    pass
        except:
            pass
        self.after(2000, self.refresh_system_info)

    def refresh_process(self):
        def run():
            txt = f"{'NAME':<25} {'PID':<8} {'CPU%':<8} {'MEM':<10}\n" + "-"*60 + "\n"
            for p in psutil.process_iter(['name','pid','cpu_percent','memory_info']):
                try:
                    name = p.info['name'][:22]
                    pid = p.info['pid']
                    cpu = round(p.info['cpu_percent'] or 0, 1)
                    mem = round(p.info['memory_info'].rss/(1024**2),1)
                    txt += f"{name:<25} {pid:<8} {cpu:<8} {mem:<10}MB\n"
                except:
                    continue
            self.ui_call(lambda: (self.process_text.delete("1.0","end"), self.process_text.insert("end", txt)))
        threading.Thread(target=run, daemon=True).start()

    def kill_pid(self):
        pid_text = self.pid_entry.get().strip()
        if not pid_text or not pid_text.isdigit():
            return messagebox.showwarning("提示", "请输入有效PID")
        pid = int(pid_text)
        def run():
            try:
                psutil.Process(pid).terminate()
                self.ui_call(lambda: messagebox.showinfo("成功", f"已结束 PID:{pid}"))
                self.refresh_process()
            except:
                self.ui_call(lambda: messagebox.showerror("失败", "权限不足或不存在"))
        threading.Thread(target=run, daemon=True).start()

    def choose_scan(self):
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.scan_path.delete(0,"end")
            self.scan_path.insert(0, path)

    def start_scan(self):
        path = self.scan_path.get().strip()
        if not path:
            return messagebox.showwarning("提示", "请选择路径")
        self.scan_btn.configure(state="disabled")
        def scan():
            log = f"扫描路径: {path}\n\n"
            exts = ['.exe','.dll','.bat','.cmd','.vbs','.js','.scr']
            cnt = 0
            sus = 0
            try:
                for root, _, files in os.walk(path):
                    for f in files:
                        cnt += 1
                        ext = os.path.splitext(f)[1].lower()
                        if ext in exts:
                            sus += 1
                            fp = os.path.join(root, f)
                            try:
                                with open(fp, 'rb') as obj:
                                    sha256 = hashlib.sha256(obj.read()).hexdigest()
                                log += f"⚠ {fp}\nSHA256: {sha256}\n\n"
                            except:
                                log += f"⚠ {fp}（无法读取）\n\n"
            except PermissionError:
                log += "⚠ 部分目录无权限，已跳过\n"
            log += f"扫描完成 | 文件总数:{cnt} | 可疑:{sus}"
            self.ui_call(lambda: (
                self.scan_text.delete("1.0","end"),
                self.scan_text.insert("end", log),
                self.scan_btn.configure(state="normal")
            ))
        threading.Thread(target=scan, daemon=True).start()

    def online_scan(self):
        path = self.scan_path.get().strip()
        if not path or not os.path.isfile(path):
            return messagebox.showwarning("提示", "请选择单个文件")
        self.online_btn.configure(state="disabled")
        def run():
            try:
                with open(path, 'rb') as f:
                    sha256 = hashlib.sha256(f.read()).hexdigest()
                r = requests.get(f"https://hashlookup.circl.lu/hash/{sha256}", timeout=8)
                res = r.json() if r.status_code == 200 else {"结果": "未查到"}
                log = f"文件: {path}\nSHA256: {sha256}\n\n在线查询结果:\n{res}"
            except:
                log = "在线查询失败（网络或接口限制）"
            self.ui_call(lambda: (
                self.scan_text.delete("1.0","end"),
                self.scan_text.insert("end", log),
                self.online_btn.configure(state="normal")
            ))
        threading.Thread(target=run, daemon=True).start()

    def start_clean(self):
        def run():
            log = ""
            if self.tmp_var.get():
                tmp = os.environ.get("TEMP")
                cnt = 0
                if tmp and os.path.exists(tmp):
                    for r, _, fs in os.walk(tmp):
                        for f in fs:
                            try:
                                os.remove(os.path.join(r, f))
                                cnt += 1
                            except:
                                continue
                log += f"临时文件：清理 {cnt} 个\n"
            if self.cache_var.get():
                paths = [
                    os.path.join(os.environ.get("LOCALAPPDATA"), "Google/Chrome/User Data/Default/Cache"),
                    os.path.join(os.environ.get("LOCALAPPDATA"), "Microsoft/Edge/User Data/Default/Cache")
                ]
                cnt = 0
                for p in paths:
                    if os.path.exists(p):
                        for r, _, fs in os.walk(p):
                            for f in fs:
                                try:
                                    os.remove(os.path.join(r, f))
                                    cnt += 1
                                except:
                                    continue
                log += f"浏览器缓存：清理 {cnt} 个\n"
            if self.rec_var.get():
                try:
                    ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 1)
                    log += "回收站：已清空\n"
                except:
                    log += "回收站：需要管理员权限\n"
            self.ui_call(lambda: (self.clean_text.delete("1.0","end"), self.clean_text.insert("end", log)))
        threading.Thread(target=run, daemon=True).start()

    def load_startup(self):
        def run():
            txt = "【用户启动项】\n"
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
                    i=0
                    while True:
                        try:
                            n,v,_ = winreg.EnumValue(k,i)
                            txt += f"{n}\n{v}\n\n"
                            i+=1
                        except:
                            break
            except:
                pass
            txt += "\n【系统启动项】\n"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
                    i=0
                    while True:
                        try:
                            n,v,_ = winreg.EnumValue(k,i)
                            txt += f"{n}\n{v}\n\n"
                            i+=1
                        except:
                            break
            except:
                pass
            self.ui_call(lambda: (self.startup_text.delete("1.0","end"), self.startup_text.insert("end", txt)))
        threading.Thread(target=run, daemon=True).start()

    def set_self_startup(self):
        try:
            path = os.path.abspath(sys.argv[0])
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE) as k:
                winreg.SetValueEx(k, "LiangDun", 0, winreg.REG_SZ, path)
            messagebox.showinfo("成功", "已设置开机自启")
        except:
            messagebox.showerror("失败", "权限不足")

    def del_self_startup(self):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE) as k:
                winreg.DeleteValue(k, "LiangDun")
            messagebox.showinfo("成功", "已取消自启")
        except:
            messagebox.showerror("失败", "未找到")

    # ==================== 实时防护逻辑 ====================
    def toggle_protection(self):
        if not self.protection_running:
            self.protection_running = True
            self.protection_btn.configure(text="停止防护", fg_color="#E53935")
            self.protection_thread = threading.Thread(target=self.protection_loop, daemon=True)
            self.protection_thread.start()
            self.log_protection("实时防护已启动")
        else:
            self.protection_running = False
            self.protection_btn.configure(text="启动防护", fg_color="#165DFF")
            self.log_protection("实时防护已停止")

    def protection_loop(self):
        while self.protection_running:
            try:
                current_pids = set()
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        pid = proc.info['pid']
                        exe = proc.info['exe']
                        current_pids.add(pid)
                        if pid not in self.checked_pids and exe and os.path.exists(exe):
                            self.checked_pids.add(pid)
                            if exe.lower() in [p.lower() for p in self.whitelist]:
                                continue
                            self.check_process(exe, pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                self.checked_pids = self.checked_pids.intersection(current_pids)
            except Exception as e:
                self.log_protection(f"防护循环异常: {e}")
            time.sleep(3)

    def check_process(self, exe_path, pid):
        try:
            with open(exe_path, 'rb') as f:
                file_data = f.read()
            sha256 = hashlib.sha256(file_data).hexdigest()
            try:
                r = requests.get(f"https://hashlookup.circl.lu/hash/{sha256}", timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("known") == True or data.get("malicious") == True:
                        threat = data.get("threat", "未知威胁")
                        self.ui_call(lambda: self.show_threat_alert(exe_path, pid, threat, sha256))
                        self.log_protection(f"⚠️ 威胁进程: {exe_path} (PID:{pid}) SHA256:{sha256}\n威胁类型: {threat}")
                    else:
                        self.log_protection(f"✅ 安全: {exe_path} (PID:{pid})")
                else:
                    self.log_protection(f"🔍 未收录: {exe_path} (PID:{pid})")
            except requests.RequestException:
                self.log_protection(f"🌐 在线查询失败: {exe_path} (PID:{pid})")
        except (PermissionError, IOError):
            self.log_protection(f"⚠️ 无法读取文件: {exe_path} (PID:{pid})")

    def show_threat_alert(self, exe_path, pid, threat, sha256):
        msg = f"检测到可疑进程！\n\n文件: {exe_path}\nPID: {pid}\n威胁: {threat}\nSHA256: {sha256[:16]}...\n\n是否立即结束该进程？"
        if messagebox.askyesno("安全警告", msg):
            try:
                psutil.Process(pid).terminate()
                self.log_protection(f"已终止进程: {exe_path} (PID:{pid})")
            except:
                self.log_protection(f"终止进程失败: {exe_path} (PID:{pid})")

    def log_protection(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.ui_call(lambda: self.protection_log.insert("end", f"[{timestamp}] {msg}\n"))

    def add_whitelist(self):
        path = self.whitelist_entry.get().strip()
        if not path:
            return
        if not os.path.exists(path):
            messagebox.showwarning("路径无效", "文件不存在，请检查路径")
            return
        self.whitelist.add(path)
        self.whitelist_entry.delete(0, "end")
        self.log_protection(f"已添加白名单: {path}")
        self.save_settings()

    def del_whitelist(self):
        path = self.whitelist_entry.get().strip()
        if path in self.whitelist:
            self.whitelist.remove(path)
            self.log_protection(f"已从白名单移除: {path}")
            self.whitelist_entry.delete(0, "end")
            self.save_settings()
        else:
            messagebox.showinfo("提示", "路径不在白名单中")

    def clear_whitelist(self):
        if messagebox.askyesno("确认", "清空所有白名单？"):
            self.whitelist.clear()
            self.log_protection("白名单已清空")
            self.save_settings()

    # ==================== 网络监控逻辑 ====================
    def start_network_refresh(self):
        def refresh_loop():
            while self.network_refresh_flag:
                self.refresh_network()
                time.sleep(2)
        threading.Thread(target=refresh_loop, daemon=True).start()

    def refresh_network(self):
        def worker():
            try:
                connections = psutil.net_connections(kind='inet')
                keyword = self.network_search.get().strip().lower()
                lines = []
                lines.append(f"{'进程名':<20} {'PID':<8} {'本地地址':<25} {'远程地址':<25} {'状态':<15} {'协议':<5}")
                lines.append("-" * 120)
                for conn in connections:
                    try:
                        pid = conn.pid
                        if pid is None:
                            continue
                        proc = psutil.Process(pid)
                        name = proc.name()
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "0.0.0.0:0"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "0.0.0.0:0"
                        status = conn.status or "UNKNOWN"
                        proto = "TCP" if conn.type == 1 else "UDP"
                        if keyword:
                            if (keyword not in name.lower() and keyword not in str(pid) and
                                keyword not in laddr and keyword not in raddr):
                                continue
                        lines.append(f"{name[:20]:<20} {pid:<8} {laddr:<25} {raddr:<25} {status:<15} {proto:<5}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                display = "\n".join(lines)
                self.ui_call(lambda: (self.network_text.delete("1.0", "end"), self.network_text.insert("end", display)))
            except Exception as e:
                self.ui_call(lambda: self.network_text.insert("end", f"获取网络连接失败: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    def on_network_click(self, event):
        try:
            index = self.network_text.index("@%d,%d" % (event.x, event.y))
            line = self.network_text.get(f"{index} linestart", f"{index} lineend")
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                self.selected_pid = int(parts[1])
            else:
                self.selected_pid = None
        except:
            self.selected_pid = None

    def kill_selected_network_process(self):
        if hasattr(self, 'selected_pid') and self.selected_pid:
            try:
                psutil.Process(self.selected_pid).terminate()
                messagebox.showinfo("成功", f"已终止进程 PID:{self.selected_pid}")
                self.refresh_network()
            except Exception as e:
                messagebox.showerror("失败", f"无法终止进程: {e}")
        else:
            messagebox.showwarning("提示", "请先点击选中一个连接")

    # ==================== 快速查杀（优化批量更新，实时显示路径） ====================
    def start_quick_scan(self):
        def scan():
            self.ui_call(lambda: (self.quick_scan_text.delete("1.0", "end"), self.quick_scan_btn.configure(state="disabled")))
            log_buffer = []
            log = "快速查杀开始...\n\n"
            high_risk_dirs = [
                os.environ.get("TEMP"),
                os.path.join(os.environ.get("USERPROFILE"), "Downloads"),
                os.path.join(os.environ.get("USERPROFILE"), "Desktop"),
                os.environ.get("APPDATA"),
                os.environ.get("LOCALAPPDATA"),
                "C:\\Windows\\Temp"
            ]
            exts = ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.scr', '.ps1', '.jar']
            found = []
            for d in high_risk_dirs:
                if d and os.path.exists(d):
                    log_buffer.append(f"扫描目录: {d}\n")
                    for root, _, files in os.walk(d):
                        for f in files:
                            # 实时显示当前文件
                            current_file = os.path.join(root, f)
                            self.ui_call(lambda path=current_file: self.status_label.configure(text=f"正在扫描: {path}"))
                            if any(f.lower().endswith(ext) for ext in exts):
                                fp = os.path.join(root, f)
                                try:
                                    size = os.path.getsize(fp)
                                    if size < 10 * 1024 * 1024:  # 小于10M
                                        with open(fp, 'rb') as obj:
                                            sha256 = hashlib.sha256(obj.read()).hexdigest()
                                        threat = self.check_hash_online(sha256)
                                        if threat:
                                            found.append((fp, sha256, threat))
                                            log_buffer.append(f"⚠ 可疑文件: {fp}\nSHA256: {sha256}\n威胁: {threat}\n\n")
                                        else:
                                            log_buffer.append(f"✅ 安全: {fp}\n")
                                except:
                                    log_buffer.append(f"❌ 无法读取: {fp}\n")
                    # 每处理完一个目录，批量更新界面
                    if log_buffer:
                        self.ui_call(lambda buff=log_buffer.copy(): self.quick_scan_text.insert("end", "".join(buff)))
                        log_buffer.clear()
            log_buffer.append(f"\n快速查杀完成。发现可疑文件: {len(found)}")
            self.ui_call(lambda: (self.quick_scan_text.insert("end", "".join(log_buffer)), self.quick_scan_btn.configure(state="normal"), self.status_label.configure(text="准备就绪")))
        threading.Thread(target=scan, daemon=True).start()

    # ==================== 全盘查杀（优化批量更新，只显示可疑文件，实时显示路径） ====================
    def start_full_scan(self):
        self.full_scan_cancel = False
        self.full_scan_btn.configure(state="disabled")
        self.cancel_full_scan_btn.configure(state="normal")
        self.export_full_scan_btn.configure(state="disabled")
        self.full_scan_text.delete("1.0", "end")
        self.full_scan_progress.set(0)
        
        def scan():
            drives = [d.device for d in psutil.disk_partitions() if 'fixed' in d.opts]
            # 计算总文件数
            total_files = 0
            self.ui_call(lambda: self.full_scan_status.configure(text="正在计算文件总数..."))
            for drive in drives:
                if self.full_scan_cancel:
                    break
                for root, _, files in os.walk(drive):
                    total_files += len(files)
            if self.full_scan_cancel:
                self.ui_call(lambda: self.full_scan_status.configure(text="扫描已取消"))
                return
            
            processed = 0
            suspicious = []
            exts = ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.scr', '.ps1', '.jar']
            buffer = []
            last_update = 0
            update_interval = 50      # 每50个文件更新一次文本
            progress_interval = 500   # 每500个文件更新一次进度条
            
            self.ui_call(lambda: self.full_scan_status.configure(text=f"开始扫描 {total_files} 个文件..."))
            
            for drive in drives:
                if self.full_scan_cancel:
                    break
                for root, _, files in os.walk(drive):
                    if self.full_scan_cancel:
                        break
                    for f in files:
                        if self.full_scan_cancel:
                            break
                        processed += 1
                        # 实时显示当前文件
                        current_file = os.path.join(root, f)
                        self.ui_call(lambda path=current_file: self.status_label.configure(text=f"正在扫描: {path}"))
                        if processed - last_update >= update_interval:
                            if buffer:
                                self.ui_call(lambda buff=buffer.copy(): self.full_scan_text.insert("end", "".join(buff)))
                                buffer.clear()
                            last_update = processed
                        if processed % progress_interval == 0:
                            progress = processed / total_files if total_files > 0 else 0
                            self.ui_call(lambda p=progress: self.full_scan_progress.set(p))
                            self.ui_call(lambda: self.full_scan_status.configure(text=f"进度: {processed}/{total_files}"))
                        
                        if any(f.lower().endswith(ext) for ext in exts):
                            fp = os.path.join(root, f)
                            try:
                                with open(fp, 'rb') as obj:
                                    sha256 = hashlib.sha256(obj.read()).hexdigest()
                                threat = self.check_hash_online(sha256)
                                if threat:
                                    suspicious.append((fp, sha256, threat))
                                    buffer.append(f"⚠ {fp}\nSHA256: {sha256}\n威胁: {threat}\n\n")
                            except:
                                pass
            # 剩余缓冲区
            if buffer:
                self.ui_call(lambda buff=buffer.copy(): self.full_scan_text.insert("end", "".join(buff)))
            
            self.full_scan_cancel = False
            self.ui_call(lambda: (
                self.full_scan_btn.configure(state="normal"),
                self.cancel_full_scan_btn.configure(state="disabled"),
                self.export_full_scan_btn.configure(state="normal"),
                self.full_scan_status.configure(text=f"扫描完成，发现 {len(suspicious)} 个可疑文件"),
                self.full_scan_progress.set(1),
                self.status_label.configure(text="准备就绪")
            ))
            self.full_scan_results = suspicious
        threading.Thread(target=scan, daemon=True).start()

    def cancel_full_scan(self):
        self.full_scan_cancel = True
        self.ui_call(lambda: self.full_scan_status.configure(text="正在取消扫描..."))

    def export_full_scan(self):
        if not hasattr(self, 'full_scan_results') or not self.full_scan_results:
            messagebox.showinfo("提示", "没有可导出的结果")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                for fp, sha256, threat in self.full_scan_results:
                    f.write(f"文件: {fp}\nSHA256: {sha256}\n威胁: {threat}\n\n")
            messagebox.showinfo("成功", f"结果已导出到 {filepath}")

    def check_hash_online(self, sha256):
        try:
            r = requests.get(f"https://hashlookup.circl.lu/hash/{sha256}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("known") == True or data.get("malicious") == True:
                    return data.get("threat", "未知威胁")
            return None
        except:
            return None

    # ==================== 删除记忆 ====================
    def clear_all_memory(self):
        if messagebox.askyesno("确认", "删除所有记忆将重置白名单、清理选项、防护开关等所有设置，是否继续？"):
            config_path = os.path.join(os.path.dirname(sys.argv[0]), "config.json")
            if os.path.exists(config_path):
                try:
                    os.remove(config_path)
                    messagebox.showinfo("成功", "已删除所有记忆，下次启动将恢复默认设置。")
                    self.whitelist.clear()
                    if hasattr(self, 'tmp_var'):
                        self.tmp_var.set(False)
                        self.cache_var.set(False)
                        self.rec_var.set(False)
                    if self.protection_running:
                        self.toggle_protection()
                    self.settings = {"whitelist": [], "clean_options": {"tmp": False, "cache": False, "rec": False}, "protection_enabled": False}
                except Exception as e:
                    messagebox.showerror("错误", f"删除失败: {e}")
            else:
                messagebox.showinfo("提示", "没有找到记忆文件")

if __name__ == "__main__":
    app = LiangDun()
    app.mainloop()
