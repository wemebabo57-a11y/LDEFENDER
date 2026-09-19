"""
量盾 - 系统安全工具
功能：
- 系统实时监控（CPU、内存、磁盘、网络）
- 进程管理（查看、结束进程）
- 病毒扫描（威胁检测、完整哈希扫描）
- 文件清理（清理缓存、临时文件、回收站）
- 启动项管理
作者：AI Assistant
日期：2026-03-22
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import psutil
import os
import winreg
import threading
import hashlib
from datetime import datetime


class LiangGun(ctk.CTk):
    """主程序类"""

    def __init__(self):
        super().__init__()

        # 设置窗口属性
        self.title("量盾 - 系统安全工具")
        self.geometry("1100x750")
        self.minsize(1100, 750)

        # 设置主题
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # 初始化界面
        self.create_widgets()
        # 立即刷新一次系统信息
        try:
            self.refresh_system_info()
        except Exception as e:
            print(f"初始化系统信息失败: {e}")

    def create_widgets(self):
        """创建界面组件"""

        # 顶部标题栏
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=15)

        title_label = ctk.CTkLabel(
            title_frame,
            text="🛡️ 量盾 - 系统安全工具",
            font=("Microsoft YaHei", 28, "bold"),
            text_color="#1E90FF"
        )
        title_label.pack(pady=5)

        # 菜单栏
        menu_frame = ctk.CTkFrame(self, fg_color="#E8E8E8", corner_radius=8)
        menu_frame.pack(fill="x", padx=20, pady=10)

        # 菜单项
        menu_items = [
            ("📊 系统监控", 0, 0),
            ("💻 进程管理", 0, 1),
            ("🦠 病毒扫描", 0, 2),
            ("🗑️ 文件清理", 0, 3),
            ("⚙️ 启动项", 0, 4),
        ]

        self.menu_buttons = {}
        for text, row, col in menu_items:
            btn = ctk.CTkButton(
                menu_frame,
                text=text,
                width=160,
                height=40,
                font=("Microsoft YaHei", 12, "bold"),
                corner_radius=6,
                command=lambda t=text: self.on_menu_click(t)
            )
            btn.grid(row=row, column=col, padx=8, pady=8)
            self.menu_buttons[text] = btn

        # 内容区
        content_frame = ctk.CTkFrame(self, fg_color="#F5F5F5", corner_radius=10)
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # 标签页
        self.notebook = ctk.CTkTabview(content_frame, width=1060, height=520)
        self.notebook.pack(pady=15, padx=15)

        # 创建各个标签页
        self.create_tabs()

        # 底部状态栏
        status_frame = ctk.CTkFrame(self, fg_color="#E0E0E0", corner_radius=5)
        status_frame.pack(fill="x", padx=20, pady=20)

        self.status_label = ctk.CTkLabel(
            status_frame,
            text="准备就绪",
            font=("Microsoft YaHei", 11),
            text_color="gray"
        )
        self.status_label.pack(side="left", padx=10, pady=5)

        # 定时刷新
        self.refresh_interval = 2000  # 2秒刷新一次
        self.after(self.refresh_interval, self.auto_refresh)

    def create_tabs(self):
        """创建所有标签页"""
        # 系统监控
        self.create_monitor_tab()
        # 进程管理
        self.create_process_tab()
        # 病毒扫描
        self.create_virus_scan_tab()
        # 文件清理
        self.create_cleanup_tab()
        # 启动项
        self.create_startup_tab()

    def create_monitor_tab(self):
        """创建系统监控标签页"""
        self.notebook.add("系统监控")
        tab_widget = self.notebook.tab("系统监控")

        # CPU 监控
        cpu_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        cpu_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(cpu_frame, text="🖥️ CPU 监控", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        self.cpu_progress = ctk.CTkProgressBar(cpu_frame, width=1030, height=20)
        self.cpu_progress.pack(pady=5, padx=20)
        self.cpu_label = ctk.CTkLabel(cpu_frame, text="CPU 使用率: 0%", font=("Microsoft YaHei", 13))
        self.cpu_label.pack(pady=5)
        self.cpu_text = ctk.CTkTextbox(cpu_frame, width=1030, height=90, font=("Consolas", 11))
        self.cpu_text.pack(pady=5, padx=20)

        # 内存监控
        mem_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        mem_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(mem_frame, text="💾 内存监控", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        self.mem_progress = ctk.CTkProgressBar(mem_frame, width=1030, height=20)
        self.mem_progress.pack(pady=5, padx=20)
        self.mem_label = ctk.CTkLabel(mem_frame, text="内存使用率: 0%", font=("Microsoft YaHei", 13))
        self.mem_label.pack(pady=5)
        self.mem_text = ctk.CTkTextbox(mem_frame, width=1030, height=90, font=("Consolas", 11))
        self.mem_text.pack(pady=5, padx=20)

        # 磁盘监控
        disk_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        disk_frame.pack(fill="both", expand=True, padx=15, pady=10)

        ctk.CTkLabel(disk_frame, text="💿 磁盘监控", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        self.disk_text = ctk.CTkTextbox(disk_frame, width=1030, height=140, font=("Consolas", 11))
        self.disk_text.pack(pady=5, padx=20)

    def create_process_tab(self):
        """创建进程管理标签页"""
        self.notebook.add("进程管理")
        tab_widget = self.notebook.tab("进程管理")

        # 进程列表
        list_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        list_frame.pack(fill="both", expand=True, padx=15, pady=10)

        ctk.CTkLabel(list_frame, text="💻 进程列表", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        # 搜索框
        search_frame = ctk.CTkFrame(list_frame, fg_color="transparent")
        search_frame.pack(fill="x", padx=10)

        ctk.CTkLabel(search_frame, text="搜索:").pack(side="left")
        self.search_entry = ctk.CTkEntry(search_frame, width=350)
        self.search_entry.pack(side="left", padx=10)

        ctk.CTkButton(search_frame, text="🔍 搜索", width=90, command=self.refresh_process_list).pack(side="left", padx=5)

        # 进程列表
        self.process_tree = ctk.CTkTextbox(list_frame, width=1090, height=420, font=("Consolas", 10))
        self.process_tree.pack(pady=5, padx=10)

        # 操作按钮
        action_frame = ctk.CTkFrame(list_frame, fg_color="transparent")
        action_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(action_frame, text="🔄 刷新", width=110, command=self.refresh_process_list).pack(side="left", padx=5)

        ctk.CTkButton(action_frame, text="❌ 结束选中进程", width=160, fg_color="#FF6B6B", text_color="white",
                      font=("Microsoft YaHei", 12, "bold"), command=self.kill_process).pack(side="right", padx=5)

    def create_virus_scan_tab(self):
        """创建病毒扫描标签页"""
        self.notebook.add("病毒扫描")
        tab_widget = self.notebook.tab("病毒扫描")

        # 扫描设置
        scan_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        scan_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(scan_frame, text="🦠 病毒扫描", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        ctk.CTkLabel(scan_frame, text="请选择要扫描的文件夹：", font=("Microsoft YaHei", 13)).pack(pady=5)

        self.scan_path = ctk.CTkEntry(scan_frame, width=550, placeholder_text="未选择路径")
        self.scan_path.pack(pady=5, padx=10)

        ctk.CTkButton(scan_frame, text="📁 浏览...", width=100, command=self.select_scan_folder).pack(side="left", padx=10)

        self.virus_scan_button = ctk.CTkButton(scan_frame, text="🔍 开始扫描", width=130, height=40,
                                                font=("Microsoft YaHei", 13, "bold"), fg_color="#E53935", text_color="white",
                                                command=self.run_virus_scan_threaded)
        self.virus_scan_button.pack(side="left", padx=10)

        # 扫描结果
        result_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        result_frame.pack(fill="both", expand=True, padx=15, pady=10)

        ctk.CTkLabel(result_frame, text="✨ 扫描结果：", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        self.virus_result = ctk.CTkTextbox(result_frame, width=1090, height=430, font=("Consolas", 10))
        self.virus_result.pack(pady=5, padx=10)

    def create_cleanup_tab(self):
        """创建文件清理标签页"""
        self.notebook.add("文件清理")
        tab_widget = self.notebook.tab("文件清理")

        # 清理选项
        options_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        options_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(options_frame, text="🗑️ 文件清理选项", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        self.cleanup_vars = {}
        cleanup_items = [
            ("清理系统临时文件", "temp"),
            ("清理浏览器缓存", "cache"),
            ("清理回收站", "recycle"),
            ("清理日志文件", "logs"),
        ]

        for text, key in cleanup_items:
            var = ctk.BooleanVar(value=False)
            self.cleanup_vars[key] = var
            ctk.CTkCheckBox(options_frame, text=text, variable=var, font=("Microsoft YaHei", 13)).pack(anchor="w",
                                                                                                         padx=20, pady=5)

        # 清理按钮
        ctk.CTkButton(options_frame, text="🧹 开始清理", width=160, height=45,
                      font=("Microsoft YaHei", 14, "bold"), fg_color="#4CAF50", text_color="white", corner_radius=8,
                      command=self.run_cleanup_threaded).pack(pady=15)

        # 清理结果
        result_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        result_frame.pack(fill="both", expand=True, padx=15, pady=10)

        ctk.CTkLabel(result_frame, text="✨ 清理结果：", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        self.cleanup_result = ctk.CTkTextbox(result_frame, width=1090, height=380, font=("Consolas", 10))
        self.cleanup_result.pack(pady=5, padx=10)

    def create_startup_tab(self):
        """创建启动项标签页"""
        self.notebook.add("启动项")
        tab_widget = self.notebook.tab("启动项")

        # 启动项信息
        list_frame = ctk.CTkFrame(tab_widget, fg_color="white", corner_radius=10)
        list_frame.pack(fill="both", expand=True, padx=15, pady=10)

        ctk.CTkLabel(list_frame, text="⚙️ 开机启动项", font=("Microsoft YaHei", 18, "bold")).pack(pady=8)

        self.startup_text = ctk.CTkTextbox(list_frame, width=1090, height=430, font=("Consolas", 10))
        self.startup_text.pack(pady=5, padx=10)

        ctk.CTkButton(list_frame, text="🔄 刷新", width=110, command=self.refresh_startup_items).pack(pady=10)

    def on_menu_click(self, menu_text):
        """菜单点击事件"""
        try:
            if menu_text == "📊 系统监控":
                self.notebook.set("系统监控")
                self.status_label.configure(text="正在显示系统监控")
            elif menu_text == "💻 进程管理":
                self.refresh_process_list()
                self.notebook.set("进程管理")
                self.status_label.configure(text="正在显示进程管理")
            elif menu_text == "🦠 病毒扫描":
                self.notebook.set("病毒扫描")
                self.status_label.configure(text="正在显示病毒扫描")
            elif menu_text == "🗑️ 文件清理":
                self.notebook.set("文件清理")
                self.status_label.configure(text="正在显示文件清理")
            elif menu_text == "⚙️ 启动项":
                self.refresh_startup_items()
                self.notebook.set("启动项")
                self.status_label.configure(text="正在显示启动项")
        except Exception as e:
            print(f"切换标签页失败: {e}")
            messagebox.showerror("错误", f"切换标签页失败:\n{str(e)}")

    def auto_refresh(self):
        """自动刷新"""
        try:
            self.refresh_system_info()
        except Exception as e:
            print(f"刷新系统信息失败: {e}")
        self.after(self.refresh_interval, self.auto_refresh)

    def refresh_system_info(self):
        """刷新系统信息"""
        try:
            # CPU 信息
            cpu_percent = psutil.cpu_percent(interval=0.5)
            cpu_cores = psutil.cpu_count(logical=False)

            self.cpu_progress.set(cpu_percent / 100)
            self.cpu_label.configure(text=f"CPU 使用率: {cpu_percent:.1f}% ({cpu_cores} 核心逻辑)")
            self.cpu_text.delete("1.0", "end")

            cpu_text = f"CPU 核心数: {cpu_cores}\n"
            cpu_text += "各核心使用率:\n"
            for i, percent in enumerate(psutil.cpu_percent(interval=0.1, percpu=True), 1):
                color = "#4CAF50" if percent < 70 else "#FF9800" if percent < 90 else "#F44336"
                cpu_text += f"  核心 {i}: {percent:.1f}%\n"
            self.cpu_text.insert("1.0", cpu_text)

            # 内存信息
            mem = psutil.virtual_memory()
            self.mem_progress.set(mem.percent / 100)
            self.mem_label.configure(text=f"内存使用率: {mem.percent:.1f}% ({mem.used / (1024**3):.2f}GB / {mem.total / (1024**3):.2f}GB)")
            self.mem_text.delete("1.0", "end")

            mem_text = f"总内存: {mem.total / (1024**3):.2f} GB\n"
            mem_text += f"已使用: {mem.used / (1024**3):.2f} GB ({mem.percent:.1f}%)\n"
            mem_text += f"可用: {mem.available / (1024**3):.2f} GB\n"

            # 查看最耗内存的进程
            mem_processes = []
            for proc in psutil.process_iter(['name', 'memory_info']):
                try:
                    mem_processes.append((proc.info['name'], proc.info['memory_info'].rss))
                except:
                    pass

            mem_processes.sort(key=lambda x: x[1], reverse=True)
            mem_text += "\n最耗内存的前10个进程:\n"
            for name, mem in mem_processes[:10]:
                mem_text += f"  {name}: {mem / (1024**2):.2f} MB\n"

            self.mem_text.insert("1.0", mem_text)

            # 磁盘信息
            self.disk_text.delete("1.0", "end")
            disk_text = ""
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_text += f"\n【{partition.device}】{partition.mountpoint}\n"
                    disk_text += f"  文件系统: {partition.fstype}\n"
                    disk_text += f"  总大小: {usage.total / (1024**3):.2f} GB\n"
                    disk_text += f"  已使用: {usage.used / (1024**3):.2f} GB\n"
                    disk_text += f"  可用: {usage.free / (1024**3):.2f} GB\n"
                    disk_text += f"  使用率: {usage.percent}%\n"
                except:
                    disk_text += f"\n【{partition.device}】无法访问\n"

            self.disk_text.insert("1.0", disk_text)

            self.status_label.configure(text=f"系统监控已更新 - {datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"刷新系统信息失败: {e}")

    def refresh_process_list(self):
        """刷新进程列表"""
        try:
            self.status_label.configure(text="正在刷新进程列表...")

            search_text = self.search_entry.get().lower()
            process_text = f"{'进程名称':<30} {'PID':<10} {'CPU%':<8} {'内存%':<8} {'内存(MB)':<12}\n"
            process_text += "=" * 80 + "\n"

            for proc in psutil.process_iter(['name', 'pid', 'cpu_percent', 'memory_percent', 'memory_info']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name']
                    pid = proc_info['pid']

                    # 搜索过滤
                    if search_text and search_text not in proc_name.lower():
                        continue

                    cpu = proc_info['cpu_percent'] or 0
                    mem_percent = proc_info['memory_percent'] or 0
                    mem_mb = proc_info['memory_info'].rss / (1024 * 1024)

                    process_text += f"{proc_name:<30} {pid:<10} {cpu:>6.1f}% {mem_percent:>6.1f}% {mem_mb:>11.1f} MB\n"
                except:
                    continue

            process_text += f"\n总计: {len(list(psutil.process_iter()))} 个进程"
            self.process_tree.delete("1.0", "end")
            self.process_tree.insert("1.0", process_text)

            self.status_label.configure(text=f"已刷新 - {datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"刷新进程列表失败: {e}")
            messagebox.showerror("错误", f"刷新进程列表失败:\n{str(e)}")

    def kill_process(self):
        """结束选中的进程"""
        try:
            selected_text = self.process_tree.get("1.0", "end")

            # 提取PID
            for line_text in selected_text.split('\n'):
                if line_text.strip():
                    parts = line_text.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        pid = int(parts[1])
                        proc_name = parts[0]

                        # 确认对话框
                        confirm = messagebox.askyesno("确认", f"确定要结束进程吗？\n\n进程名: {proc_name}\nPID: {pid}")

                        if confirm:
                            try:
                                process = psutil.Process(pid)
                                process.terminate()
                                messagebox.showinfo("成功", f"已结束进程:\n{proc_name} (PID: {pid})")
                                self.refresh_process_list()
                                return
                            except psutil.NoSuchProcess:
                                messagebox.showerror("错误", "进程不存在")
                            except psutil.AccessDenied:
                                messagebox.showerror("错误", "权限不足，无法结束该进程")
                            except Exception as e:
                                messagebox.showerror("错误", f"结束进程失败:\n{str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"选择进程失败:\n{str(e)}")

    def select_scan_folder(self):
        """选择扫描文件夹"""
        folder = filedialog.askdirectory()
        if folder:
            self.scan_path.delete(0, "end")
            self.scan_path.insert(0, folder)

    def run_virus_scan_threaded(self):
        """在线程中运行病毒扫描"""
        try:
            # 禁用按钮防止重复点击
            self.virus_scan_button.configure(state="disabled")

            # 在后台线程运行扫描
            thread = threading.Thread(target=self.run_virus_scan_background, daemon=True)
            thread.start()
        except Exception as e:
            messagebox.showerror("错误", f"启动扫描失败:\n{str(e)}")

    def run_virus_scan_background(self):
        """后台运行病毒扫描"""
        try:
            scan_folder = self.scan_path.get()

            if not scan_folder:
                self.after(0, lambda: messagebox.showwarning("警告", "请先选择要扫描的文件夹！"))
                self.after(0, lambda: self.virus_scan_button.configure(state="normal"))
                return

            # 清空结果框
            self.after(0, lambda: self.virus_result.delete("1.0", "end"))

            result_text = f"""
扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
扫描路径: {scan_folder}

{'='*80}

扫描说明：
本工具进行的是**威胁检测**，而非完整病毒扫描。
它会检查：
✓ 文件大小异常
✓ 文件名可疑模式
✓ 可疑文件类型
✓ 文件哈希值
⚠️ 请注意：这不是专业杀毒软件，如发现严重威胁请使用专业工具

{'='*80}

"""

            # 已知威胁特征（简化版）
            suspicious_extensions = ['.exe', '.scr', '.pif', '.bat', '.cmd', '.vbs', '.js', '.jar', '.dll', '.com']
            suspicious_names = ['autorun', 'setup', 'install', 'update', 'patch', 'crack', 'keygen', 'patch', 'hack', 'trojan', 'virus', 'malware']

            file_count = 0
            threat_count = 0
            total_size = 0

            try:
                for root, dirs, files in os.walk(scan_folder):
                    for file in files:
                        file_count += 1
                        file_path = os.path.join(root, file)
                        file_size = os.path.getsize(file_path)
                        total_size += file_size

                        file_ext = os.path.splitext(file)[1].lower()
                        file_lower = file.lower()

                        threat_score = 0
                        threat_details = []

                        # 检查文件大小
                        if file_size > 100 * 1024 * 1024:  # 超过100MB
                            threat_score += 10
                            threat_details.append("超大文件")

                        # 检查扩展名
                        if file_ext in suspicious_extensions:
                            threat_score += 5
                            threat_details.append("可疑扩展名")

                        # 检查文件名模式
                        for suspicious in suspicious_names:
                            if suspicious in file_lower:
                                threat_score += 3
                                threat_details.append(f"可疑关键词: {suspicious}")
                                break

                        # 计算文件哈希（MD5）
                        file_hash_md5 = ""
                        try:
                            with open(file_path, 'rb') as f:
                                file_hash_md5 = hashlib.md5(f.read()).hexdigest()
                        except:
                            file_hash_md5 = "N/A"

                        # 计算文件哈希（SHA256）
                        file_hash_sha256 = ""
                        try:
                            with open(file_path, 'rb') as f:
                                file_hash_sha256 = hashlib.sha256(f.read()).hexdigest()
                        except:
                            file_hash_sha256 = "N/A"

                        # 显示结果
                        if threat_score > 0:
                            threat_count += 1

                            result_text += f"⚠️  发现可疑文件 #{threat_count}\n"
                            result_text += f"路径: {file_path}\n"
                            result_text += f"大小: {file_size:,} bytes ({file_size / (1024**2):.2f} MB)\n"
                            result_text += f"扩展名: {file_ext}\n"
                            result_text += f"MD5:  {file_hash_md5}\n"
                            result_text += f"SHA256: {file_hash_sha256}\n"

                            for detail in threat_details:
                                result_text += f"  - {detail}\n"

                            result_text += "-" * 80 + "\n"

                result_text += f"""
{'='*80}

扫描完成：
- 扫描文件总数: {file_count:,}
- 总大小: {total_size / (1024**2):.2f} MB
- 发现可疑文件: {threat_count:,}

建议：
1. 上述扫描基于已知威胁模式，仅供参考
2. 如发现严重可疑文件，建议使用专业杀毒软件扫描
3. 对于 .exe, .scr 等可执行文件需特别谨慎
4. 您可以复制MD5或SHA256哈希值到病毒扫描网站（如VirusTotal）进行验证

"""

            except Exception as e:
                result_text += f"\n扫描错误: {str(e)}\n"

            # 更新UI
            self.after(0, lambda: self.virus_result.insert("1.0", result_text))
            self.after(0, lambda: self.virus_scan_button.configure(state="normal"))
            self.after(0, lambda: self.status_label.configure(text=f"已扫描完成 - {datetime.now().strftime('%H:%M:%S')}"))
        except Exception as e:
            print(f"病毒扫描失败: {e}")
            self.after(0, lambda: self.virus_scan_button.configure(state="normal"))
            self.after(0, lambda: messagebox.showerror("错误", f"扫描失败:\n{str(e)}"))

    def run_cleanup_threaded(self):
        """在线程中运行文件清理"""
        try:
            # 禁用按钮防止重复点击
            cleanup_btn = None
            for btn in self.menu_buttons.values():
                if "🗑️ 文件清理" in btn.cget("text"):
                    cleanup_btn = btn
                    break

            if cleanup_btn:
                cleanup_btn.configure(state="disabled")

            # 在后台线程运行清理
            thread = threading.Thread(target=self.run_cleanup_background, daemon=True)
            thread.start()
        except Exception as e:
            messagebox.showerror("错误", f"启动清理失败:\n{str(e)}")

    def run_cleanup_background(self):
        """后台运行文件清理"""
        try:
            result_text = f"""
清理时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}

"""

            cleaned = 0
            size = 0

            if self.cleanup_vars['temp'].get():
                result_text += "【清理系统临时文件】\n"
                temp_path = os.environ.get('TEMP', '')
                if os.path.exists(temp_path):
                    for root, dirs, files in os.walk(temp_path):
                        for file in files:
                            try:
                                file_path = os.path.join(root, file)
                                if os.path.getsize(file_path) > 0:
                                    os.remove(file_path)
                                    cleaned += 1
                                    size += os.path.getsize(file_path)
                            except:
                                pass
                    result_text += f"  清理了 {cleaned} 个临时文件 ({size / (1024**2):.2f} MB)\n\n"
                    cleaned = 0
                    size = 0

            if self.cleanup_vars['cache'].get():
                result_text += "【清理浏览器缓存】\n"
                cache_dirs = [
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
                ]
                for cache_dir in cache_dirs:
                    if os.path.exists(cache_dir):
                        for root, dirs, files in os.walk(cache_dir):
                            for file in files:
                                try:
                                    file_path = os.path.join(root, file)
                                    if os.path.getsize(file_path) > 0:
                                        os.remove(file_path)
                                        cleaned += 1
                                        size += os.path.getsize(file_path)
                                except:
                                    pass
                    result_text += f"  清理了 {cleaned} 个缓存文件 ({size / (1024**2):.2f} MB)\n\n"
                    cleaned = 0
                    size = 0

            if self.cleanup_vars['recycle'].get():
                result_text += "【清理回收站】\n"
                try:
                    import shutil
                    for drive in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                        recycle_path = f"{drive}:\\$RECYCLE.BIN"
                        if os.path.exists(recycle_path):
                            try:
                                shutil.rmtree(recycle_path)
                                result_text += f"  已清空 {recycle_path}\n"
                            except:
                                pass
                except Exception as e:
                    result_text += f"  清理失败: {str(e)}\n"

            result_text += "=" * 80
            result_text += f"\n总计清理: {cleaned} 个文件 ({size / (1024**2):.2f} MB)"

            # 更新UI
            self.after(0, lambda: self.cleanup_result.insert("1.0", result_text))

            # 恢复按钮状态
            cleanup_btn = None
            for btn in self.menu_buttons.values():
                if "🗑️ 文件清理" in btn.cget("text"):
                    cleanup_btn = btn
                    break

            if cleanup_btn:
                cleanup_btn.configure(state="normal")

            self.after(0, lambda: self.status_label.configure(text=f"已清理完成 - {datetime.now().strftime('%H:%M:%S')}"))
        except Exception as e:
            print(f"文件清理失败: {e}")
            cleanup_btn = None
            for btn in self.menu_buttons.values():
                if "🗑️ 文件清理" in btn.cget("text"):
                    cleanup_btn = btn
                    break

            if cleanup_btn:
                cleanup_btn.configure(state="normal")

            self.after(0, lambda: messagebox.showerror("错误", f"清理失败:\n{str(e)}"))

    def refresh_startup_items(self):
        """刷新启动项"""
        try:
            self.status_label.configure(text="正在读取启动项...")

            startup_text = "【当前用户启动项 - 注册表】\n"
            startup_text += "=" * 80 + "\n"

            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                    r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                                    winreg.KEY_READ)

                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        startup_text += f"名称: {name}\n"
                        startup_text += f"路径: {value}\n"
                        startup_text += "-" * 80 + "\n"
                        i += 1
                    except OSError:
                        break

                winreg.CloseKey(key)

                if i == 0:
                    startup_text += "未发现启动项\n"
                else:
                    startup_text += f"\n总计: {i} 个启动项\n"

            except Exception as e:
                startup_text += f"\n读取失败: {str(e)}\n"

            self.startup_text.delete("1.0", "end")
            self.startup_text.insert("1.0", startup_text)

            self.status_label.configure(text=f"已刷新 - {datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"刷新启动项失败: {e}")
            messagebox.showerror("错误", f"刷新启动项失败:\n{str(e)}")


def main():
    """主函数"""
    app = LiangGun()
    app.mainloop()


if __name__ == "__main__":
    main()
