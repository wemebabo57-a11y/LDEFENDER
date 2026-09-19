# 更新日志

## 2026-09-19 — 仓库结构整理

对仓库做了一次结构整理：按文件类型归类到 `src/`、`data/`、`releases/`、`docs/`，补上缺失的许可证与忽略规则，并订正文档中过时的版本信息。

**重要：仓库目录只是归档方式，不是程序运行目录。** 程序运行时要求 `clamav/` 与主程序 `.py` 同级，详见 [README](README.md) 的《真实运行目录》一节。

### 文件移动对照表

| 原路径 | 新路径 | 说明 |
|--------|--------|------|
| `6.1.py` | `src/current/6.1.py` | 当前版本主程序 |
| `v1.py` | `src/legacy/v1.py` | |
| `v4.py` | `src/legacy/v4.py` | |
| `v4_plus.py` | `src/legacy/v4_plus.py` | |
| `5.5.py` | `src/legacy/5.5.py` | |
| `6.0.py` | `src/legacy/6.0.py` | |
| `git5.4/liangdun.py` | `src/legacy/5.4-liangdun.py` | 内部版本串为 v5.2.4 |
| `00001–00011.md5.txt` | `data/md5-signatures/` | MD5 特征库分片 |
| `webshells_index.zip` | `data/yara/webshells_index.zip` | YARA 规则集 |
| `liangdunv2.zip` | `releases/liangdunv2.zip` | |
| `-5.0open.zip` | `releases/5.0-open.zip` | 去掉文件名开头的连字符 |
| `-5.2plus.zip` | `releases/5.2-plus.zip` | 去掉文件名开头的连字符 |
| `doc/*.png` | `docs/images/screenshot-01–08.png` | 改为 ASCII 文件名 |
| `fi'l` | `docs/intro-article.md` | 原文件名疑似误敲 |
| `git5.4/clamav/README_YARA.txt` | `docs/clamav-yara.md` | |
| `git5.4/clamav/大小原因请自行前往官方网站下载.txt` | *已删除* | 空文件，内容并入 `src/current/clamav/README.md` |

### 新增文件

| 文件 | 说明 |
|------|------|
| `LICENSE` | MIT 许可证（README 原先声明 MIT 但仓库中无此文件） |
| `CHANGELOG.md` | 本文件 |
| `.gitignore` | 忽略运行数据、构建产物、ClamAV 二进制，并**显式忽略证书与密钥**（`*.pfx`、`*.key`、`*.pem`、`secret.key` 等） |
| `src/current/clamav/README.md` | 说明 ClamAV 引擎的放置方式与获取途径 |
| `src/legacy/requirements.txt` | 历史版本（CustomTkinter 时代）的依赖 |

### 文档订正

- **版本谱系补全** — 原 README 只记录到 `v4_plus.py`，遗漏了 `5.4`、`5.5`、`6.0`、`6.1` 四个版本，现已补全
- **依赖订正** — 原 `requirements.txt` 只有 3 项，与实际导入不符。现已按技术代际拆分：
  - `v1`/`v4`/`v4_plus` 使用 **CustomTkinter**，依赖 `customtkinter`、`pystray`、`Pillow`、`requests`
  - `5.4` 之后改用**原生 tkinter**，核心依赖仅 `psutil`，另有若干可选增强
- **移除 `pywin32`** — 原文档要求安装 `pywin32`，但代码中的注册表操作使用标准库 `winreg`，实际并不需要
- **版本号说明** — 文件名中的编号是修订序号，与代码内部 `APP_VERSION` 不一致：`6.0.py` 与 `6.1.py` 内部都声明 `v6.0.0`，`git5.4/liangdun.py` 内部声明 `v5.2.4`

---

## 历史版本

### 2026-04-05
- 修复部分进程误报
- 优化启动速度，降低资源占用
- 界面细节优化

### 2026-04-01
- 新增文件清理功能
- 修复闪退问题

### 2026-03-28
- 首个版本发布，基础进程监控 + 文件扫描
