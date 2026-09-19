# ClamAV 引擎目录

**这个目录默认是空的，需要你自己放入 ClamAV 引擎。**

## 为什么仓库里没有 ClamAV

1. **体积过大** — ClamAV Windows x64 完整包解压后数百 MB，不适合放进 Git 仓库
2. **授权不同** — ClamAV 以 GNU GPL v2.0 授权，本项目以独立可执行文件方式调用它，不修改也不重新分发

## 怎么获取

1. 打开 <https://www.clamav.net/downloads>
2. 下载 **Windows x64** 版本（推荐 **1.5.2**）
3. 解压，把整个 `clamav` 目录的内容放到本目录下

放好后目录应该长这样：

```text
clamav/
├── clamscan.exe          ← 必需，扫描程序
├── freshclam.exe         ← 必需，病毒库更新程序
├── clamd.exe             ← 可选，守护进程
├── scan.bat
├── update.bat
└── db/                   ← 病毒库
    ├── main.cvd
    ├── daily.cld
    ├── bytecode.cvd
    └── yara-rules.ndb    ← 可选，YARA 转换签名
```

## 首次使用

先更新病毒库，否则检出率会很低：

```bat
update.bat
```

或手动执行：

```bat
freshclam.exe --datadir=db
```

## 关于 YARA 规则

`db/yara-rules.ndb` 是由 YARA 规则转换来的 ClamAV 文本签名。
转换方法、限制说明与规则来源见 [`docs/clamav-yara.md`](../../../docs/clamav-yara.md)。
仓库 `data/yara/webshells_index.zip` 中提供了原始的 YARA 规则集。

## 程序如何找到这个目录

主程序中的约定：

```python
BASE_DIR   = get_base_dir()          # 开发环境下 = Path(__file__).parent
CLAMAV_DIR = BASE_DIR / "clamav"
CLAMSCAN   = CLAMAV_DIR / "clamscan.exe"
```

也就是说，`clamav/` 必须与**正在运行的 `.py` 文件位于同一级目录**。
如果你把 `src/current/6.1.py` 复制到别处运行，请把 `clamav/` 一并复制过去。
详见仓库根目录 README 的《真实运行目录》一节。
