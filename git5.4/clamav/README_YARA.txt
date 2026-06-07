# ClamAV YARA 规则集成说明

## 目录结构

```
E:\0LIANDUN\5.6\clamav\
├── clamscan.exe          # 扫描程序
├── freshclam.exe         # 病毒库更新程序
├── scan.bat              # 扫描脚本 (带 YARA 规则)
├── update.bat            # 更新脚本
├── db\
│   ├── main.cvd          # 主病毒库
│   ├── daily.cld         # 每日更新
│   ├── bytecode.cvd      # 字节码签名
│   └── yara-rules.ndb    # 从 YARA 转换的签名 (500条)
└── tmp\                  # 临时目录
```

## 使用方法

### 1. 扫描文件或目录

双击运行 `scan.bat`，或从命令行执行：

```batch
scan.bat "C:\Users\Test\Downloads"
```

### 2. 更新病毒库

双击运行 `update.bat`，或执行：

```batch
update.bat
```

### 3. 命令行扫描

```batch
cd E:\0LIANDUN\5.6\clamav
clamscan.exe --database=db\main.cvd --database=db\daily.cld --database=db\bytecode.cvd --database=db\yara-rules.ndb [目标路径]
```

## YARA 规则转换说明

由于 ClamAV 对 YARA 规则的支持有限，已将部分 YARA 规则转换为 ClamAV .ndb 格式：

- **来源**: E:\0LIANDUN\yara2 中的 IOC 文件
- **数量**: 500 条签名
- **类型**: C2 域名 IOC
- **格式**: .ndb (ClamAV 文本签名格式)

### 转换限制

ClamAV 无法直接使用完整的 YARA 规则，因为：
1. 不支持 YARA 的 `pe` 模块
2. 不支持复杂的条件表达式
3. 单字节子模式不受支持
4. 子签名数量限制 (最多 64 个)

### 如需更多 YARA 规则支持

建议使用专门的 YARA 工具：
- yara.exe (命令行)
- YARA-Rules 管理工具

## 签名统计

- 官方病毒库: main.cvd + daily.cld (~90,000+ 签名)
- YARA 转换签名: 500 条
- 总计: ~90,500 条检测规则

## 注意事项

1. 首次使用前建议运行 `update.bat` 更新病毒库
2. 扫描大文件或大量文件可能需要较长时间
3. 发现可疑文件时，clamscan 会显示 "FOUND"
