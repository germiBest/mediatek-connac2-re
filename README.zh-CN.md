# MediaTek connac2 Wi-Fi 固件逆向工程

用于逆向工程 MediaTek "connac2" Wi-Fi MCU 固件的工具与笔记：
涵盖 MT7921 / MT7922 / MT7961 / MT7915 系列（即上游 `mt76` 驱动加载 `WIFI_RAM_CODE_*` 二进制文件的芯片）。

三项核心发现推动了本工作：

- connac2 Wi-Fi MCU 采用的是 Tensilica Xtensa 架构（LX、小端序、32 位），并带有厂商自定义的 TIE 扩展指令。
- connac2 RAM 固件为明文，未加密。完整性校验采用简单的 `zlib.crc32(file[:-4])`，校验值存储在文件尾部的 trailer 中。
- 在未经修改的 Ghidra 中，MT7961 镜像仅能恢复约 4 个可用函数：它通过指针分析播种了约 509 个函数桩，但在遇到第一个未知操作码时便放弃每个函数，因此几乎无一能被解码。而使用本仓库中的处理器扩展后，可恢复约 3,800 至 4,500 个函数，且零未解析指令。

## 仓库内容

| 路径 | 内容 |
|------|------|
| `ghidra_extension/` | Ghidra 处理器扩展，新增语言定义 `Xtensa:LE:32:MTK`。它将自定义 TIE 操作码解码为长度正确的透明指令，使反汇编器保持同步，函数得以正常反编译。预构建的 zip 文件位于 `dist/`。 |
| `kaitai/` | 固件容器及镜像内指令 / TLV 分派表的 Kaitai Struct 解析器，以及 `COMMAND-MAP.md`，即 MT7961 镜像的完整主机指令接口。 |
| `FINDINGS.md` | 技术报告：Xtensa + TIE 的识别、容器格式、操作码与长度说明、固件架构（指令分派、CNM 信道授权、MCC 调度器）。 |
| `DEEP-FINDINGS.md` | 借助 mt76 驱动作为 Rosetta Stone 命名固件结构（逐字段还原 RLM 信道 TLV、分派表、约 30 个处理函数）、SDK 源码可得性，以及 ROM 子系统（eFuse、HIF、引导）。 |
| `ROM-DUMP.md` | 如何在不使用 JTAG 的情况下，通过 USB 从在线适配器读取位于 `0x800000` 的 WM 掩码 ROM、其内容，以及载入 Ghidra 后恢复的结果（函数数从 4471 增至 6511）。 |
| `TIE-BOUNDARY.md` | 为何 MCC 调度器无法被还原（厂商 TIE，已通过五种方式确认，包括仿真），哪些内容仍可恢复，以及不受此边界影响的未触及区域。 |
| `CAPSTONE-FIX.md` | 在本次 RE 中发现的一个 capstone Xtensa 解码缺陷（非 ESP32-S3 配置被误解码为 4 字节 ee.* 操作），以及向上游提交的修复。 |
| `examples/` | 无头加载脚本及函数计数辅助工具。 |

## 安装 Ghidra 扩展

在 Ghidra 12.1 上构建并验证。

GUI 安装：`File > Install Extensions`，点击 `+`，选择 `dist/Xtensa-MTK-ghidra_12.1.zip`，重启 Ghidra。

命令行直接安装：

```
unzip dist/Xtensa-MTK-ghidra_12.1.zip -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"
```

扩展附带为 Ghidra 12.1 预编译的 `.sla` 文件。若使用不同版本的 Ghidra，首次加载时会从附带的 `.slaspec` / `.sinc` 重新编译（首次加载较慢，但可正常使用）；如需重新构建，请修改 `extension.properties` 并运行 `ghidra_extension/build.sh`。

## 使用方法

将 connac2 代码镜像作为 Raw Binary 导入，语言设置为 `Xtensa:LE:32:MTK`，基地址设为区域加载地址（MT7961 的代码区域加载于 `0x915000`），然后运行自动分析。

如需一步完成完整布局，请运行附带的脚本管理器脚本 `LoadConnac2Firmware`（类别 MTK.Connac2）。该脚本会解析容器、按加载地址映射每个区域、添加 ROM 与 DRAM 桩块（防止反编译器追踪未映射内存）、设置入口点并启动反汇编。

通过该脚本加载完整 `WIFI_RAM_CODE_MT7961_1.bin` 并自动分析后的验证结果：

```
language:           Xtensa:LE:32:MTK
container:          mt76_connac2_fw_trailer, CRC 校验通过
entry:              0x915000  (j 0x917405)
functions:          3848
bad instructions:   0
unresolved opcodes: 0
```

## Kaitai 解析器

`kaitai/mediatek_connac2_wifi_firmware.ksy` 解析固件容器（trailer 及 `n_region` 个区域头，含 `FW_FEATURE_*` 位解码）。
`kaitai/mediatek_connac2_fw_tables.ksy` 解析镜像内的分派表；
`kaitai/COMMAND-MAP.md` 为导出结果，包含每个主机指令 ID 与 BSS TLV 标签映射到的处理函数地址，并与 `mt76` 枚举值交叉引用。

使用 `kaitai-struct-compiler` 0.11 及 Python 运行时编译并运行。

## 局限性

- 自定义 TIE 操作码保持透明。它们显示为 `mtk_tie_*()` CALLOTHER，未建模具体语义，因为 MediaTek 从未公开 Tensilica TIE 配置。镜像中约 73% 为基础 Xtensa 指令（显示真实助记符），其余为厂商协处理器指令。函数边界、控制流与调用图均完整保留，因此固件仍可被分析与导航。
- `0x800000-0x900000` 处的掩码 ROM 不属于可下载的 blob，因此驻留于该区域、被 RAM 代码调用的叶子辅助例程无法读取。
- DBGLOG 数字 ID 到格式字符串的数据库仅存在于主机端。固件内无字符串指针表，因此无法从代码交叉引用日志字符串。

## 已验证与推测适用

MT7961 已端到端验证。MT7921、MT7922 与 MT7915 共享 connac2 容器及同系列 Xtensa 核心，因此解析器与扩展应可适用，但尚未在本仓库中进行字节级验证。

## 相关项目

MediaTek 固件逆向工程按处理器分散在不同仓库中。本仓库为 connac2 Wi-Fi MCU 部分。相邻项目如下：

- [`cyrozap/mediatek-wifi-re`](https://github.com/cyrozap/mediatek-wifi-re)：
  针对较早世代 MediaTek Wi-Fi 核心（MT76x7 及类似）的早期工作，部分加密，使用 ILM/DLM、`MTKW`/`MTKE` 及 `.ALPS` 补丁容器。核心与容器均与 connac2 不同；两者无重叠。

- [`nccgroup/ghidra-nanomips`](https://github.com/nccgroup/ghidra-nanomips) 及
  [`nccgroup/mtk_bp`](https://github.com/nccgroup/mtk_bp)：
  MediaTek 5G 基带 / 调制解调器（`md1rom`），核心为 nanoMIPS，非 Xtensa，并附带 `DbgInfo` 符号文件。工具集形态与本仓库相同（Ghidra 处理器模块 + Kaitai 容器解包器），但处理器不同。

因此，在一台 MediaTek 设备上：调制解调器为 nanoMIPS，connac2 Wi-Fi 即为本仓库处理的 Xtensa 核心。与基带不同，connac2 Wi-Fi 固件为剥离符号版本，且使用主机端 ID 日志，因此无可导入的符号。

## 致谢与许可

Ghidra 扩展基于 Ghidra 的 Apache-2.0 Xtensa 处理器（基础 ISA SLEIGH、编译器及处理器规范）进行分支；详见 `NOTICE` 文件。本仓库采用 Apache-2.0 许可。Kaitai 定义采用 CC0 许可。