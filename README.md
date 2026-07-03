# winhostappexe — PE 文件窗口应用分析器

分析 Windows EXE 文件，判断双击后是否会弹出窗口，并评估其"像窗口主程序"的程度。

## 使用方法

### CLI 快速分析单个文件

```bash
cargo run -- "C:\Program Files\some.exe"
```

### 批量扫描目录

```bash
# 完整扫描 + 分析
cargo run --example find

# 强制重分析（沿用缓存路径，免遍历）
cargo run --example find -- --force

# 仅重算排序/统计（不重新分析）
cargo run --example find -- --recalc
```

扫描参数在 `examples/find.rs` 顶部修改：

```rust
const ROOT_DIR: &str = r"D:\software";   // 要扫描的根目录
const MAX_DEPTH: usize = 3;               // 有文件的目录算一层，纯子目录不计数
const THREADS: usize = 0;                 // 0 = 自动（CPU 核数的一半）
const USE_CACHE: bool = true;             // 启用缓存（存到 %TEMP%/winhostappexe-cache/）
```

### 导出精简 JSON

```bash
cargo run --example pretty
```

输出到缓存目录下的 `exe-analysis.json`。

## 两套分数体系（满分 100）

### 主分（score_main）—— 消息循环强信号

测量 EXE 是否拥有自己的 Win32 消息循环。真正创建窗口的程序必会导入 `GetMessage → DispatchMessage → DefWindowProc` 这一系列函数，而仅靠 `DialogBoxParam` 的辅助工具不会导入它们。

| 计分类别                                                       | 满分    | 说明                   |
| -------------------------------------------------------------- | ------- | ---------------------- |
| 消息循环（GetMessage + DispatchMessage）                       | 30      | 两者各 15 分，缺一不可 |
| 窗口过程（DefWindowProc）                                      | 15      | 只计一次，不分 W/A     |
| 自绘制（BeginPaint/EndPaint + GetDC/ReleaseDC + UpdateWindow） | 15      | 自己管理 WM_PAINT      |
| 窗口管理（ShowWindow + SetWindowPos）                          | 10      | 控制窗口可见性和位置   |
| 菜单系统（CreateMenu/AppendMenu/TrackPopupMenu）               | 10      | 有菜单栏或右键菜单     |
| 输入处理（TranslateAccelerator + TranslateMessage）            | 10      | 快捷键和消息翻译       |
| 杂项 UI（定时器/度量/拖放/子类化等）                           | 10      | 最多 5 项，每项 2 分   |
| **总计**                                                       | **100** |                        |

### 副分（score_sub）—— 资源/导入/路径语义

衡量导入丰富度、资源类型、部署位置等辅助特征。

| 信号                            | 加减分   | 说明             |
| ------------------------------- | -------- | ---------------- |
| user32 函数 > 30                | +20      | GUI 复杂度       |
| 核心 DLL ≥ 10                   | +15      | 导入广度         |
| 有图标/对话框/清单              | +5/+5/+3 | 资源丰富度       |
| 版本信息完整                    | +8/+4    | 应用身份         |
| .NET 应用                       | +10      | 独立 UI 框架     |
| 桌面应用 stub（Electron/CEF）   | +20      | 启动器但真实应用 |
| 文件名含 crashpad/update 等     | **-15**  | 非主应用关键词   |
| 路径含 plugins/mui/resources 等 | **-15**  | 组件/插件路径    |
| stub 惩罚（非桌面应用）         | **-20**  | 空壳启动器       |
| 服务程序                        | **-15**  | Windows 服务     |

## 分类体系

| 分类        | 含义                  |
| ----------- | --------------------- |
| Portable    | 普通便携式应用        |
| Installer   | 安装程序              |
| Uninstaller | 卸载程序              |
| Launcher    | 启动器 / stub         |
| Service     | Windows 服务          |
| DotNet      | .NET 托管应用         |
| ConsoleTool | 控制台工具            |
| Other       | 其他（无窗口 GUI 等） |

## 已知局限

### 1. 插件与主应用无法区分（根本性问题）

许多插件和组件（如 WPS 的公式编辑器 EqnEdit、VS 的远程调试器 msvsmon、Thunder 的 BHO 安装程序）拥有完整的 Win32 消息循环，score_main 和真正的主应用一样高（90+）。**从 PE 结构上无法区分"主应用"和"插件"，因为两者的技术特征完全相同。**

目前的缓解措施：通过路径副分降权（`\ksee\`、`\BHO\`、`\plugins\`、`\conpty\` 等），在 score_main 相同时让真应用排在前面。

### 2. Electron 应用需要特殊处理

Electron 应用（VSCode、QQ、微信等）的主 exe 是一个 stub，没有自己的消息循环（score_main = 0）。这是框架设计和性能优化的结果，并非"非窗口应用"。

目前的缓解措施：通过 `is_desktop_app_stub()` 检测 Electron/CEF 特征（`chrome_elf.dll`、`dwrite.dll` + `version.dll`、`xweb_elf.dll` 等），在副分中给 +20 分，使其在排序时排在普通 stub 前面。

### 3. 路径/文件名关键词需要维护

插件和组件的扣分依赖于路径片段和文件名关键词列表。随着软件生态的变化，这些列表需要持续更新。

### 4. 部分合法 PE 文件无法解析

部分非标准 PE 文件（BaiduNetdisk 的 cmd.exe、Android NDK 的 ld.exe、macOS 资源叉文件 `._*.exe` 等）会被 pelite 拒绝，无法分析。

### 5. 不分析运行期行为

本工具只做静态 PE 分析，不执行任何代码。因此无法检测：

- 程序启动后是否立即退出
- 是否有隐藏窗口（如托盘图标应用）
- 是否通过脚本或其他进程间接创建窗口
- 安装程序解压后是否启动真正的安装界面

## 测试结果

对 `D:\software` 目录的 4358 个 EXE 分析结果：

```
score_main 分布：
  80-100:  61  ← 完整 GUI 应用
  60-80:  129  ← 中度 GUI
  40-60:   72
  20-40:   31
   0-20: 4027  ← Console/Stub/辅助工具
```

| 应用              | score_main | score_sub | 说明               |
| ----------------- | ---------- | --------- | ------------------ |
| WinRAR.exe        | 91         | 56        | 完整 GUI           |
| BaiduNetdisk.exe  | 91         | 56        | 完整 GUI           |
| ToDesk.exe        | 83         | 41        | 远程桌面           |
| WizTree.exe       | 76         | 52        | 磁盘分析           |
| notepad.exe       | 75         | 36        | 系统记事本         |
| Everything.exe    | 46         | 36        | 搜索工具（无菜单） |
| Code.exe (VSCode) | 0          | 41        | Electron stub      |
| QQ.exe            | 0          | 36        | Electron stub      |
| cmd.exe           | 0          | 0         | 控制台             |
| unins000.exe      | 0          | 28        | 卸载程序           |

## 技术栈

- **PE 解析**：[pelite](https://crates.io/crates/pelite) 0.10
- **序列化**：serde + serde_json
- **并发**：std::thread::scope
- **缓存**：单文件 JSON（`%TEMP%/winhostappexe-cache/cache.json`）
