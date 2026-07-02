//! PE 文件分析器：判断 exe 双击后是否会弹出窗口，并分类其用途。
//!
//! 根据《Windows EXE 文件类型分类、用途与解析方式详解》重新设计。
//!
//! # 得分体系
//!
//! 两套分数从不同维度衡量一个 EXE "像窗口主程序"的程度：
//!
//! - **主分数**（score_main, 0-10）：强信号。基于 Win32 消息循环体系的函数导入。
//!   真正自己创建窗口、管理消息循环的应用必会导入 GetMessageW + DispatchMessageW
//!   + DefWindowProcW 等函数；而仅使用 DialogBoxParam 的辅助工具不会导入这些。
//!
//! - **副分数**（score_sub, 0-10）：弱信号。基于资源丰富度、DLL 导入广度、
//!   版本信息完整度等辅助指标。

use std::fs;
use std::path::Path;

use pelite::pe64;
use pelite::pe32;
use pelite::pe64::Pe as _;
use pelite::pe32::Pe as _;
use pelite::image::{IMAGE_SUBSYSTEM_WINDOWS_GUI, IMAGE_SUBSYSTEM_WINDOWS_CUI, IMAGE_SUBSYSTEM_NATIVE};
use pelite::resources::Name;

// ---------------------------------------------------------------------------
// 公开类型
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Subsystem {
    Gui, Console, Native, Other(u16),
}
impl Subsystem {
    fn from_u16(v: u16) -> Self {
        match v {
            IMAGE_SUBSYSTEM_WINDOWS_GUI => Subsystem::Gui,
            IMAGE_SUBSYSTEM_WINDOWS_CUI => Subsystem::Console,
            IMAGE_SUBSYSTEM_NATIVE => Subsystem::Native,
            x => Subsystem::Other(x),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Subsystem::Gui => "GUI", Subsystem::Console => "Console",
            Subsystem::Native => "Native", Subsystem::Other(_) => "Other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Classification {
    Portable, Installer, Uninstaller, SfxArchive,
    Launcher, Service, DotNet, WebView, ConsoleTool, Other,
}
impl Classification {
    pub fn as_str(&self) -> &'static str {
        use Classification::*;
        match self {
            Portable => "Portable", Installer => "Installer",
            Uninstaller => "Uninstaller", SfxArchive => "SFX",
            Launcher => "Launcher", Service => "Service",
            DotNet => ".NET", WebView => "WebView",
            ConsoleTool => "Console", Other => "Other",
        }
    }
}

/// 版本信息摘要，从 RT_VERSION 资源解析。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VersionSummary {
    pub original_filename: Option<String>,
    pub file_description: Option<String>,
    pub company_name: Option<String>,
    pub product_name: Option<String>,
    pub file_version: Option<String>,
}

/// PE 分析完整结果。
///
/// 得分字段说明：
/// - `score_main`（主分数）：反映程序是否拥有完整的 Win32 消息循环体系。
///   真正自己创建窗口、运行消息循环的应用得分高。
/// - `score_sub`（副分数）：反映资源丰富度、DLL 导入多样性和其他辅助特征。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalyzeResult {
    pub subsystem: Subsystem,
    pub classification: Classification,
    pub has_window: bool,
    pub has_icon: bool,
    pub is_dotnet: bool,
    pub is_service: bool,
    pub is_stub: bool,
    pub has_manifest: bool,
    pub has_dialog: bool,
    pub version: Option<VersionSummary>,
    // 导入表相关
    pub window_funcs: Vec<String>,   // 命中的窗口创建函数列表
    pub all_dlls: Vec<String>,       // 所有导入的 DLL 名
    pub core_dlls: Vec<String>,      // 常见系统 DLL 子集
    pub user32_funcs: Vec<String>,   // 从 user32.dll 导入的所有函数名
    // 两套分数
    pub score_main: f64,             // 主分 0-10：消息循环等强信号
    pub score_sub: f64,              // 副分 0-10：资源/导入等弱信号
}

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// 窗口创建函数——有其中任意一个表明该 EXE 可能创建窗口界面。
pub const WINDOW_CREATE_FUNCS: &[&str] = &[
    "CreateWindowExA", "CreateWindowExW",
    "RegisterClassA", "RegisterClassW",
    "RegisterClassExA", "RegisterClassExW",
    "DialogBoxParamA", "DialogBoxParamW",
    "DialogBoxIndirectParamA", "DialogBoxIndirectParamW",
    "CreateDialogParamA", "CreateDialogParamW",
    "MessageBoxA", "MessageBoxW",
    "MessageBoxExA", "MessageBoxExW",
    "PropertySheetA", "PropertySheetW",
];

/// Windows 服务特征函数——用于识别服务程序。
const SERVICE_FUNCS: &[&str] = &[
    "StartServiceCtrlDispatcherW", "StartServiceCtrlDispatcherA",
    "RegisterServiceCtrlHandlerW", "RegisterServiceCtrlHandlerA",
    "RegisterServiceCtrlHandlerExW", "RegisterServiceCtrlHandlerExA",
];

/// 主分（强信号）：拥有自己消息循环体系的 Win32 函数。
/// 真正创建窗口的 GUI 程序必须拥有自己的消息循环
/// （GetMessage → TranslateMessage → DispatchMessage），
/// 而仅用 DialogBoxParam 的辅助工具由系统提供内部循环，不会导入这些函数。
const _MAIN_SCORE_FUNCS: &[&str] = &[
    // === 消息循环核心（窗口应用刚需，辅助工具几乎从不导入）===
    "DispatchMessageW", "DispatchMessageA",     // 分派消息到窗口过程 ← 最强信号
    "GetMessageW", "GetMessageA",               // 从消息队列取消息
    "DefWindowProcW", "DefWindowProcA",          // 默认窗口过程（对话框用 DefDlgProc，不同函数）
    "TranslateMessage",                          // 虚拟键 → 字符消息转换
    "BeginPaint", "EndPaint",                    // WM_PAINT 绘画（对话框不需要）
    // === 窗口管理 ===
    "ShowWindow",                                // 显式控制窗口可见性
    "UpdateWindow",                              // 强制立即重绘
    "GetDC", "ReleaseDC",                        // 获取/释放设备上下文
    "InvalidateRect",                            // 主动请求重绘
    // === 菜单 & 快捷键 ===
    "CreateMenu", "AppendMenuW", "AppendMenuA",
    "TrackPopupMenu",                            // 上下文菜单
    "SetMenu",                                   // 设置窗口菜单栏
    "TranslateAccelerator",                      // 快捷键翻译
    // === 窗口管理进阶 ===
    "SetWindowPos", "MoveWindow",                // 管理窗口位置/大小
    "SetWindowLongPtrW", "SetWindowLongPtrA",    // 窗口子类化
    "SetCapture",                                // 鼠标捕获
    "SetTimer",                                  // 定时器
    "GetSystemMetrics",                          // 系统度量信息
    "DragAcceptFiles",                           // 拖放支持
];

/// 常见系统 DLL（用于副分统计 core_dlls 数量）。
const CORE_DLLS: &[&str] = &[
    "kernel32.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "shell32.dll", "ole32.dll",
    "oleaut32.dll", "comctl32.dll", "comdlg32.dll",
    "ws2_32.dll", "winhttp.dll", "wininet.dll",
    "ntdll.dll", "msvcrt.dll", "crypt32.dll",
    "shlwapi.dll", "version.dll",
];

// ---------------------------------------------------------------------------
// 内部工具
// ---------------------------------------------------------------------------

fn cstr_lower(c: &pelite::util::CStr) -> String {
    String::from_utf8_lossy(c.as_ref()).to_lowercase()
}

// ---------------------------------------------------------------
// 导入表扫描
// ---------------------------------------------------------------

/// 扫描 64-bit PE 导入表，收集：
/// - wf: 窗口创建函数
/// - sf: 服务特征函数
/// - all: 所有 DLL 名
/// - uf: user32.dll 的所有导入函数名（用于后续计算主/副分数）
fn scan_imports64<'a>(
    pe: impl pe64::Pe<'a>,
    wf: &mut Vec<String>,
    sf: &mut Vec<String>,
    all: &mut Vec<String>,
    uf: &mut Vec<String>,
) {
    let imports = match pe.imports() {
        Ok(imp) => imp,
        Err(_) => return,
    };
    for desc in imports {
        let dll = match desc.dll_name() {
            Ok(n) => cstr_lower(n),
            Err(_) => continue,
        };
        all.push(dll.clone());
        let int = match desc.int() {
            Ok(it) => it,
            Err(_) => continue,
        };
        for imp in int {
            let imp = match imp {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let pe64::imports::Import::ByName { name, .. } = imp {
                let fn_name = String::from_utf8_lossy(name.as_ref());
                if dll == "user32.dll" {
                    // 收集 user32.dll 的全部函数名（用于主/副分计算）
                    uf.push(fn_name.to_string());
                    if WINDOW_CREATE_FUNCS.contains(&fn_name.as_ref()) {
                        wf.push(fn_name.to_string());
                    }
                }
                if SERVICE_FUNCS.contains(&fn_name.as_ref()) {
                    sf.push(fn_name.to_string());
                }
            }
        }
    }
}

/// 扫描 32-bit PE 导入表，同上。
fn scan_imports32<'a>(
    pe: impl pe32::Pe<'a>,
    wf: &mut Vec<String>,
    sf: &mut Vec<String>,
    all: &mut Vec<String>,
    uf: &mut Vec<String>,
) {
    let imports = match pe.imports() {
        Ok(imp) => imp,
        Err(_) => return,
    };
    for desc in imports {
        let dll = match desc.dll_name() {
            Ok(n) => cstr_lower(n),
            Err(_) => continue,
        };
        all.push(dll.clone());
        let int = match desc.int() {
            Ok(it) => it,
            Err(_) => continue,
        };
        for imp in int {
            let imp = match imp {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let pe32::imports::Import::ByName { name, .. } = imp {
                let fn_name = String::from_utf8_lossy(name.as_ref());
                if dll == "user32.dll" {
                    uf.push(fn_name.to_string());
                    if WINDOW_CREATE_FUNCS.contains(&fn_name.as_ref()) {
                        wf.push(fn_name.to_string());
                    }
                }
                if SERVICE_FUNCS.contains(&fn_name.as_ref()) {
                    sf.push(fn_name.to_string());
                }
            }
        }
    }
}

// ---------------------------------------------------------------
// 资源分析
// ---------------------------------------------------------------

/// 枚举 PE 资源根目录，标记是否存在各类型资源。
fn enum_rsrc(root: &pelite::resources::Directory<'_>, hm: &mut bool, hd: &mut bool, hi: &mut bool) {
    for e in root.entries() {
        if let Ok(n) = e.name() {
            match n {
                Name::Id(5)  => *hd = true,   // RT_DIALOG：对话框资源
                Name::Id(14) => *hi = true,    // RT_GROUP_ICON：图标
                Name::Id(16) => {}              // RT_VERSION：版本信息（仅检测，不含值）
                Name::Id(24) => *hm = true,    // RT_MANIFEST：应用程序清单
                _ => {}
            }
        }
    }
}

/// 解析版本信息，无 RT_VERSION 则返回 None。
fn parse_ver(rsrc: &pelite::resources::Resources<'_>) -> Option<VersionSummary> {
    let vi = rsrc.version_info().ok()?;
    let lang = vi.translation().first().copied()?;
    let mut ver = VersionSummary::default();
    if let Some(v) = vi.value(lang, "OriginalFilename") { ver.original_filename = Some(v); }
    if let Some(v) = vi.value(lang, "FileDescription")  { ver.file_description = Some(v); }
    if let Some(v) = vi.value(lang, "CompanyName")      { ver.company_name = Some(v); }
    if let Some(v) = vi.value(lang, "ProductName")      { ver.product_name = Some(v); }
    if let Some(v) = vi.value(lang, "FileVersion")      { ver.file_version = Some(v); }
    Some(ver)
}

fn analyze_rsrc_impl<'a>(
    pf: &impl pe64::Pe<'a>,
    hm: &mut bool, hd: &mut bool, hi: &mut bool,
) -> Option<VersionSummary> {
    let rsrc = match pf.resources() { Ok(r) => r, Err(_) => return None };
    let root = match rsrc.root() { Ok(r) => r, Err(_) => return None };
    enum_rsrc(&root, hm, hd, hi);
    parse_ver(&rsrc)
}

fn analyze_rsrc32<'a>(
    pf: &impl pe32::Pe<'a>,
    hm: &mut bool, hd: &mut bool, hi: &mut bool,
) -> Option<VersionSummary> {
    let rsrc = match pf.resources() { Ok(r) => r, Err(_) => return None };
    let root = match rsrc.root() { Ok(r) => r, Err(_) => return None };
    enum_rsrc(&root, hm, hd, hi);
    parse_ver(&rsrc)
}

/// 检查 PE 文件中是否存在 .NET CLR 头（COM 描述符目录）。
fn has_clr(bytes: &[u8], is64: bool) -> bool {
    if bytes.len() < 300 || bytes[0] != 0x4d || bytes[1] != 0x5a { return false; }
    let pe_off = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    if pe_off + 6 > bytes.len() { return false; }
    let dd_off = (pe_off + 24) + if is64 { 112 } else { 96 };
    let com_off = dd_off + 14 * 8;
    if com_off + 8 > bytes.len() { return false; }
    u32::from_le_bytes([bytes[com_off], bytes[com_off+1], bytes[com_off+2], bytes[com_off+3]]) != 0
}

// ---------------------------------------------------------------
// 分类
// ---------------------------------------------------------------

fn classify(r: &AnalyzeResult) -> Classification {
    use Classification::*;
    if r.subsystem == Subsystem::Console { return ConsoleTool; }
    if r.is_dotnet { return DotNet; }
    if r.is_service { return Service; }
    if r.is_stub { return Launcher; }
    if let Some(ref ver) = r.version {
        if let Some(ref ofn) = ver.original_filename {
            let l = ofn.to_lowercase();
            if l.contains("unins") || l.contains("uninstall") { return Uninstaller; }
            if l.contains("setup") || l.contains("install")  { return Installer; }
        }
        if let Some(ref fd) = ver.file_description {
            let l = fd.to_lowercase();
            if l.contains("uninstall") { return Uninstaller; }
            if l.contains("setup") || l.contains("install") { return Installer; }
        }
    }
    if !r.has_window { return Other; }
    Portable
}

// ---------------------------------------------------------------
// 得分计算
// ---------------------------------------------------------------

/// 计算主分数（0-10）：基于消息循环体系的强信号。
///
/// 核心思路：真正窗口应用必须有 `GetMessage → DispatchMessage` 消息循环，
/// 辅助工具（bugreport/crashpad/dpinst 等）只用 DialogBoxParam 自带循环，
/// 不会导入 `DispatchMessageW`、`DefWindowProcW`、`BeginPaint` 等函数。
fn compute_score_main(user32_funcs: &[String]) -> f64 {
    let mut s = 0.0_f64;
    let mut has_get_msg = false;
    let mut has_dispatch = false;

    // 遍历 user32.dll 的导入函数，逐项打分
    for f in user32_funcs {
        let name = f.as_str();
        match name {
            // ── 消息循环核心（+2.0 基础，两者兼得再 +1.0）──
            "GetMessageW" | "GetMessageA" => {
                if !has_get_msg { s += 2.0; has_get_msg = true; }
            }
            "DispatchMessageW" | "DispatchMessageA" => {
                if !has_dispatch { s += 2.0; has_dispatch = true; }
            }
            "DefWindowProcW" | "DefWindowProcA" => s += 1.5,

            // ── WM_PAINT 绘制体系 ──
            "BeginPaint" => { if user32_funcs.iter().any(|x| x == "EndPaint") { s += 1.0; } }
            "EndPaint" => {} // 和 BeginPaint 成对计分

            // ── 窗口管理 ──
            "ShowWindow"         => s += 0.5,
            "UpdateWindow"       => s += 0.3,
            "InvalidateRect"     => s += 0.5,
            "GetDC"             => { if user32_funcs.iter().any(|x| x == "ReleaseDC") { s += 0.5; } }
            "ReleaseDC"          => {}

            // ── 菜单 ──
            "CreateMenu" | "AppendMenuW" | "AppendMenuA" => {
                s += 0.5;
            }
            "TrackPopupMenu" => s += 0.5,

            // ── 快捷键 ──
            "TranslateAccelerator" => s += 0.5,

            // ── 窗口管理进阶 ──
            "SetWindowPos" | "MoveWindow" => s += 0.5,
            "SetWindowLongPtrW" | "SetWindowLongPtrA" => s += 0.5,
            "SetCapture" => s += 0.3,
            "SetTimer"   => s += 0.3,
            "GetSystemMetrics" => s += 0.3,
            "DragAcceptFiles"  => s += 0.3,
            "TranslateMessage" => s += 0.3,

            _ => {}
        }
    }

    // GetMessage + DispatchMessage 两者兼得 → 强窗口应用特征
    if has_get_msg && has_dispatch { s += 1.0; }

    // 裁剪到 0-10
    (s * 10.0).round() / 10.0
}

/// 计算副分数（0-10）：资源丰富度、DLL 导入广度等弱信号。
fn compute_score_sub(r: &AnalyzeResult, user32_func_count: usize) -> f64 {
    let mut s = 0.0_f64;
    if r.subsystem != Subsystem::Gui { return 0.0; }

    // user32.dll 导入函数数量：真 GUI 通常 > 25 个，辅助工具通常 < 10 个
    if user32_func_count > 25 { s += 1.5; }
    else if user32_func_count > 10 { s += 0.5; }

    // 核心 DLL 丰富度：真 GUI 通常同时导入 gdi32 + shell32 + comctl32 等
    let core_count = r.core_dlls.len();
    if core_count >= 8 { s += 1.5; }
    else if core_count >= 6 { s += 1.0; }
    else if core_count >= 4 { s += 0.5; }

    // 缺 gdi32 扣分（辅助工具常见）
    if !r.core_dlls.iter().any(|d| d == "gdi32.dll") { s -= 0.5; }

    // 资源丰富度
    if r.has_icon    { s += 0.5; }
    if r.has_dialog  { s += 0.5; }
    if r.has_manifest { s += 0.3; }

    // 有版本信息且填写较完整
    if let Some(ref ver) = r.version {
        let filled = [&ver.original_filename, &ver.file_description, &ver.company_name,
                       &ver.product_name, &ver.file_version].iter()
            .filter(|x| x.is_some()).count();
        if filled >= 3 { s += 0.5; }
        if filled >= 5 { s += 0.5; }
    }

    // .NET 应用有自己独立的 UI 框架
    if r.is_dotnet { s += 1.0; }

    // 是 stub 或 service → 非窗口应用
    if r.is_stub    { s -= 1.5; }
    if r.is_service { s -= 1.0; }

    // 裁剪到 0-10
    (s * 10.0).round() / 10.0
}

// ---------------------------------------------------------------
// 构建结果（含得分计算）
// ---------------------------------------------------------------

fn build(
    subsystem: Subsystem, wf: Vec<String>, all: Vec<String>,
    is_svc: bool, hm: bool, hd: bool, hi: bool,
    ver: Option<VersionSummary>, is_dn: bool, is_stub: bool,
    uf: Vec<String>,
) -> AnalyzeResult {
    let has_w = !wf.is_empty()
        || (subsystem == Subsystem::Gui && hd)
        || (subsystem == Subsystem::Gui && is_dn)
        || (subsystem == Subsystem::Gui && hi && !is_stub);

    let core = {
        let mut v: Vec<String> = all.iter()
            .filter(|d| CORE_DLLS.contains(&d.as_str()))
            .cloned().collect();
        v.sort(); v.dedup(); v
    };

    // 计算得分
    let user32_count = uf.len();
    let score_main = compute_score_main(&uf);
    let mut r = AnalyzeResult {
        subsystem, has_window: has_w, window_funcs: wf, all_dlls: all,
        core_dlls: core, is_dotnet: is_dn, is_service: is_svc, is_stub,
        has_manifest: hm, has_dialog: hd, has_icon: hi,
        version: ver, classification: Classification::Other,
        user32_funcs: uf,
        score_main, score_sub: 0.0, // 副分需要完整 AnalyzeResult 才能算
    };
    r.score_sub = compute_score_sub(&r, user32_count);
    r.classification = classify(&r);
    r
}

// ---------------------------------------------------------------
// 核心分析
// ---------------------------------------------------------------

fn analyze64(bytes: &[u8], pf: pe64::PeFile<'_>) -> AnalyzeResult {
    let ss = Subsystem::from_u16(pf.optional_header().Subsystem);
    let mut wf = Vec::new(); let mut sf = Vec::new();
    let mut all = Vec::new(); let mut uf = Vec::new();
    if ss == Subsystem::Gui { scan_imports64(pf, &mut wf, &mut sf, &mut all, &mut uf); }
    all.sort(); all.dedup();
    let is_svc = !sf.is_empty();
    let is_dn = all.iter().any(|d| d == "mscoree.dll") || has_clr(bytes, true);
    let is_stub = ss == Subsystem::Gui && all.len() <= 8
        && !all.iter().any(|d| d == "user32.dll") && wf.is_empty() && !is_svc && !is_dn;
    let mut hm = false; let mut hd = false; let mut hi = false;
    let ver = if ss == Subsystem::Gui { analyze_rsrc_impl(&pf, &mut hm, &mut hd, &mut hi) } else { None };
    build(ss, wf, all, is_svc, hm, hd, hi, ver, is_dn, is_stub, uf)
}

fn analyze32(bytes: &[u8], pf: pe32::PeFile<'_>) -> AnalyzeResult {
    let ss = Subsystem::from_u16(pf.optional_header().Subsystem);
    let mut wf = Vec::new(); let mut sf = Vec::new();
    let mut all = Vec::new(); let mut uf = Vec::new();
    if ss == Subsystem::Gui { scan_imports32(pf, &mut wf, &mut sf, &mut all, &mut uf); }
    all.sort(); all.dedup();
    let is_svc = !sf.is_empty();
    let is_dn = all.iter().any(|d| d == "mscoree.dll") || has_clr(bytes, false);
    let is_stub = ss == Subsystem::Gui && all.len() <= 8
        && !all.iter().any(|d| d == "user32.dll") && wf.is_empty() && !is_svc && !is_dn;
    let mut hm = false; let mut hd = false; let mut hi = false;
    let ver = if ss == Subsystem::Gui { analyze_rsrc32(&pf, &mut hm, &mut hd, &mut hi) } else { None };
    build(ss, wf, all, is_svc, hm, hd, hi, ver, is_dn, is_stub, uf)
}

// ---------------------------------------------------------------
// 公开 API
// ---------------------------------------------------------------

/// 分析 PE 文件，返回结构化的结果。
pub fn analyze_exe<P: AsRef<Path>>(path: P) -> Result<AnalyzeResult, Box<dyn std::error::Error>> {
    let bytes = fs::read(path.as_ref())?;
    if let Ok(pf) = pe64::PeFile::from_bytes(&bytes) {
        return Ok(analyze64(&bytes, pf));
    }
    if let Ok(pf) = pe32::PeFile::from_bytes(&bytes) {
        return Ok(analyze32(&bytes, pf));
    }
    Err("Not a valid PE file".into())
}
