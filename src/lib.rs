//! PE 文件分析器：判断 exe 双击后是否会弹出窗口，并分类其用途。
//!
//! 根据《Windows EXE 文件类型分类、用途与解析方式详解》重新设计。

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

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VersionSummary {
    pub original_filename: Option<String>,
    pub file_description: Option<String>,
    pub company_name: Option<String>,
    pub product_name: Option<String>,
    pub file_version: Option<String>,
}

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
    pub window_funcs: Vec<String>,
    pub all_dlls: Vec<String>,
    pub core_dlls: Vec<String>,
}

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

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

const SERVICE_FUNCS: &[&str] = &[
    "StartServiceCtrlDispatcherW", "StartServiceCtrlDispatcherA",
    "RegisterServiceCtrlHandlerW", "RegisterServiceCtrlHandlerA",
    "RegisterServiceCtrlHandlerExW", "RegisterServiceCtrlHandlerExA",
];

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

fn scan_imports64<'a>(
    pe: impl pe64::Pe<'a>,
    wf: &mut Vec<String>,
    sf: &mut Vec<String>,
    all: &mut Vec<String>,
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
                if dll == "user32.dll" && WINDOW_CREATE_FUNCS.contains(&fn_name.as_ref()) {
                    wf.push(fn_name.to_string());
                }
                if SERVICE_FUNCS.contains(&fn_name.as_ref()) {
                    sf.push(fn_name.to_string());
                }
            }
        }
    }
}

fn scan_imports32<'a>(
    pe: impl pe32::Pe<'a>,
    wf: &mut Vec<String>,
    sf: &mut Vec<String>,
    all: &mut Vec<String>,
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
                if dll == "user32.dll" && WINDOW_CREATE_FUNCS.contains(&fn_name.as_ref()) {
                    wf.push(fn_name.to_string());
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

fn enum_rsrc(root: &pelite::resources::Directory<'_>, hm: &mut bool, hd: &mut bool, hi: &mut bool) {
    for e in root.entries() {
        if let Ok(n) = e.name() {
            match n {
                Name::Id(5)  => *hd = true,
                Name::Id(14) => *hi = true,
                Name::Id(16) => {}
                Name::Id(24) => *hm = true,
                _ => {}
            }
        }
    }
}

/// 解析版本信息，返回 None 表示无 RT_VERSION。
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
// 构建结果
// ---------------------------------------------------------------

fn build(
    subsystem: Subsystem, wf: Vec<String>, all: Vec<String>,
    is_svc: bool, hm: bool, hd: bool, hi: bool,
    ver: Option<VersionSummary>, is_dn: bool, is_stub: bool,
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

    let mut r = AnalyzeResult {
        subsystem, has_window: has_w, window_funcs: wf, all_dlls: all,
        core_dlls: core, is_dotnet: is_dn, is_service: is_svc, is_stub,
        has_manifest: hm, has_dialog: hd, has_icon: hi,
        version: ver, classification: Classification::Other,
    };
    r.classification = classify(&r);
    r
}

// ---------------------------------------------------------------
// 核心分析
// ---------------------------------------------------------------

fn analyze64(bytes: &[u8], pf: pe64::PeFile<'_>) -> AnalyzeResult {
    let ss = Subsystem::from_u16(pf.optional_header().Subsystem);
    let mut wf = Vec::new(); let mut sf = Vec::new(); let mut all = Vec::new();
    if ss == Subsystem::Gui { scan_imports64(pf, &mut wf, &mut sf, &mut all); }
    all.sort(); all.dedup();
    let is_svc = !sf.is_empty();
    let is_dn = all.iter().any(|d| d == "mscoree.dll") || has_clr(bytes, true);
    let is_stub = ss == Subsystem::Gui && all.len() <= 8
        && !all.iter().any(|d| d == "user32.dll") && wf.is_empty() && !is_svc && !is_dn;
    let mut hm = false; let mut hd = false; let mut hi = false;
    let ver = if ss == Subsystem::Gui { analyze_rsrc_impl(&pf, &mut hm, &mut hd, &mut hi) } else { None };
    build(ss, wf, all, is_svc, hm, hd, hi, ver, is_dn, is_stub)
}

fn analyze32(bytes: &[u8], pf: pe32::PeFile<'_>) -> AnalyzeResult {
    let ss = Subsystem::from_u16(pf.optional_header().Subsystem);
    let mut wf = Vec::new(); let mut sf = Vec::new(); let mut all = Vec::new();
    if ss == Subsystem::Gui { scan_imports32(pf, &mut wf, &mut sf, &mut all); }
    all.sort(); all.dedup();
    let is_svc = !sf.is_empty();
    let is_dn = all.iter().any(|d| d == "mscoree.dll") || has_clr(bytes, false);
    let is_stub = ss == Subsystem::Gui && all.len() <= 8
        && !all.iter().any(|d| d == "user32.dll") && wf.is_empty() && !is_svc && !is_dn;
    let mut hm = false; let mut hd = false; let mut hi = false;
    let ver = if ss == Subsystem::Gui { analyze_rsrc32(&pf, &mut hm, &mut hd, &mut hi) } else { None };
    build(ss, wf, all, is_svc, hm, hd, hi, ver, is_dn, is_stub)
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
