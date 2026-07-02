//! playscript pretty — 从缓存读取 entries，精简后输出 JSON 数组。
//!
//! 不重新排序，仅保留必要字段，固定字段顺序。
//! 输出到缓存目录下的 exe-analysis.json。
//!
//! 运行: cargo run --example pretty

use std::fs;
use std::path::{Path, PathBuf};
use serde::Serialize;

use playscript::AnalyzeResult;
use playscript::VersionSummary;

// ═══════════════════════════════════════════════════════════════
//  可调参数
// ═══════════════════════════════════════════════════════════════

/// 输出文件名（放在缓存目录下）。
const OUTPUT_JSON: &str = "exe-analysis.json";

// ═══════════════════════════════════════════════════════════════

#[derive(Serialize)]
struct PrettyEntry {
    file: String,
    score: f64,
    classification: String,
    subsystem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<VersionSummary>,
    has_window: bool,
    has_icon: bool,
    is_dotnet: bool,
    is_service: bool,
    is_stub: bool,
    has_manifest: bool,
    has_dialog: bool,
    path: String,
}

fn cache_path() -> PathBuf {
    let mut p = PathBuf::from(std::env::temp_dir());
    p.push("playscript-cache");
    p.push("cache.json");
    p
}

#[derive(serde::Deserialize)]
struct CacheEntry {
    path: String,
    score: f64,
    result: AnalyzeResult,
}

#[derive(serde::Deserialize)]
struct CacheData {
    entries: Vec<CacheEntry>,
}

fn to_pretty(e: &CacheEntry) -> PrettyEntry {
    let file = Path::new(&e.path).file_name()
        .map(|s| s.to_string_lossy()).unwrap_or_default().to_string();
    PrettyEntry {
        file,
        score: e.score,
        classification: e.result.classification.as_str().to_string(),
        subsystem: e.result.subsystem.as_str().to_string(),
        has_window: e.result.has_window,
        has_icon: e.result.has_icon,
        is_dotnet: e.result.is_dotnet,
        is_service: e.result.is_service,
        is_stub: e.result.is_stub,
        has_manifest: e.result.has_manifest,
        has_dialog: e.result.has_dialog,
        version: e.result.version.clone(),
        path: e.path.clone(),
    }
}

fn main() {
    let cp = cache_path();
    println!("playscript pretty — 精简输出 entries\n");
    println!("缓存: {}", cp.display());

    let file = match fs::File::open(&cp) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("错误: 缓存不存在。请先运行 `cargo run --example find`");
            std::process::exit(1);
        }
    };
    let data: CacheData = match serde_json::from_reader(std::io::BufReader::new(file)) {
        Ok(d) => d,
        Err(e) => { eprintln!("错误: 缓存解析失败 → {e}"); std::process::exit(1); }
    };

    println!("共 {} 条 entries\n", data.entries.len());

    let arr: Vec<PrettyEntry> = data.entries.iter().map(to_pretty).collect();
    let json = serde_json::to_string_pretty(&arr).unwrap();

    let out = cache_path().parent().unwrap().join(OUTPUT_JSON);
    fs::write(&out, &json).unwrap();
    println!("已写入 {} ({} KB)", out.display(), json.len() / 1024);
}
