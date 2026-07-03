//! playscript pretty — 从缓存读取 entries，精简后输出 JSON 数组。
//!
//! 不重新排序，仅保留必要字段，固定字段顺序。
//! 输出到缓存目录下的 exe-analysis.json。
//!
//! 运行: cargo run --example pretty

use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use playscript::AnalyzeResult;

const OUTPUT_JSON: &str = "exe-analysis.json";

#[derive(Serialize)]
struct PrettyEntry {
    file: String,
    score_main: f64,
    score_sub: f64,
    classification: String,
    subsystem: String,
    has_window: bool,
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
    score_main: f64,
    score_sub: f64,
    result: AnalyzeResult,
}

#[derive(serde::Deserialize)]
struct CacheData {
    entries: Vec<CacheEntry>,
}

fn to_pretty(e: &CacheEntry) -> PrettyEntry {
    let file = Path::new(&e.path)
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default()
        .to_string();
    PrettyEntry {
        file,
        score_main: e.score_main,
        score_sub: e.score_sub,
        classification: e.result.classification.as_str().to_string(),
        subsystem: e.result.subsystem.as_str().to_string(),
        has_window: e.result.has_window,
        path: e.path.clone(),
    }
}

fn main() {
    let cp = cache_path();
    println!("playscript pretty\n{}\n", cp.display());

    let file = match fs::File::open(&cp) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("错误: 缓存不存在");
            std::process::exit(1);
        }
    };
    let data: CacheData = match serde_json::from_reader(std::io::BufReader::new(file)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("错误: {e}");
            std::process::exit(1);
        }
    };

    println!("{} 条 entries\n", data.entries.len());

    let arr: Vec<PrettyEntry> = data.entries.iter().map(to_pretty).collect();
    let json = serde_json::to_string_pretty(&arr).unwrap();

    let out = cache_path().parent().unwrap().join(OUTPUT_JSON);
    fs::write(&out, &json).unwrap();
    println!("写入 {} ({} KB)", out.display(), json.len() / 1024);
}
