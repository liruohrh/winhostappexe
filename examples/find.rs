//! playscript find — 在目录树中查找 EXE，按两套分数排序输出。
//!
//! 排序规则：主分(降) → 副分(降) → 文件名(升) → 路径(升)
//!
//! 深度规则：只有目录中存在文件时才计为一层，纯子目录不计数。
//!
//! 运行:
//!   cargo run --example find                     # 完整扫描 + 分析
//!   cargo run --example find -- --recalc         # 仅重算缓存（排序/评分/统计）
//!   cargo run --example find -- --force          # 强制重分析（沿用缓存路径，免遍历）

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use playscript::{AnalyzeResult, analyze_exe};

// ═══════════════════════════════════════════════════════════════
//  可调参数
// ═══════════════════════════════════════════════════════════════

const ROOT_DIR: &str = r"D:\software";
const MAX_DEPTH: usize = 3;
const THREADS: usize = 0; // 0 = 自动（CPU核数的一半）
const USE_CACHE: bool = true;

// ═══════════════════════════════════════════════════════════════

fn find_exes(dir: &Path, depth: usize, results: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut files = Vec::new();
    let mut subdirs = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if path
            .extension()
            .map_or(false, |ext| ext.eq_ignore_ascii_case("exe"))
        {
            files.push(path);
        }
    }
    let next = if files.is_empty() { depth } else { depth + 1 };
    results.extend(files);
    if next <= MAX_DEPTH {
        for sd in &subdirs {
            find_exes(sd, next, results);
        }
    }
}

// ─── 缓存 ──────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct CacheEntry {
    path: String,
    mtime_secs: u64,
    score_main: f64,
    score_sub: f64,
    result: AnalyzeResult,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheStats {
    total: usize,
    score_ranges: serde_json::Value,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheData {
    version: u32,
    stats: Option<CacheStats>,
    entries: Vec<CacheEntry>,
}

fn cache_path() -> PathBuf {
    let mut p = PathBuf::from(std::env::temp_dir());
    p.push("playscript-cache");
    let _ = fs::create_dir_all(&p);
    p.push("cache.json");
    p
}

fn load_cache_entries() -> Vec<CacheEntry> {
    let path = cache_path();
    let file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let reader = std::io::BufReader::new(file);
    match serde_json::from_reader::<_, CacheData>(reader) {
        Ok(d) if d.version == 2 => d.entries,
        _ => Vec::new(),
    }
}

fn build_cache_set(entries: &[CacheEntry]) -> HashSet<String> {
    entries.iter().map(|e| e.path.clone()).collect()
}

/// 保存缓存，统计主分各分段数量（满分 100，每 20 分一档）。
fn save_cache(entries: &[CacheEntry]) {
    let total = entries.len();
    let mut r0 = 0usize;
    let mut r20 = 0;
    let mut r40 = 0;
    let mut r60 = 0;
    let mut r80 = 0;
    for e in entries {
        let s = e.score_main;
        if s <= 20.0 {
            r0 += 1;
        } else if s <= 40.0 {
            r20 += 1;
        } else if s <= 60.0 {
            r40 += 1;
        } else if s <= 80.0 {
            r60 += 1;
        } else {
            r80 += 1;
        }
    }
    let pct = |c: usize| -> String {
        if total == 0 {
            "0.0%".into()
        } else {
            format!("{:.1}%", c as f64 / total as f64 * 100.0)
        }
    };
    let ranges = serde_json::json!([
        { "range": "80-100", "count": r80, "percent": pct(r80) },
        { "range": "60-80",  "count": r60, "percent": pct(r60) },
        { "range": "40-60",  "count": r40, "percent": pct(r40) },
        { "range": "20-40",  "count": r20, "percent": pct(r20) },
        { "range": "0-20",   "count": r0,  "percent": pct(r0) },
    ]);

    let data = CacheData {
        version: 2,
        stats: Some(CacheStats {
            total,
            score_ranges: ranges,
        }),
        entries: entries.to_vec(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&data) {
        let _ = fs::write(cache_path(), &json);
    }
    println!(
        "  缓存: {} 条 | 80-100:{} 60-80:{} 40-60:{} 20-40:{} 0-20:{}",
        total, r80, r60, r40, r20, r0
    );
}

fn file_mtime(path: &Path) -> Option<u64> {
    let meta = fs::metadata(path).ok()?;
    let dur = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some(dur.as_secs())
}

fn analyze_one(
    path: &Path,
    cache_map: &HashSet<String>,
    entries: &mut Vec<CacheEntry>,
) -> Option<(String, AnalyzeResult)> {
    let path_str = path.to_string_lossy().to_string();
    let abs_path = fs::canonicalize(path).ok()?;
    let abs_str = abs_path.to_string_lossy().to_string();
    let mtime = file_mtime(path)?;

    if USE_CACHE && cache_map.contains(&abs_str) {
        if let Some(entry) = entries.iter().find(|e| e.path == abs_str) {
            if entry.mtime_secs == mtime {
                return Some((path_str, entry.result.clone()));
            }
        }
    }

    let result = match analyze_exe(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("\n  分析失败: {path_str} → {e}");
            return None;
        }
    };
    entries.push(CacheEntry {
        path: abs_str,
        mtime_secs: mtime,
        score_main: result.score_main,
        score_sub: result.score_sub,
        result: result.clone(),
    });
    Some((path_str, result))
}

// ─── 核心流程 ─────────────────────────────────────────────

fn run_pipeline(exe_paths: Vec<PathBuf>, cache_entries_init: Vec<CacheEntry>) {
    let n_threads = if THREADS == 0 { num_cpus() } else { THREADS };
    let cache_entries = Mutex::new(cache_entries_init);
    let cache_set = Mutex::new(HashSet::new());

    {
        let entries = cache_entries.lock().unwrap();
        *cache_set.lock().unwrap() = build_cache_set(&entries);
    }

    let results = Mutex::new(Vec::with_capacity(exe_paths.len()));
    let progress = Mutex::new(0usize);
    let total = exe_paths.len();

    std::thread::scope(|s| {
        let chunk_size = (total + n_threads - 1) / n_threads;
        for chunk in exe_paths.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let cache_entries = &cache_entries;
            let cache_set = &cache_set;
            let results = &results;
            let progress = &progress;
            s.spawn(move || {
                for path in &chunk {
                    if let Some((p, r)) = analyze_one(
                        path,
                        &cache_set.lock().unwrap(),
                        &mut cache_entries.lock().unwrap(),
                    ) {
                        results.lock().unwrap().push((p, r));
                    }
                    let mut pg = progress.lock().unwrap();
                    *pg += 1;
                    if *pg % 10 == 0 || *pg == total {
                        eprint!("\r  进度: {}/{}", *pg, total);
                    }
                }
            });
        }
    });
    println!("\n");

    let final_entries = cache_entries.into_inner().unwrap();

    // 排序
    let mut sorted: Vec<(String, AnalyzeResult)> = results.into_inner().unwrap();
    for (p, r) in &mut sorted {
        if let Ok(abs) = fs::canonicalize(p) {
            let a = abs.to_string_lossy().to_string();
            if let Some(e) = final_entries.iter().find(|e| e.path == a) {
                r.score_main = e.score_main;
                r.score_sub = e.score_sub;
            }
        }
    }
    sorted.sort_by(|(a_p, a_r), (b_p, b_r)| {
        b_r.score_main
            .partial_cmp(&a_r.score_main)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b_r.score_sub
                    .partial_cmp(&a_r.score_sub)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                let fa = Path::new(a_p).file_name().map(|s| s.to_ascii_lowercase());
                let fb = Path::new(b_p).file_name().map(|s| s.to_ascii_lowercase());
                fa.cmp(&fb)
            })
            .then_with(|| a_p.cmp(b_p))
    });

    // 保存缓存
    if USE_CACHE {
        let mut all: Vec<CacheEntry> = final_entries;
        let existing: HashSet<String> = all.iter().map(|e| e.path.clone()).collect();
        for item in &sorted {
            if let Ok(abs) = fs::canonicalize(&item.0) {
                let a = abs.to_string_lossy().to_string();
                if !existing.contains(&a) {
                    all.push(CacheEntry {
                        path: a,
                        mtime_secs: 0,
                        score_main: item.1.score_main,
                        score_sub: item.1.score_sub,
                        result: item.1.clone(),
                    });
                }
            }
        }
        all.sort_by(|a, b| {
            b.score_main
                .partial_cmp(&a.score_main)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    b.score_sub
                        .partial_cmp(&a.score_sub)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    let fa = Path::new(&a.path)
                        .file_name()
                        .map(|s| s.to_ascii_lowercase());
                    let fb = Path::new(&b.path)
                        .file_name()
                        .map(|s| s.to_ascii_lowercase());
                    fa.cmp(&fb)
                })
                .then_with(|| a.path.cmp(&b.path))
        });
        save_cache(&all);
    }
}

fn num_cpus() -> usize {
    std::cmp::max(
        1,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            / 2,
    )
}

// ─── 入口 ────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let recalc_only = args.iter().any(|a| a == "--recalc");
    let force_mode = args.iter().any(|a| a == "--force");

    if recalc_only {
        println!("playscript find — 仅重算缓存\n{}", cache_path().display());
        let mut entries = load_cache_entries();
        if entries.is_empty() {
            eprintln!("错误: 缓存为空");
            std::process::exit(1);
        }
        println!("加载: {} 条\n", entries.len());

        let mut changed = 0;
        for e in &mut entries {
            let nsm = e.result.score_main;
            let nss = e.result.score_sub;
            if (e.score_main - nsm).abs() > 0.01 || (e.score_sub - nss).abs() > 0.01 {
                changed += 1;
            }
            e.score_main = nsm;
            e.score_sub = nss;
        }
        println!("重算: {} 条变更", changed);

        entries.sort_by(|a, b| {
            b.score_main
                .partial_cmp(&a.score_main)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    b.score_sub
                        .partial_cmp(&a.score_sub)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| {
                    let fa = Path::new(&a.path)
                        .file_name()
                        .map(|s| s.to_ascii_lowercase());
                    let fb = Path::new(&b.path)
                        .file_name()
                        .map(|s| s.to_ascii_lowercase());
                    fa.cmp(&fb)
                })
                .then_with(|| a.path.cmp(&b.path))
        });
        save_cache(&entries);
        return;
    }

    if force_mode {
        let cached = load_cache_entries();
        if !cached.is_empty() {
            let paths: Vec<PathBuf> = cached.iter().map(|e| PathBuf::from(&e.path)).collect();
            println!(
                "playscript find --force\n{}\n从缓存读取 {} 条路径，跳过目录遍历",
                cache_path().display(),
                paths.len()
            );
            run_pipeline(paths, Vec::new());
            return;
        }
        println!("缓存为空，回退到目录遍历");
    }

    println!(
        "playscript find\n{}\n线程: {}",
        cache_path().display(),
        if THREADS == 0 {
            format!("{} (CPU/2)", num_cpus())
        } else {
            THREADS.to_string()
        }
    );

    let root = Path::new(ROOT_DIR);
    if !root.exists() {
        eprintln!("错误: {} 不存在", ROOT_DIR);
        std::process::exit(1);
    }

    let mut exe_paths = Vec::new();
    find_exes(root, 0, &mut exe_paths);
    println!("找到 {} 个 EXE\n", exe_paths.len());
    if exe_paths.is_empty() {
        return;
    }

    let cache_init = if USE_CACHE {
        load_cache_entries()
    } else {
        Vec::new()
    };
    run_pipeline(exe_paths, cache_init);
}
