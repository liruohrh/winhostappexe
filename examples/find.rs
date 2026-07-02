//! playscript find — 在目录树中查找 EXE 并按"像窗口应用的程度"排序输出。
//!
//! 深度规则：只有目录中存在文件时才计为一层，纯子目录不算层。
//! 分类规则：按导入表 + 资源判断是否双击后会弹出窗口。
//!
//! 运行: cargo run --example find        # 完整扫描 + 分析
//!       cargo run --example find -- --recalc   # 仅重算缓存（排序/评分/统计）

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use playscript::{analyze_exe, AnalyzeResult, Subsystem};

// ═══════════════════════════════════════════════════════════════
//  可调参数 — 只需改这里
// ═══════════════════════════════════════════════════════════════

/// 要扫描的根目录。
const ROOT_DIR: &str = r"D:\software";

/// 最大层级（有文件的目录才算一层，纯子目录不计数）。
const MAX_DEPTH: usize = 3;

/// 并发分析线程数（0 = 自动，按 CPU 核数）。
const THREADS: usize = 0;

/// 是否启用缓存（存到 %TEMP%/playscript-cache/）。
const USE_CACHE: bool = true;

// ═══════════════════════════════════════════════════════════════

// ─── 相似度判定 ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Likelihood {
    MostLikely, Somewhat, Unlikely, NotAtAll,
}
impl Likelihood {
    fn as_str(&self) -> &'static str {
        match self {
            Likelihood::MostLikely => "🟢 最像窗口",
            Likelihood::Somewhat   => "🟡 比较像",
            Likelihood::Unlikely   => "🟠 不太像",
            Likelihood::NotAtAll   => "⚫ 完全不是",
        }
    }
}

fn classify_likelihood(r: &AnalyzeResult) -> Likelihood {
    match r.subsystem {
        Subsystem::Console | Subsystem::Native | Subsystem::Other(_) => return Likelihood::NotAtAll,
        Subsystem::Gui => {}
    }
    if !r.window_funcs.is_empty() { return Likelihood::MostLikely; }
    if r.is_dotnet || r.has_dialog || (r.has_icon && !r.is_stub) { return Likelihood::Somewhat; }
    Likelihood::Unlikely
}

// ─── 得分计算 (0-10) ─────────────────────────────────────

fn compute_score(r: &AnalyzeResult) -> f64 {
    if r.subsystem != Subsystem::Gui { return 0.0; }
    let mut s: f64 = 2.0;
    if r.has_icon   { s += 1.0; }
    if r.has_dialog { s += 1.0; }
    if r.is_dotnet  { s += 1.5; }
    let f = &r.window_funcs;
    if !f.is_empty() {
        s += 1.0;
        if f.iter().any(|x| x.contains("RegisterClass"))           { s += 0.5; }
        if f.iter().any(|x| x.contains("DialogBoxParam") || x.contains("CreateDialogParam")) { s += 1.0; }
        if f.iter().any(|x| x.contains("CreateWindowEx"))          { s += 1.5; }
        if f.iter().any(|x| x.contains("MessageBox"))              { s += 0.5; }
        if f.iter().any(|x| x.contains("CreateWindowEx")) &&
           f.iter().any(|x| x.contains("RegisterClass"))           { s += 0.5; }
        if f.len() >= 3                                            { s += 0.5; }
    }
    if r.is_stub    { s -= 2.0; }
    if r.is_service { s -= 1.5; }
    (s.max(0.0).min(10.0) * 10.0).round() / 10.0
}

// ─── 目录遍历 ──────────────────────────────────────────────

fn find_exes(dir: &Path, depth: usize, results: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH { return; }
    let entries = match fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    let mut files = Vec::new();
    let mut subdirs = Vec::new();
    for entry in entries {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let path = entry.path();
        if path.is_dir() { subdirs.push(path); }
        else if path.extension().map_or(false, |ext| ext.eq_ignore_ascii_case("exe")) { files.push(path); }
    }
    let next = if files.is_empty() { depth } else { depth + 1 };
    results.extend(files);
    if next <= MAX_DEPTH { for sd in &subdirs { find_exes(sd, next, results); } }
}

// ─── 缓存（v2：数组 + 得分） ──────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct CacheEntry {
    path: String,
    mtime_secs: u64,
    score: f64,
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
    let file = match fs::File::open(&path) { Ok(f) => f, Err(_) => return Vec::new() };
    let reader = std::io::BufReader::new(file);
    match serde_json::from_reader::<_, CacheData>(reader) {
        Ok(d) if d.version == 2 => d.entries,
        _ => Vec::new(),
    }
}

fn build_cache_set(entries: &[CacheEntry]) -> HashSet<String> {
    entries.iter().map(|e| e.path.clone()).collect()
}

fn save_cache(entries: &[CacheEntry]) {
    let total = entries.len();
    // 统计分档
    let mut r0 = 0usize; let mut r5 = 0; let mut r6 = 0;
    let mut r7 = 0; let mut r8 = 0; let mut r9 = 0;
    for e in entries {
        let s = e.score;
        if      s <= 4.0 { r0 += 1; }
        else if s <= 6.0 { r5 += 1; }
        else if s <= 7.0 { r6 += 1; }
        else if s <= 8.0 { r7 += 1; }
        else if s <= 9.0 { r8 += 1; }
        else             { r9 += 1; }
    }
    let pct = |c: usize| -> String { if total == 0 { "0.0%".into() } else { format!("{:.1}%", c as f64 / total as f64 * 100.0) } };
    let ranges = serde_json::json!([
        { "range": "9-10", "count": r9, "percent": pct(r9) },
        { "range": "8-9",  "count": r8, "percent": pct(r8) },
        { "range": "7-8",  "count": r7, "percent": pct(r7) },
        { "range": "6-7",  "count": r6, "percent": pct(r6) },
        { "range": "5-6",  "count": r5, "percent": pct(r5) },
        { "range": "0-4",  "count": r0, "percent": pct(r0) },
    ]);

    let data = CacheData {
        version: 2,
        stats: Some(CacheStats { total, score_ranges: ranges }),
        entries: entries.to_vec(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&data) {
        let _ = fs::write(cache_path(), &json);
    }
    println!("  缓存保存: {} 条", total);
}

fn file_mtime(path: &Path) -> Option<u64> {
    let meta = fs::metadata(path).ok()?;
    let dur = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some(dur.as_secs())
}

// ─── 分析单个文件 ──────────────────────────────────────────

fn analyze_one(path: &Path, cache_map: &HashSet<String>, entries: &mut Vec<CacheEntry>) -> Option<(String, AnalyzeResult)> {
    let path_str = path.to_string_lossy().to_string();
    let abs_path = fs::canonicalize(path).ok()?;
    let abs_str = abs_path.to_string_lossy().to_string();
    let mtime = file_mtime(path)?;

    // 缓存命中
    if USE_CACHE && cache_map.contains(&abs_str) {
        if let Some(entry) = entries.iter().find(|e| e.path == abs_str) {
            if entry.mtime_secs == mtime {
                return Some((path_str, entry.result.clone()));
            }
        }
    }

    // 分析
    let result = match analyze_exe(path) {
        Ok(r) => r,
        Err(e) => { eprintln!("\n  分析失败: {path_str} → {e}"); return None; }
    };
    let score = compute_score(&result);
    entries.push(CacheEntry { path: abs_str, mtime_secs: mtime, score, result: result.clone() });
    Some((path_str, result))
}

// ─── 主逻辑 ────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let recalc_only = args.iter().any(|a| a == "--recalc");

    if recalc_only {
        println!("playscript find — 仅重算缓存\n");
        println!("缓存: {}", cache_path().display());
        let mut entries = load_cache_entries();
        if entries.is_empty() {
            eprintln!("错误: 缓存为空或无效");
            std::process::exit(1);
        }
        println!("加载: {} 条\n", entries.len());

        // 重算得分
        let mut changed = 0;
        for e in &mut entries {
            let new_score = compute_score(&e.result);
            if (e.score - new_score).abs() > 0.01 { changed += 1; }
            e.score = new_score;
        }
        println!("重算得分: {} 条变更", changed);

        // 排序 + 保存
        entries.sort_by(|a, b| {
            b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    let fa = Path::new(&a.path).file_name().map(|s| s.to_ascii_lowercase());
                    let fb = Path::new(&b.path).file_name().map(|s| s.to_ascii_lowercase());
                    fa.cmp(&fb)
                })
                .then_with(|| a.path.cmp(&b.path))
        });
        save_cache(&entries);
        return;
    }

    println!("playscript find — 按窗口相似度排序\n");
    println!("根目录: {ROOT_DIR}");
    println!("最大层级(有文件的层): {MAX_DEPTH}");
    println!("并发线程数: {}", if THREADS == 0 { format!("{} (自动)", num_cpus()) } else { THREADS.to_string() });
    println!("缓存: {}\n", if USE_CACHE { format!("{}", cache_path().display()) } else { "关闭".into() });

    let root = Path::new(ROOT_DIR);
    if !root.exists() { eprintln!("错误: 目录不存在 -> {ROOT_DIR}"); std::process::exit(1); }

    // 1. 收集 EXE
    let mut exe_paths = Vec::new();
    find_exes(root, 0, &mut exe_paths);
    println!("共找到 {} 个 EXE\n", exe_paths.len());
    if exe_paths.is_empty() { return; }

    // 2. 加载缓存 + 并发分析
    let n_threads = if THREADS == 0 { num_cpus() } else { THREADS };
    let cache_entries = Mutex::new(if USE_CACHE { load_cache_entries() } else { Vec::new() });
    let cache_set = Mutex::new(HashSet::new());

    // 预先构建 path set
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
                    if let Some((p, r)) = analyze_one(path, &cache_set.lock().unwrap(), &mut cache_entries.lock().unwrap()) {
                        results.lock().unwrap().push((p, r, 0.0)); // score filled below
                    }
                    let mut pg = progress.lock().unwrap();
                    *pg += 1;
                    if *pg % 10 == 0 || *pg == total { eprint!("\r  分析进度: {}/{}", *pg, total); }
                }
            });
        }
    });
    println!("\n");

    // 从缓存拿回 score
    let final_entries = cache_entries.into_inner().unwrap();

    // 3. 排序：得分(降) → 文件名(升) → 路径(升)
    let mut sorted: Vec<(String, AnalyzeResult, f64)> = results.into_inner().unwrap();
    for (p, _, sc) in &mut sorted {
        if let Ok(abs) = fs::canonicalize(p) {
            let a = abs.to_string_lossy().to_string();
            if let Some(e) = final_entries.iter().find(|e| e.path == a) {
                *sc = e.score;
            }
        }
    }
    sorted.sort_by(|(a_p, _, a_s), (b_p, _, b_s)| {
        b_s.partial_cmp(a_s).unwrap_or(std::cmp::Ordering::Equal)  // score desc
            .then_with(|| {
                let fa = Path::new(a_p).file_name().map(|s| s.to_ascii_lowercase());
                let fb = Path::new(b_p).file_name().map(|s| s.to_ascii_lowercase());
                fa.cmp(&fb)
            })  // filename asc
            .then_with(|| a_p.cmp(b_p))  // path asc
    });

    // 4. 分组输出
    let mut groups: BTreeMap<Likelihood, Vec<&(String, AnalyzeResult, f64)>> = BTreeMap::new();
    for item in &sorted {
        let l = classify_likelihood(&item.1);
        groups.entry(l).or_default().push(item);
    }

    for (likelihood, items) in &groups {
        println!("────────────────────────────────────────────");
        println!("{}  ({} 个)", likelihood.as_str(), items.len());
        println!("────────────────────────────────────────────");
        for (path, r, score) in items {
            let name = Path::new(path).file_name().unwrap_or_default().to_string_lossy();
            println!("  [{score:>4.1}] {name}");
            println!("    路径: {path}");
            let mut info = format!("    类型: {} | 有窗口: {}", r.subsystem.as_str(), r.has_window);
            if !r.window_funcs.is_empty() { info.push_str(&format!(" | {}", r.window_funcs.join(", "))); }
            println!("{info}");
            let mut tags = Vec::new();
            if r.is_dotnet { tags.push(".NET"); }
            if r.is_stub { tags.push("Stub"); }
            if r.has_manifest { tags.push("Manifest"); }
            if r.has_dialog { tags.push("Dialog"); }
            if r.has_icon { tags.push("Icon"); }
            if !tags.is_empty() { println!("    特征: {}", tags.join(", ")); }
            if let Some(ref ver) = r.version {
                if let Some(ref v) = ver.file_description { println!("    描述: {v}"); }
            }
            println!();
        }
    }

    // 保存缓存在最后（包含排序后的所有数据）
    if USE_CACHE {
        // 合并 + 排序后保存
        let mut all: Vec<CacheEntry> = final_entries;
        let existing: HashSet<String> = all.iter().map(|e| e.path.clone()).collect();
        for item in &sorted {
            if let Ok(abs) = fs::canonicalize(&item.0) {
                let a = abs.to_string_lossy().to_string();
                if !existing.contains(&a) {
                    all.push(CacheEntry { path: a, mtime_secs: 0, score: item.2, result: item.1.clone() });
                }
            }
        }
        // 排序：分数降序 → 文件名升序 → 路径升序
        all.sort_by(|a, b| {
            b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    let fa = Path::new(&a.path).file_name().map(|s| s.to_ascii_lowercase());
                    let fb = Path::new(&b.path).file_name().map(|s| s.to_ascii_lowercase());
                    fa.cmp(&fb)
                })
                .then_with(|| a.path.cmp(&b.path))
        });
        save_cache(&all);
    }

    println!("\n═══════════════════════════════════════════════");
    println!("  汇总");
    println!("═══════════════════════════════════════════════");
    for (likelihood, items) in &groups { println!("  {} : {} 个", likelihood.as_str(), items.len()); }
}

fn num_cpus() -> usize { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) }
