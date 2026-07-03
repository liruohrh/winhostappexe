//! CLI 入口 — 调用 lib.rs 进行分析并输出结果。
//!
//! 用法: playscript <exe_path>

use std::env;
use std::process;

use playscript::analyze_exe;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <exe_path>", args[0]);
        process::exit(1);
    }

    match analyze_exe(&args[1]) {
        Ok(r) => {
            println!("subsystem    : {}", r.subsystem.as_str());
            println!("classification: {}", r.classification.as_str());
            println!("has_window   : {}", r.has_window);
            if !r.window_funcs.is_empty() {
                println!("window_funcs : {:?}", r.window_funcs);
            }
            if !r.all_dlls.is_empty() {
                println!("dlls ({}): {:?}", r.all_dlls.len(), r.all_dlls);
            }

            let mut tags = Vec::new();
            if r.is_dotnet {
                tags.push(".NET");
            }
            if r.is_service {
                tags.push("Service");
            }
            if r.is_stub {
                tags.push("Stub");
            }
            if r.has_manifest {
                tags.push("Manifest");
            }
            if r.has_dialog {
                tags.push("DialogRes");
            }
            if r.has_icon {
                tags.push("Icon");
            }
            if r.version.is_some() {
                tags.push("VersionInfo");
            }
            if !tags.is_empty() {
                println!("tags: {}", tags.join(" "));
            }
            println!("score_main: {}, score_sub: {}", r.score_main, r.score_sub);

            if let Some(ref ver) = r.version {
                if let Some(ref v) = ver.original_filename {
                    println!("  OriginalFilename: {v}");
                }
                if let Some(ref v) = ver.file_description {
                    println!("  FileDescription : {v}");
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}
