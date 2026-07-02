//! playscript 库使用示例（根据《Windows EXE 文件类型分类》设计）
//!
//! 运行: cargo run --example demo -- <exe_path>
//! 不带参数时展示内置测试路径。

use std::env;
use playscript::analyze_exe;
use std::path::Path;

fn analyze_and_print(path: &str) {
    let name = Path::new(path).file_name().unwrap_or_default().to_string_lossy();
    println!("── {name}");
    match analyze_exe(path) {
        Ok(r) => {
            println!("  类型    : {}", r.subsystem.as_str());
            println!("  分类    : {}", r.classification.as_str());
            println!("  有窗口  : {}", r.has_window);

            let mut tags = Vec::new();
            if r.is_dotnet { tags.push(".NET"); }
            if r.is_service { tags.push("Service"); }
            if r.is_stub { tags.push("Stub"); }
            if r.has_manifest { tags.push("Manifest"); }
            if r.has_dialog { tags.push("Dialog"); }
            if r.has_icon { tags.push("Icon"); }
            if r.version.is_some() { tags.push("VersionInfo"); }
            if !tags.is_empty() { println!("  特征    : {}", tags.join(", ")); }

            if !r.window_funcs.is_empty() {
                println!("  窗口函数: {:?}", r.window_funcs);
            }
            if let Some(ref ver) = r.version {
                if let Some(ref v) = ver.original_filename { println!("  OFilename: {v}"); }
                if let Some(ref v) = ver.file_description  { println!("  描述     : {v}"); }
                if let Some(ref v) = ver.company_name { println!("  公司     : {v}"); }
            }

            let core = r.core_dlls;
            if !core.is_empty() { println!("  核心DLL  : {:?}", core); }
            println!();
        }
        Err(e) => eprintln!("  错误: {e}\n"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 {
        for path in &args[1..] { analyze_and_print(path); }
    } else {
        println!("playscript 示例 — PE 文件窗口检测与分类\n");
        println!("用法: cargo run --example demo -- <exe_path>\n");
        println!("内置演示:\n");

        let demos = &[
            r"D:\software\tool\WizTree\WizTree.exe",
            r"D:\software\tool\WizTree\unins000.exe",
            r"D:\software\tool\ClashVerge\clash-verge.exe",
            r"D:\software\tool\ClashVerge\verge-mihomo.exe",
            r"D:\software\tool\ClashVerge\resources\clash-verge-service.exe",
            r"D:\software\tool\ClashVerge\resources\enableLoopback.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\146.0.7680.154\notification_helper.exe",
            r"C:\Windows\system32\notepad.exe",
            r"C:\Windows\system32\cmd.exe",
        ];

        let mut any = false;
        for &path in demos {
            if Path::new(path).exists() { any = true; analyze_and_print(path); }
        }
        if !any { println!("  (没有内置路径存在，请传一个 exe 路径运行)\n"); }
    }
}
