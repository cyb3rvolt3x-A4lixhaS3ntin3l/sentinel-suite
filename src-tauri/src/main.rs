// Sentinel Suite — Tauri desktop shell.
// Loads the SAME local SPA/API as the browser (http://127.0.0.1:8888).
// Does NOT replace `sentinel ui`; start the Python API first for live data.
// No Electron. MIT.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .run(tauri::generate_context!())
        .expect("error while running Sentinel Suite Tauri shell");
}
