mod commands;
mod core;
mod database;
mod discovery;
mod routeros;

use tauri::Manager;

use core::state::AppState;
use database::connection::Database;
use discovery::manager::DiscoveryManager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_data_dir)?;

            let database_path = app_data_dir.join("netwarga.db");

            let database =
                Database::initialize(&database_path).expect("Failed to initialize database");

            database
                .migrate()
                .expect("Failed to run database migrations");

            app.manage(AppState {
                database: std::sync::Mutex::new(database),
                discovery: DiscoveryManager::default(),
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::system::get_system_info,
            commands::router::get_router_profiles,
            commands::router::add_router_profile,
            commands::router::delete_router_profile,
            commands::discovery::start_discovery,
            commands::discovery::stop_discovery,
            commands::discovery::get_discovery_status,
            commands::winbox::test_winbox_connection,
        ])
        .run(tauri::generate_context!())
        .expect("Failed to run Net Warga");
}
