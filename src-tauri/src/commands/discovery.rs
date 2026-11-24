use tauri::{AppHandle, State};

use crate::core::state::AppState;

#[tauri::command]
pub async fn start_discovery(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    state.discovery.start(app).await
}

#[tauri::command]
pub fn stop_discovery(state: State<'_, AppState>) -> Result<(), String> {
    state.discovery.stop()
}

#[tauri::command]
pub fn get_discovery_status(state: State<'_, AppState>) -> Result<bool, String> {
    state.discovery.is_running()
}
