use tauri::State;

use crate::{
    core::{error::AppResult, state::AppState},
    database::repositories::router_repository::{RouterProfile, RouterRepository},
};

#[tauri::command]
pub fn get_router_profiles(state: State<'_, AppState>) -> AppResult<Vec<RouterProfile>> {
    let database = state
        .database
        .lock()
        .map_err(|_| crate::core::error::AppError::Internal("Database lock poisoned".into()))?;

    RouterRepository::list(&database.connection)
}

#[tauri::command]
pub fn add_router_profile(
    state: State<'_, AppState>,
    name: String,
    host: String,
    port: u16,
    username: String,
    use_tls: bool,
) -> AppResult<i64> {
    if name.trim().is_empty() || host.trim().is_empty() || username.trim().is_empty() || port == 0 {
        return Err(crate::core::error::AppError::Config(
            "Invalid router profile data".into(),
        ));
    }

    let database = state
        .database
        .lock()
        .map_err(|_| crate::core::error::AppError::Internal("Database lock poisoned".into()))?;

    RouterRepository::create(
        &database.connection,
        name.trim(),
        host.trim(),
        port,
        username.trim(),
        use_tls,
    )
}

#[tauri::command]
pub fn delete_router_profile(state: State<'_, AppState>, id: i64) -> AppResult<()> {
    let database = state
        .database
        .lock()
        .map_err(|_| crate::core::error::AppError::Internal("Database lock poisoned".into()))?;

    RouterRepository::delete(&database.connection, id)
}
