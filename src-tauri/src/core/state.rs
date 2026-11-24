use std::sync::Mutex;

use crate::{database::connection::Database, discovery::manager::DiscoveryManager};

pub struct AppState {
    pub database: Mutex<Database>,
    pub discovery: DiscoveryManager,
}
