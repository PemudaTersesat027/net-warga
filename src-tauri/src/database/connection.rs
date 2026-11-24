use rusqlite::Connection;
use std::path::Path;

use crate::core::error::AppResult;

pub struct Database {
    pub connection: Connection,
}

impl Database {
    pub fn initialize(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(path)?;

        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;

        Ok(Self { connection })
    }

    pub fn migrate(&self) -> AppResult<()> {
        let migration = include_str!("../../migrations/001_initial.sql");

        self.connection.execute_batch(migration)?;

        Ok(())
    }
}
