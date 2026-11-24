use rusqlite::{Connection, params};
use serde::Serialize;

use crate::core::error::AppResult;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterProfile {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub use_tls: bool,
    pub created_at: String,
}

pub struct RouterRepository;

impl RouterRepository {
    pub fn list(connection: &Connection) -> AppResult<Vec<RouterProfile>> {
        let mut statement = connection.prepare(
            "SELECT id, name, host, port, username, use_tls, created_at
             FROM router_profiles
             ORDER BY name ASC",
        )?;

        let profiles = statement.query_map([], |row| {
            Ok(RouterProfile {
                id: row.get(0)?,
                name: row.get(1)?,
                host: row.get(2)?,
                port: row.get(3)?,
                username: row.get(4)?,
                use_tls: row.get::<_, i64>(5)? != 0,
                created_at: row.get(6)?,
            })
        })?;

        let mut result = Vec::new();

        for profile in profiles {
            result.push(profile?);
        }

        Ok(result)
    }

    pub fn create(
        connection: &Connection,
        name: &str,
        host: &str,
        port: u16,
        username: &str,
        use_tls: bool,
    ) -> AppResult<i64> {
        connection.execute(
            "INSERT INTO router_profiles
             (name, host, port, username, use_tls)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, host, port, username, use_tls as i64],
        )?;

        Ok(connection.last_insert_rowid())
    }

    pub fn delete(connection: &Connection, id: i64) -> AppResult<()> {
        connection.execute("DELETE FROM router_profiles WHERE id = ?1", params![id])?;

        Ok(())
    }
}
