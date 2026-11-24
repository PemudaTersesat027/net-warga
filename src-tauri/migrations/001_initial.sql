
CREATE TABLE IF NOT EXISTS router_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 8728,
    username TEXT NOT NULL,
    use_tls INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_router_profiles_name
ON router_profiles(name);

CREATE INDEX IF NOT EXISTS idx_router_profiles_host
ON router_profiles(host);
