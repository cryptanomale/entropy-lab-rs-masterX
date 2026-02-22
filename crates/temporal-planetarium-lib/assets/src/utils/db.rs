//! Target Address Database Module
//!
//! High-performance database for vulnerability intelligence tracking with support for
//! both SQLite (default) and PostgreSQL (optional, feature-gated).
//!
//! ## Performance Characteristics
//!
//! **Indexes:**
//! - `address`: PRIMARY KEY (automatic B-tree index)
//! - `vuln_class`: Secondary index via `idx_vuln_class`
//!
//! **Expected Performance:**
//! - Bulk insert: 10k addresses in <5s (SQLite WAL mode)
//! - Indexed query: <100ms for 100k+ address lookups
//! - Primary key lookup: <10ms per address
//!
//! ## Database Backends
//!
//! ### SQLite (Default)
//! - File-based database with WAL (Write-Ahead Logging) for concurrency
//! - Perfect for local research and moderate-scale datasets (<1M addresses)
//! - No external dependencies or server required
//!
//! ### PostgreSQL (Feature-Gated)
//! - Enable with `--features postgres`
//! - Connection pooling via `deadpool-postgres`
//! - Suitable for large-scale datasets (>1M addresses) and multi-user scenarios
//! - Requires PostgreSQL server running
//!
//! ## Usage Example
//!
//! ```no_run
//! use temporal_planetarium_lib::utils::db::{TargetDatabase, Target};
//! use std::path::PathBuf;
//!
//! // SQLite (default)
//! let db = TargetDatabase::new(PathBuf::from("targets.db"))?;
//!
//! // Upsert target
//! let target = Target {
//!     address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
//!     vuln_class: "randstorm".to_string(),
//!     first_seen_timestamp: Some(1231006505),
//!     metadata_json: Some(r#"{"fingerprint_id": 42}"#.to_string()),
//!     status: "pending".to_string(),
//! };
//!
//! db.upsert_target(&target)?;
//!
//! // Query by vulnerability class (uses index)
//! let results = db.query_by_class("randstorm", 1000)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(feature = "postgres")]
use deadpool_postgres::{Config as PgConfig, Pool, Runtime};
#[cfg(feature = "postgres")]
use tokio_postgres::NoTls;

/// Database backend selection
#[derive(Debug, Clone)]
pub enum DatabaseBackend {
    SQLite(PathBuf),
    #[cfg(feature = "postgres")]
    PostgreSQL(String), // connection string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub address: String,
    pub vuln_class: String,
    pub first_seen_timestamp: Option<i64>,
    pub metadata_json: Option<String>,
    pub status: String,
    /// Encrypted private key (AES-256-GCM ciphertext) in WIF format
    pub encrypted_private_key: Option<Vec<u8>>,
    /// 12-byte nonce for AES-256-GCM decryption
    pub encryption_nonce: Option<Vec<u8>>,
    /// 32-byte salt for PBKDF2 key derivation
    pub pbkdf2_salt: Option<Vec<u8>>,
    /// Number of times the encrypted key has been accessed
    pub access_count: i64,
    /// Last access timestamp (Unix epoch)
    pub last_accessed: Option<i64>,
}

impl Target {
    /// Create a basic target without encrypted key data
    pub fn new(address: String, vuln_class: String, status: String) -> Self {
        Self {
            address,
            vuln_class,
            first_seen_timestamp: None,
            metadata_json: None,
            status,
            encrypted_private_key: None,
            encryption_nonce: None,
            pbkdf2_salt: None,
            access_count: 0,
            last_accessed: None,
        }
    }

    /// Create a target with encrypted private key
    pub fn with_encrypted_key(
        address: String,
        vuln_class: String,
        metadata_json: Option<String>,
        encrypted_private_key: Vec<u8>,
        encryption_nonce: Vec<u8>,
        pbkdf2_salt: Vec<u8>,
    ) -> Self {
        Self {
            address,
            vuln_class,
            first_seen_timestamp: Some(chrono::Utc::now().timestamp()),
            metadata_json,
            status: "detected".to_string(),
            encrypted_private_key: Some(encrypted_private_key),
            encryption_nonce: Some(encryption_nonce),
            pbkdf2_salt: Some(pbkdf2_salt),
            access_count: 0,
            last_accessed: None,
        }
    }
}

impl Default for Target {
    fn default() -> Self {
        Self {
            address: String::new(),
            vuln_class: String::new(),
            first_seen_timestamp: None,
            metadata_json: None,
            status: "pending".to_string(),
            encrypted_private_key: None,
            encryption_nonce: None,
            pbkdf2_salt: None,
            access_count: 0,
            last_accessed: None,
        }
    }
}

/// Unified database interface supporting both SQLite and PostgreSQL
pub enum TargetDatabase {
    SQLite(SqliteDatabase),
    #[cfg(feature = "postgres")]
    Postgres(PostgresDatabase),
}

pub struct SqliteDatabase {
    conn: Connection,
}

#[cfg(feature = "postgres")]
pub struct PostgresDatabase {
    pool: Pool,
}

impl TargetDatabase {
    /// Initialize SQLite database at the given path
    pub fn new(path: PathBuf) -> Result<Self> {
        let db = SqliteDatabase::new(path)?;
        Ok(TargetDatabase::SQLite(db))
    }

    /// Initialize from backend configuration
    pub fn from_backend(backend: DatabaseBackend) -> Result<Self> {
        match backend {
            DatabaseBackend::SQLite(path) => Self::new(path),
            #[cfg(feature = "postgres")]
            DatabaseBackend::PostgreSQL(conn_str) => {
                let db = PostgresDatabase::new(&conn_str)?;
                Ok(TargetDatabase::Postgres(db))
            }
        }
    }

    /// Initialize an in-memory SQLite database for testing
    pub fn in_memory() -> Result<Self> {
        let db = SqliteDatabase::in_memory()?;
        Ok(TargetDatabase::SQLite(db))
    }

    /// Upsert a target (delegates to backend)
    pub fn upsert_target(&self, target: &Target) -> Result<()> {
        match self {
            TargetDatabase::SQLite(db) => db.upsert_target(target),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(db) => db.upsert_target(target),
        }
    }

    /// Query targets by vulnerability class
    pub fn query_by_class(&self, vuln_class: &str, limit: usize) -> Result<Vec<Target>> {
        match self {
            TargetDatabase::SQLite(db) => db.query_by_class(vuln_class, limit),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(db) => db.query_by_class(vuln_class, limit),
        }
    }

    /// Bulk upsert targets for high performance
    pub fn bulk_upsert_targets(&mut self, targets: &[Target]) -> Result<()> {
        match self {
            TargetDatabase::SQLite(db) => db.bulk_upsert_targets(targets),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(db) => db.bulk_upsert_targets(targets),
        }
    }

    /// Update status of a target
    pub fn update_status(&self, address: &str, status: &str) -> Result<()> {
        match self {
            TargetDatabase::SQLite(db) => db.update_status(address, status),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(db) => db.update_status(address, status),
        }
    }

    /// Add an intelligence entry
    pub fn add_intelligence(&self, intel_type: &str, value: &str, context: Option<&str>, vuln_class: Option<&str>) -> Result<()> {
        match self {
            TargetDatabase::SQLite(db) => db.add_intelligence(intel_type, value, context, vuln_class),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(db) => db.add_intelligence(intel_type, value, context, vuln_class),
        }
    }

    /// Add intelligence entries in batch
    pub fn add_intelligence_batch(&mut self, entries: &[(&str, &str, Option<&str>, Option<&str>)]) -> Result<()> {
        match self {
            TargetDatabase::SQLite(db) => db.add_intelligence_batch(entries),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(db) => db.add_intelligence_batch(entries),
        }
    }

    /// Query intelligence by type and class
    pub fn query_intelligence(&self, intel_type: &str, vuln_class: Option<&str>) -> Result<Vec<String>> {
        match self {
            TargetDatabase::SQLite(db) => db.query_intelligence(intel_type, vuln_class),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(db) => db.query_intelligence(intel_type, vuln_class),
        }
    }

    /// Query targets with encrypted private keys (for nonce reuse findings)
    pub fn query_by_class_with_keys(&self, vuln_class: &str, limit: usize) -> Result<Vec<Target>> {
        match self {
            TargetDatabase::SQLite(db) => db.query_by_class_with_keys(vuln_class, limit),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(_db) => {
                // PostgreSQL implementation not yet updated for encrypted keys
                Err(anyhow::anyhow!("PostgreSQL encrypted key queries not yet implemented"))
            }
        }
    }

    /// Get a single target by address (for key retrieval)
    pub fn get_target(&self, address: &str) -> Result<Option<Target>> {
        match self {
            TargetDatabase::SQLite(db) => db.get_target(address),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(_db) => {
                Err(anyhow::anyhow!("PostgreSQL get_target not yet implemented"))
            }
        }
    }

    /// Update access tracking for a target (for audit logging)
    pub fn update_access_tracking(&self, address: &str) -> Result<()> {
        match self {
            TargetDatabase::SQLite(db) => db.update_access_tracking(address),
            #[cfg(feature = "postgres")]
            TargetDatabase::Postgres(_db) => {
                Err(anyhow::anyhow!("PostgreSQL access tracking not yet implemented"))
            }
        }
    }
}

// ============================================================================
// SQLite Implementation
// ============================================================================

impl SqliteDatabase {
    /// Initialize database at the given path, creating schema if necessary
    pub fn new(path: PathBuf) -> Result<Self> {
        let conn = Connection::open(path).context("Failed to open SQLite database")?;

        // Enable WAL mode for better concurrency and performance
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        Self::create_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Initialize an in-memory database for testing
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::create_schema(&conn)?;
        Ok(Self { conn })
    }

    fn create_schema(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS targets (
                address TEXT PRIMARY KEY,
                vuln_class TEXT NOT NULL,
                first_seen_timestamp INTEGER,
                metadata_json TEXT,
                status TEXT DEFAULT 'pending',
                encrypted_private_key BLOB,
                encryption_nonce BLOB,
                pbkdf2_salt BLOB,
                access_count INTEGER DEFAULT 0,
                last_accessed INTEGER
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                context TEXT,
                vuln_class TEXT
            )",
            [],
        )?;

        // Create indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vuln_class ON targets(vuln_class)",
            [],
        )?;

        Ok(())
    }

    /// Upsert a target (insert or ignore if address exists)
    pub fn upsert_target(&self, target: &Target) -> Result<()> {
        self.conn.execute(
            "INSERT INTO targets (address, vuln_class, first_seen_timestamp, metadata_json, status,
                                 encrypted_private_key, encryption_nonce, pbkdf2_salt, access_count, last_accessed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(address) DO UPDATE SET
                vuln_class = excluded.vuln_class,
                metadata_json = excluded.metadata_json,
                encrypted_private_key = excluded.encrypted_private_key,
                encryption_nonce = excluded.encryption_nonce,
                pbkdf2_salt = excluded.pbkdf2_salt,
                access_count = excluded.access_count,
                last_accessed = excluded.last_accessed,
                status = CASE WHEN targets.status = 'pending' THEN excluded.status ELSE targets.status END",
            params![
                target.address,
                target.vuln_class,
                target.first_seen_timestamp,
                target.metadata_json,
                target.status,
                target.encrypted_private_key,
                target.encryption_nonce,
                target.pbkdf2_salt,
                target.access_count,
                target.last_accessed
            ],
        )?;
        Ok(())
    }

    /// Query targets by vulnerability class
    pub fn query_by_class(&self, vuln_class: &str, limit: usize) -> Result<Vec<Target>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, vuln_class, first_seen_timestamp, metadata_json, status,
                    encrypted_private_key, encryption_nonce, pbkdf2_salt, access_count, last_accessed
             FROM targets
             WHERE vuln_class = ?1
             LIMIT ?2",
        )?;

        let target_iter = stmt.query_map(params![vuln_class, limit], |row| {
            Ok(Target {
                address: row.get(0)?,
                vuln_class: row.get(1)?,
                first_seen_timestamp: row.get(2)?,
                metadata_json: row.get(3)?,
                status: row.get(4)?,
                encrypted_private_key: row.get(5)?,
                encryption_nonce: row.get(6)?,
                pbkdf2_salt: row.get(7)?,
                access_count: row.get(8)?,
                last_accessed: row.get(9)?,
            })
        })?;

        let mut results = Vec::new();
        for target in target_iter {
            results.push(target?);
        }
        Ok(results)
    }

    /// Bulk upsert targets for high performance
    pub fn bulk_upsert_targets(&mut self, targets: &[Target]) -> Result<()> {
        let tx = self.conn.transaction().context("Failed to start transaction")?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO targets (address, vuln_class, first_seen_timestamp, metadata_json, status,
                                     encrypted_private_key, encryption_nonce, pbkdf2_salt, access_count, last_accessed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(address) DO UPDATE SET
                    vuln_class = excluded.vuln_class,
                    metadata_json = excluded.metadata_json,
                    encrypted_private_key = excluded.encrypted_private_key,
                    encryption_nonce = excluded.encryption_nonce,
                    pbkdf2_salt = excluded.pbkdf2_salt,
                    access_count = excluded.access_count,
                    last_accessed = excluded.last_accessed,
                    status = CASE WHEN targets.status = 'pending' THEN excluded.status ELSE targets.status END",
            )?;

            for target in targets {
                stmt.execute(params![
                    target.address,
                    target.vuln_class,
                    target.first_seen_timestamp,
                    target.metadata_json,
                    target.status,
                    target.encrypted_private_key,
                    target.encryption_nonce,
                    target.pbkdf2_salt,
                    target.access_count,
                    target.last_accessed
                ])?;
            }
        }
        tx.commit().context("Failed to commit transaction")?;
        Ok(())
    }

    /// Update status of a target
    pub fn update_status(&self, address: &str, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE targets SET status = ?1 WHERE address = ?2",
            params![status, address],
        )?;
        Ok(())
    }

    /// Add an intelligence entry (passphrase, weak seed, etc.)
    pub fn add_intelligence(&self, intel_type: &str, value: &str, context: Option<&str>, vuln_class: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO intelligence (type, value, context, vuln_class) VALUES (?1, ?2, ?3, ?4)",
            params![intel_type, value, context, vuln_class],
        )?;
        Ok(())
    }

    /// Add intelligence entries in batch
    pub fn add_intelligence_batch(&mut self, entries: &[(&str, &str, Option<&str>, Option<&str>)]) -> Result<()> {
        let tx = self.conn.transaction().context("Failed to start transaction")?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO intelligence (type, value, context, vuln_class) VALUES (?1, ?2, ?3, ?4)"
            )?;

            for (intel_type, value, context, vuln_class) in entries {
                stmt.execute(params![intel_type, value, context, vuln_class])?;
            }
        }
        tx.commit().context("Failed to commit transaction")?;
        Ok(())
    }

    /// Query intelligence by type and class
    pub fn query_intelligence(&self, intel_type: &str, vuln_class: Option<&str>) -> Result<Vec<String>> {
        let mut stmt;
        let mut results = Vec::new();

        if let Some(vc) = vuln_class {
            stmt = self.conn.prepare("SELECT value FROM intelligence WHERE type = ?1 AND vuln_class = ?2")?;
            let iter = stmt.query_map(params![intel_type, vc], |row| row.get(0))?;
            for val in iter {
                results.push(val?);
            }
        } else {
            stmt = self.conn.prepare("SELECT value FROM intelligence WHERE type = ?1")?;
            let iter = stmt.query_map(params![intel_type], |row| row.get(0))?;
            for val in iter {
                results.push(val?);
            }
        };

        Ok(results)
    }

    /// Query targets with encrypted private keys (for nonce reuse findings)
    pub fn query_by_class_with_keys(&self, vuln_class: &str, limit: usize) -> Result<Vec<Target>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, vuln_class, first_seen_timestamp, metadata_json, status,
                    encrypted_private_key, encryption_nonce, pbkdf2_salt, access_count, last_accessed
             FROM targets
             WHERE vuln_class = ?1 AND encrypted_private_key IS NOT NULL
             LIMIT ?2",
        )?;

        let target_iter = stmt.query_map(params![vuln_class, limit], |row| {
            Ok(Target {
                address: row.get(0)?,
                vuln_class: row.get(1)?,
                first_seen_timestamp: row.get(2)?,
                metadata_json: row.get(3)?,
                status: row.get(4)?,
                encrypted_private_key: row.get(5)?,
                encryption_nonce: row.get(6)?,
                pbkdf2_salt: row.get(7)?,
                access_count: row.get(8)?,
                last_accessed: row.get(9)?,
            })
        })?;

        let mut results = Vec::new();
        for target in target_iter {
            results.push(target?);
        }
        Ok(results)
    }

    /// Get a single target by address (for key retrieval)
    pub fn get_target(&self, address: &str) -> Result<Option<Target>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, vuln_class, first_seen_timestamp, metadata_json, status,
                    encrypted_private_key, encryption_nonce, pbkdf2_salt, access_count, last_accessed
             FROM targets
             WHERE address = ?1",
        )?;

        let mut rows = stmt.query(params![address])?;

        if let Some(row) = rows.next()? {
            Ok(Some(Target {
                address: row.get(0)?,
                vuln_class: row.get(1)?,
                first_seen_timestamp: row.get(2)?,
                metadata_json: row.get(3)?,
                status: row.get(4)?,
                encrypted_private_key: row.get(5)?,
                encryption_nonce: row.get(6)?,
                pbkdf2_salt: row.get(7)?,
                access_count: row.get(8)?,
                last_accessed: row.get(9)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Update access tracking for a target (for audit logging)
    pub fn update_access_tracking(&self, address: &str) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "UPDATE targets SET access_count = access_count + 1, last_accessed = ?1 WHERE address = ?2",
            params![now, address],
        )?;
        Ok(())
    }
}

// ============================================================================
// PostgreSQL Implementation
// ============================================================================

#[cfg(feature = "postgres")]
impl PostgresDatabase {
    /// Initialize PostgreSQL connection pool with schema creation
    pub fn new(connection_string: &str) -> Result<Self> {
        // Parse connection string into config
        let mut pg_config = PgConfig::new();
        pg_config.url = Some(connection_string.to_string());

        let pool = pg_config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .context("Failed to create PostgreSQL connection pool")?;

        // Create schema using blocking tokio runtime
        let pool_clone = pool.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                Self::create_schema_async(&pool_clone).await
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Failed to join schema creation thread"))??;

        Ok(Self { pool })
    }

    async fn create_schema_async(pool: &Pool) -> Result<()> {
        let client = pool.get().await.context("Failed to get PostgreSQL client")?;

        client.execute(
            "CREATE TABLE IF NOT EXISTS targets (
                address TEXT PRIMARY KEY,
                vuln_class TEXT NOT NULL,
                first_seen_timestamp BIGINT,
                metadata_json TEXT,
                status TEXT DEFAULT 'pending',
                encrypted_private_key BYTEA,
                encryption_nonce BYTEA,
                pbkdf2_salt BYTEA,
                access_count BIGINT DEFAULT 0,
                last_accessed BIGINT
            )",
            &[],
        ).await?;

        client.execute(
            "CREATE TABLE IF NOT EXISTS intelligence (
                id SERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                context TEXT,
                vuln_class TEXT
            )",
            &[],
        ).await?;

        // Create indexes
        client.execute(
            "CREATE INDEX IF NOT EXISTS idx_vuln_class ON targets(vuln_class)",
            &[],
        ).await?;

        Ok(())
    }

    /// Upsert a target
    pub fn upsert_target(&self, target: &Target) -> Result<()> {
        let pool = self.pool.clone();
        let target = target.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let client = pool.get().await.context("Failed to get PostgreSQL client")?;

                client.execute(
                    "INSERT INTO targets (address, vuln_class, first_seen_timestamp, metadata_json, status)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT(address) DO UPDATE SET
                        vuln_class = EXCLUDED.vuln_class,
                        metadata_json = EXCLUDED.metadata_json,
                        status = CASE WHEN targets.status = 'pending' THEN EXCLUDED.status ELSE targets.status END",
                    &[&target.address, &target.vuln_class, &target.first_seen_timestamp, &target.metadata_json, &target.status],
                ).await?;

                Ok::<(), anyhow::Error>(())
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Thread join failed"))??;

        Ok(())
    }

    /// Query targets by vulnerability class
    pub fn query_by_class(&self, vuln_class: &str, limit: usize) -> Result<Vec<Target>> {
        let pool = self.pool.clone();
        let vuln_class = vuln_class.to_string();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let client = pool.get().await.context("Failed to get PostgreSQL client")?;

                let rows = client.query(
                    "SELECT address, vuln_class, first_seen_timestamp, metadata_json, status
                     FROM targets
                     WHERE vuln_class = $1
                     LIMIT $2",
                    &[&vuln_class, &(limit as i64)],
                ).await?;

                let mut results = Vec::new();
                for row in rows {
                    results.push(Target {
                        address: row.get(0),
                        vuln_class: row.get(1),
                        first_seen_timestamp: row.get(2),
                        metadata_json: row.get(3),
                        status: row.get(4),
                    });
                }

                Ok::<Vec<Target>, anyhow::Error>(results)
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Thread join failed"))?
    }

    /// Bulk upsert targets
    pub fn bulk_upsert_targets(&mut self, targets: &[Target]) -> Result<()> {
        let pool = self.pool.clone();
        let targets = targets.to_vec();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut client = pool.get().await.context("Failed to get PostgreSQL client")?;
                let tx = client.transaction().await?;

                for target in &targets {
                    tx.execute(
                        "INSERT INTO targets (address, vuln_class, first_seen_timestamp, metadata_json, status)
                         VALUES ($1, $2, $3, $4, $5)
                         ON CONFLICT(address) DO UPDATE SET
                            vuln_class = EXCLUDED.vuln_class,
                            metadata_json = EXCLUDED.metadata_json,
                            status = CASE WHEN targets.status = 'pending' THEN EXCLUDED.status ELSE targets.status END",
                        &[&target.address, &target.vuln_class, &target.first_seen_timestamp, &target.metadata_json, &target.status],
                    ).await?;
                }

                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Thread join failed"))??;

        Ok(())
    }

    /// Update status
    pub fn update_status(&self, address: &str, status: &str) -> Result<()> {
        let pool = self.pool.clone();
        let address = address.to_string();
        let status = status.to_string();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let client = pool.get().await.context("Failed to get PostgreSQL client")?;
                client.execute(
                    "UPDATE targets SET status = $1 WHERE address = $2",
                    &[&status, &address],
                ).await?;
                Ok::<(), anyhow::Error>(())
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Thread join failed"))??;

        Ok(())
    }

    /// Add intelligence
    pub fn add_intelligence(&self, intel_type: &str, value: &str, context: Option<&str>, vuln_class: Option<&str>) -> Result<()> {
        let pool = self.pool.clone();
        let intel_type = intel_type.to_string();
        let value = value.to_string();
        let context = context.map(|s| s.to_string());
        let vuln_class = vuln_class.map(|s| s.to_string());

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let client = pool.get().await.context("Failed to get PostgreSQL client")?;
                client.execute(
                    "INSERT INTO intelligence (type, value, context, vuln_class) VALUES ($1, $2, $3, $4)",
                    &[&intel_type, &value, &context, &vuln_class],
                ).await?;
                Ok::<(), anyhow::Error>(())
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Thread join failed"))??;

        Ok(())
    }

    /// Add intelligence batch
    pub fn add_intelligence_batch(&mut self, entries: &[(&str, &str, Option<&str>, Option<&str>)]) -> Result<()> {
        let pool = self.pool.clone();
        let entries: Vec<(String, String, Option<String>, Option<String>)> = entries
            .iter()
            .map(|(t, v, c, vc)| (t.to_string(), v.to_string(), c.map(|s| s.to_string()), vc.map(|s| s.to_string())))
            .collect();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let mut client = pool.get().await.context("Failed to get PostgreSQL client")?;
                let tx = client.transaction().await?;

                for (intel_type, value, context, vuln_class) in &entries {
                    tx.execute(
                        "INSERT INTO intelligence (type, value, context, vuln_class) VALUES ($1, $2, $3, $4)",
                        &[intel_type, value, context, vuln_class],
                    ).await?;
                }

                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Thread join failed"))??;

        Ok(())
    }

    /// Query intelligence
    pub fn query_intelligence(&self, intel_type: &str, vuln_class: Option<&str>) -> Result<Vec<String>> {
        let pool = self.pool.clone();
        let intel_type = intel_type.to_string();
        let vuln_class = vuln_class.map(|s| s.to_string());

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let client = pool.get().await.context("Failed to get PostgreSQL client")?;

                let rows = if let Some(vc) = vuln_class {
                    client.query(
                        "SELECT value FROM intelligence WHERE type = $1 AND vuln_class = $2",
                        &[&intel_type, &vc],
                    ).await?
                } else {
                    client.query(
                        "SELECT value FROM intelligence WHERE type = $1",
                        &[&intel_type],
                    ).await?
                };

                let mut results = Vec::new();
                for row in rows {
                    results.push(row.get(0));
                }

                Ok::<Vec<String>, anyhow::Error>(results)
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("Thread join failed"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upsert_and_query() -> Result<()> {
        let db = TargetDatabase::in_memory()?;
        let target = Target {
            address: "1BitcoinAddress".to_string(),
            vuln_class: "randstorm".to_string(),
            first_seen_timestamp: Some(123456789),
            metadata_json: Some("{}".to_string()),
            status: "pending".to_string(),
            ..Default::default()
        };

        db.upsert_target(&target)?;
        let results = db.query_by_class("randstorm", 10)?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "1BitcoinAddress");

        // Test update
        db.update_status("1BitcoinAddress", "scanned")?;
        let results = db.query_by_class("randstorm", 10)?;
        assert_eq!(results[0].status, "scanned");

        Ok(())
    }

    #[test]
    fn test_index_usage_verification() -> Result<()> {
        // Verify that EXPLAIN QUERY PLAN shows index usage
        let db_wrapper = TargetDatabase::in_memory()?;
        let db = match &db_wrapper {
            TargetDatabase::SQLite(sqlite_db) => sqlite_db,
            #[cfg(feature = "postgres")]
            _ => panic!("Expected SQLite database"),
        };

        // Check vuln_class index usage
        let mut stmt = db.conn.prepare("EXPLAIN QUERY PLAN SELECT * FROM targets WHERE vuln_class = 'randstorm'")?;
        let plan: Vec<String> = stmt.query_map([], |row| {
            row.get::<_, String>(3) // detail column
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        let plan_text = plan.join(" ");
        // Should use idx_vuln_class index
        assert!(plan_text.contains("idx_vuln_class") || plan_text.contains("SEARCH"),
                "Expected index usage in query plan, got: {}", plan_text);

        Ok(())
    }

    #[test]
    fn test_bulk_performance() -> Result<()> {
        use std::time::Instant;

        let mut db = TargetDatabase::in_memory()?;

        // Create 10k test targets
        let targets: Vec<Target> = (0..10_000)
            .map(|i| Target {
                address: format!("1Address{:08}", i),
                vuln_class: if i % 3 == 0 { "randstorm" } else { "milk_sad" }.to_string(),
                first_seen_timestamp: Some(i as i64),
                metadata_json: None,
                status: "pending".to_string(),
                ..Default::default()
            })
            .collect();

        // Test bulk insert performance
        let start = Instant::now();
        db.bulk_upsert_targets(&targets)?;
        let duration = start.elapsed();

        println!("Bulk insert of 10k addresses: {:?}", duration);
        assert!(duration.as_secs() < 5, "Bulk insert should complete in <5s");

        // Test indexed query performance
        let start = Instant::now();
        let results = db.query_by_class("randstorm", 5000)?;
        let query_duration = start.elapsed();

        println!("Query 3.3k addresses by index: {:?}", query_duration);
        assert_eq!(results.len(), 3334); // 10000 / 3 rounded up
        assert!(query_duration.as_millis() < 100, "Indexed query should be <100ms, was {:?}", query_duration);

        Ok(())
    }

    #[test]
    fn test_address_primary_key_lookup() -> Result<()> {
        use std::time::Instant;

        let mut db = TargetDatabase::in_memory()?;

        // Insert 1000 addresses
        let targets: Vec<Target> = (0..1000)
            .map(|i| Target {
                address: format!("1Addr{:08}", i),
                vuln_class: "randstorm".to_string(),
                first_seen_timestamp: Some(i as i64),
                metadata_json: None,
                status: "pending".to_string(),
                ..Default::default()
            })
            .collect();

        db.bulk_upsert_targets(&targets)?;

        // Primary key lookup should be instant
        let start = Instant::now();
        db.update_status("1Addr00000500", "scanned")?;
        let duration = start.elapsed();

        println!("Primary key lookup and update: {:?}", duration);
        assert!(duration.as_micros() < 10_000, "PK lookup should be <10ms");

        Ok(())
    }
}
