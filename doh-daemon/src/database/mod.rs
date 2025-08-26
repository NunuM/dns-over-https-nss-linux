use async_sqlite::rusqlite::params;
use async_sqlite::{Pool};
use doh_common::{AuditDnsQuery, AuditDnsQueryPage};
use std::fmt::{Debug, Formatter};
use std::ops::{Add};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use doh_common::error::Error;

use crate::provider::DnsReply;
use crate::settings::{ApplicationSettings, TTlConfig};

#[derive(Clone)]
pub struct DatabaseService {
    pool: Arc<Pool>,
    application_settings: ApplicationSettings,
}

impl Debug for DatabaseService {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DatabaseService")
    }
}

impl DatabaseService {
    pub fn new(connection: Pool, application_settings: ApplicationSettings) -> Self {
        Self {
            pool: Arc::new(connection),
            application_settings,
        }
    }

    pub async fn create_tables(&self) -> Result<bool, Error> {
        self.pool.conn(|connection| {

            connection.execute(
                r#"CREATE TABLE IF NOT EXISTS audit_dns_query (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            process_name VARCHAR(255),
            dns_name     VARCHAR(1024),
            dns_family   INTEGER,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"#,  [])?;

            connection.execute(
                r#"CREATE TABLE IF NOT EXISTS dns_reply (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            dns_name     VARCHAR(1024),
            dns_family   INTEGER,
            answer       VARCHAR(1024),
            expired      TIMESTAMP,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"#, [])?;

            connection.execute(
                r#"CREATE TABLE IF NOT EXISTS blacklist_hosts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            dns_name     VARCHAR(1024),
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"#, [])?;

            connection.execute(r#"CREATE INDEX IF NOT EXISTS idx_dns_reply_lookup ON dns_reply (dns_name, dns_family, expired)"#, [])?;

            connection.execute(
                r#"CREATE INDEX IF NOT EXISTS idx_blacklist_lookup ON blacklist_hosts (dns_name)"#,[])?;

            Ok(true)
        }).await.map_err(|e| e.into())
    }

    pub async fn get_dns_answer(&self, host: &str, family: u32) -> Result<Option<DnsReply>, Error> {

        let host_clone = host.to_lowercase();

        let answer_json_str = self.pool.conn(move |connection| {

            let str : String = connection
                .query_one("SELECT answer FROM dns_reply WHERE dns_name=? AND dns_family=? AND expired >= strftime('%s', 'now') LIMIT 1",
                           params![host_clone.to_lowercase(), family as i64], |row| row.get(0))?;

            Ok(str)
        }).await.map_err::<doh_common::error::Error, _>(|e| e.into())?;

        let reply = serde_json::from_str::<DnsReply>(answer_json_str.as_str())?;

        Ok(Some(reply))
    }

    pub async fn create_dns_answer(
        &self,
        host: &str,
        family: u32,
        reply: &DnsReply,
    ) -> Result<bool, Error> {
        let instant = std::time::SystemTime::now();

        let duration = if let TTlConfig::Custom(ttl) = self.application_settings.ttl() {
            std::time::Duration::from_secs(*ttl)
        } else {
            std::time::Duration::from_secs(reply.get_expiration().unwrap_or(60) as u64)
        };

        let expiration = instant.add(duration).duration_since(UNIX_EPOCH)?.as_secs();

        let reply_json_str = serde_json::to_string(reply)?;

        let host_clone = host.to_lowercase();

        self.pool.conn(move |connection| {
            let mut statement = connection.prepare(
                "INSERT INTO dns_reply (dns_name, dns_family, answer, expired) VALUES (?,?,?,?)",
            )?;

            let rows_affected = statement.execute(params![
                host_clone.to_lowercase(),
                family,
                reply_json_str,
                expiration as i64
            ])?;

            Ok(rows_affected > 0)
        }).await.map_err(|e| e.into())
    }

    pub async fn is_host_blocked(&self, host: &str) -> Result<bool, Error> {

        let host_clone = host.to_lowercase();

        self.pool.conn(move |connection| {
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM blacklist_hosts WHERE dns_name = ? LIMIT 1)",
                params![host_clone.to_lowercase()],
                |row| row.get(0),
            )?;

            Ok(exists)
        }).await.map_err(|e| e.into())
    }

    pub async fn create_host_blocked(&self, host: &str) -> Result<bool, Error> {

        let host_clone = host.to_lowercase();

        self.pool.conn(move |connection| {
            let mut statement =
                connection.prepare("INSERT INTO blacklist_hosts (dns_name) VALUES (?)")?;

            let rows_affected = statement.execute(params![host_clone.to_lowercase()])?;

            Ok(rows_affected > 0)
        }).await.map_err(|e| e.into())
    }

    pub async fn delete_host_blocked(&self, host: &str) -> Result<bool, Error> {

        let host_clone = host.to_lowercase();

        self.pool.conn(move |connection| {
            let mut statement =
                connection.prepare("DELETE FROM blacklist_hosts WHERE dns_name=?")?;

            let rows_affected = statement.execute(params![host_clone.to_lowercase()])?;

            Ok(rows_affected > 0)
        }).await.map_err(|e| e.into())
    }

    pub async fn create_dns_audit(
        &self,
        process_name: &str,
        host: &str,
        family: u32,
    ) -> Result<bool, Error> {

        let host_clone = host.to_lowercase();
        let process_name_clone = process_name.to_lowercase();

        self.pool.conn(move |connection| {
            let mut statement = connection.prepare(
                "INSERT INTO audit_dns_query (process_name, dns_name, dns_family) VALUES (?, ?, ?)",
            )?;

            let rows_affected =
                statement.execute(params![process_name_clone, host_clone.to_lowercase(), family])?;

            Ok(rows_affected > 0)
        }).await.map_err(|e| e.into())
    }

    pub async fn get_dns_audit(&self, page: u64) -> Result<AuditDnsQueryPage, Error> {
        self.pool.conn(move |connection| {

            let offset = page * 10;
            let mut statement = connection.prepare(
                "SELECT process_name, dns_name, created FROM audit_dns_query ORDER BY id DESC LIMIT 10 OFFSET ?"
            )?;

            let mut rows = statement.query(params![offset])?;
            let mut result = Vec::with_capacity(10);

            while let Some(row) = rows.next()? {
                let process_name = row.get::<_, String>("process_name")?;
                let dns_name = row.get::<_, String>("dns_name")?;
                let created = row.get::<_, i64>("created")?;

                result.push(AuditDnsQuery::new(process_name, dns_name, created as u64));
            }

            Ok(AuditDnsQueryPage::new(page, result))

        }).await.map_err(|e| e.into())
    }
}
