use std::ops::Add;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use sqlite::{State, Value};
use doh_common::{AuditDnsQuery, AuditDnsQueryPage};

use doh_common::error::Error;

use crate::provider::DnsReply;
use crate::settings::{ApplicationSettings, TTlConfig};

#[derive(Clone)]
pub struct DatabaseService {
    connection: Arc<sqlite::ConnectionThreadSafe>,
    application_settings: ApplicationSettings
}

impl DatabaseService {
    pub fn new(connection: sqlite::ConnectionThreadSafe, application_settings: ApplicationSettings) -> Self {
        Self {
            connection: Arc::new(connection),
            application_settings
        }
    }

    pub fn create_tables(&self) -> Result<bool, Error> {
        self.connection.execute(r#"CREATE TABLE IF NOT EXISTS audit_dns_query (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            process_name VARCHAR(255),
            dns_name     VARCHAR(1024),
            dns_family   INTEGER,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"#)?;

        self.connection.execute(r#"CREATE TABLE IF NOT EXISTS dns_reply (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            dns_name     VARCHAR(1024),
            dns_family   INTEGER,
            answer       VARCHAR(1024),
            expired      TIMESTAMP,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"#)?;

        self.connection.execute(r#"CREATE TABLE IF NOT EXISTS blacklist_hosts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            dns_name     VARCHAR(1024),
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"#)?;

        Ok(true)
    }

    pub fn get_dns_answer(&self, host: &str, family: u32) -> Result<Option<DnsReply>, Error> {
        let mut statement = self.connection.prepare("SELECT answer FROM dns_reply WHERE dns_name=? AND dns_family=? AND expired >= strftime('%s', 'now') LIMIT 1")?;

        statement.bind::<&[(_, Value)]>(&[
            (1, host.to_lowercase().into()),
            (2, (family as i64).into()),
        ][..])?;

        while let Ok(State::Row) = statement.next() {
            let answer_json_str = statement.read::<String, _>("answer")?;

            let reply = serde_json::from_str::<DnsReply>(answer_json_str.as_str())?;

            return Ok(Some(reply));
        }

        Ok(None)
    }

    pub async fn create_dns_answer(&self, host: &str, family: u32, reply: &DnsReply) -> Result<bool, Error> {
        let mut statement = self.connection.prepare("INSERT INTO dns_reply (dns_name, dns_family, answer, expired) VALUES (?,?,?,?)")?;

        let instant = std::time::SystemTime::now();

        let duration = if let TTlConfig::Custom(ttl) = self.application_settings.ttl() {
            std::time::Duration::from_secs(*ttl)
        } else {
            std::time::Duration::from_secs(reply.get_expiration().unwrap_or(60) as u64)
        };

        let expiration = instant.add(duration).duration_since(UNIX_EPOCH)?.as_secs();

        let reply_json_str = serde_json::to_string(reply)?;

        statement.bind::<&[(_, Value)]>(&[
            (1, host.to_lowercase().into()),
            (2, (family as i64).into()),
            (3, reply_json_str.into()),
            (4, (expiration as i64).into()),
        ][..])?;

        let state = statement.next()?;

        Ok(state == State::Done)
    }

    pub fn is_host_blocked(&self, host: &str) -> Result<bool, Error> {
        let mut statement = self.connection.prepare("SELECT 1 FROM blacklist_hosts WHERE dns_name=? LIMIT 1")?;

        statement.bind::<&[(_, Value)]>(&[
            (1, host.to_lowercase().into()),
        ][..])?;

        while let Ok(State::Row) = statement.next() {
            return Ok(true);
        }

        Ok(false)
    }

    pub fn create_host_blocked(&self, host: &str) -> Result<bool, Error> {
        let mut statement = self.connection.prepare("INSERT INTO blacklist_hosts (dns_name) VALUES (?)")?;

        statement.bind::<&[(_, Value)]>(&[
            (1, host.to_lowercase().into()),
        ][..])?;

        let state = statement.next()?;

        Ok(state == State::Done)
    }

    pub fn delete_host_blocked(&self, host: &str) -> Result<bool, Error> {
        let mut statement = self.connection.prepare("DELETE FROM blacklist_hosts WHERE dns_name=?")?;

        statement.bind::<&[(_, Value)]>(&[
            (1, host.to_lowercase().into()),
        ][..])?;

        let state = statement.next()?;

        Ok(state == State::Done)
    }

    pub fn create_dns_audit(&self, process_name: &str, host: &str, family: u32) -> Result<bool, Error> {
        let mut statement = self.connection.prepare("INSERT INTO audit_dns_query (process_name, dns_name, dns_family) VALUES (?,?,?)")?;

        statement.bind::<&[(_, Value)]>(&[
            (1, process_name.into()),
            (2, host.to_lowercase().into()),
            (3, (family as i64).into()),
        ][..])?;

        let state = statement.next()?;

        Ok(state == State::Done)
    }

    pub fn get_dns_audit(&self, page:u64) -> Result<AuditDnsQueryPage, Error> {

        let mut statement = self.connection.prepare("SELECT process_name,dns_name,created FROM audit_dns_query ORDER BY id DESC LIMIT 10 OFFSET ?")?;

        statement.bind::<&[(_, Value)]>(&[
            (1, ((page * 10) as i64).into()),
        ][..])?;

        let mut result = Vec::with_capacity(10);

        while let Ok(State::Row) = statement.next() {
            let process_name = statement.read::<String, _>("process_name")?;
            let host = statement.read::<String, _>("dns_name")?;

            let created = statement.read::<i64, _>("created")?;

            result.push(AuditDnsQuery::new(process_name, host, created as u64));
        }

        Ok(AuditDnsQueryPage::new(page, result))
    }
}
