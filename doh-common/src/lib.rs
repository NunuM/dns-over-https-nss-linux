pub mod error;
pub mod loggger;

use serde::{Serialize};
use zvariant::Type;


#[derive(Serialize, Type)]
pub struct AuditDnsQueryPage {
    current_page: u64,
    results: Vec<AuditDnsQuery>,
}

impl AuditDnsQueryPage {
    pub fn new(current_page: u64, results: Vec<AuditDnsQuery>) -> Self {
        Self { current_page, results }
    }
}

#[derive(Serialize, Type)]
pub struct AuditDnsQuery {
    process_name: String,
    host: String,
    create: u64,
}

impl AuditDnsQuery {
    pub fn new(process_name: String, host: String, create: u64) -> Self {
        Self { process_name, host, create }
    }
}