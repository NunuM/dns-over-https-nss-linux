use log::debug;
use zbus::interface;

use doh_common::AuditDnsQueryPage;

use crate::provider::Resolver;

pub struct DoHBusService {
    resolver: Resolver,
}

impl DoHBusService {
    pub fn new(resolver: Resolver) -> Self {
        Self { resolver }
    }
}

#[interface(name = "com.glaciaos.NameResolver")]
impl DoHBusService {
    async fn name_request(&mut self, process_id: u32, name: &str, family: u32) -> zbus::fdo::Result<libnss::host::Host> {
        debug!("received query: {} - {} {}", process_id, name, family);
        self.resolver.resolve(process_id, name, family).await.map_err(|e| e.into())
    }

    fn block_host(&mut self, name: &str) -> zbus::fdo::Result<bool> {
        self.resolver.add_to_blacklist(name).map_err(|e| e.into())
    }

    fn get_last_queries(&mut self, page: u64) -> zbus::fdo::Result<AuditDnsQueryPage> {
        self.resolver.get_queries(page).map_err(|e| e.into())
    }
}
