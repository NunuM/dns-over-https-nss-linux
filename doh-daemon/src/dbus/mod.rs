
use tracing::{info, instrument};
use zbus::interface;

use doh_common::AuditDnsQueryPage;

use crate::provider::Resolver;

#[derive(Debug)]
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
    #[instrument(skip(self))]
    async fn resolve_name(
        &mut self,
        process_id: u32,
        name: &str,
        family: u32,
    ) -> zbus::fdo::Result<libnss::host::Host> {
        info!("received query: {} - {} {}", process_id, name, family);

        let result = self
            .resolver
            .resolve(process_id, name, family)
            .await
            .map_err(|e| e.into());

        result
    }

    async fn block_host(&mut self, name: &str) -> zbus::fdo::Result<bool> {
        self.resolver
            .add_to_blacklist(name)
            .await
            .map_err(|e: doh_common::error::Error | e.into())
    }

    async fn unblock_host(&mut self, name: &str) -> zbus::fdo::Result<bool> {
        self.resolver
            .remove_from_blacklist(name)
            .await
            .map_err(|e: doh_common::error::Error | e.into())
    }

    async fn get_last_queries(&mut self, page: u64) -> zbus::fdo::Result<AuditDnsQueryPage> {
        self.resolver.get_queries(page)
            .await
            .map_err(|e: doh_common::error::Error | e.into())
    }
}
