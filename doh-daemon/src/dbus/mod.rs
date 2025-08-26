use std::time::Instant;
use tracing::{instrument, trace};
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
    #[instrument(level = "debug", skip(self), fields(process_id, name, family))]
    async fn name_request(
        &mut self,
        process_id: u32,
        name: &str,
        family: u32,
    ) -> zbus::fdo::Result<libnss::host::Host> {
        trace!("received query: {} - {} {}", process_id, name, family);
        let start = Instant::now();
        let result = self
            .resolver
            .resolve(process_id, name, family)
            .await
            .map_err(|e| e.into());

        let elapsed = start.elapsed();
        println!("Async method took: {:.6} seconds", elapsed.as_secs_f64());

        result
    }

    async fn block_host(&mut self, name: &str) -> zbus::fdo::Result<bool> {
        self.resolver
            .add_to_blacklist(name)
            .await
            .map_err(|e: doh_common::error::Error | e.into())
    }

    async fn get_last_queries(&mut self, page: u64) -> zbus::fdo::Result<AuditDnsQueryPage> {
        self.resolver.get_queries(page)
            .await
            .map_err(|e: doh_common::error::Error | e.into())
    }
}
