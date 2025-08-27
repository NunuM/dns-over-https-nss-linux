use std::{error::Error, future::pending};
use log::{info};
use zbus::{connection};
use crate::database::DatabaseService;
use crate::provider::Resolver;
use crate::settings::ApplicationSettings;

use async_sqlite::{JournalMode, PoolBuilder};

mod provider;
mod client;
mod dbus;
mod database;
mod sysinfo;
mod settings;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    tracing_subscriber::fmt::init();

    info!("Starting daemon");

    let settings= ApplicationSettings::configs();

    let pool = PoolBuilder::new()
        .path(settings.sqlite().connection_str())
        .journal_mode(JournalMode::Wal)
        .num_conns(4)
        .open()
        .await?;

    let database_service = DatabaseService::new(pool, settings.clone());

    info!("Creating tables");

    database_service.create_tables().await.expect("Unable to create base tables");

    let resolver = Resolver::new(database_service, settings);

    let service = dbus::DoHBusService::new(resolver);

    let _conn = connection::Builder::session()?
        .name("com.glaciaos.NameResolver")?
        .serve_at("/com/glaciaos/NameResolver", service)?
        .build()
        .await?;

    // Do other things or go to wait forever
    pending::<()>().await;

    Ok(())
}
