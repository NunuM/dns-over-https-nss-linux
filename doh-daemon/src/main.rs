use std::{error::Error, future::pending};
use log::{info};
use zbus::{connection};
use crate::database::DatabaseService;
use crate::provider::Resolver;
use crate::settings::ApplicationSettings;

mod provider;
mod client;
mod dbus;
mod database;
mod sysinfo;
mod settings;


#[tokio::main(
    flavor = "multi_thread",
    worker_threads = 10,
)]
async fn main() -> Result<(), Box<dyn Error>> {
    unsafe { std::env::set_var("RUST_LOG", "doh_common=debug,doh_daemon=debug"); }

    env_logger::init();

    info!("Starting daemon");

    let settings = ApplicationSettings::configs();

    let connection = sqlite::Connection::open_thread_safe(settings.sqlite().connection_str())
        .expect("Unable to open database, aborting...");

    let database_service = DatabaseService::new(connection, settings.clone());

    info!("Creating tables");

    database_service.create_tables().expect("Unable to create base tables");

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
