use log::info;

// use syslog::{Facility, Formatter3164};

pub fn log<M: AsRef<str>>(message: M) {
    // Log to syslog of it is in debug mode
    // if let Ok(_) = std::env::var(format!("{}_DEBUG", LIB_NAME.to_uppercase())) {
    info!("{}", message.as_ref())
}