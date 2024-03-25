use syslog::{Facility, Formatter3164};
use crate::LIB_NAME;

pub fn log<M: AsRef<str>>(message: M) {
    // Log to syslog of it is in debug mode
    // if let Ok(_) = std::env::var(format!("{}_DEBUG", LIB_NAME.to_uppercase())) {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: LIB_NAME.into(),
        pid: 0,
    };

    if let Ok(mut writer) = syslog::unix(formatter) {
        writer.info(message.as_ref()).unwrap_or(());
    }
    // }
}